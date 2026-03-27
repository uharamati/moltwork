package dag

import "bytes"

// TopologicalOrder returns all entries in causal order.
// Concurrent entries (no ancestry relationship) are ordered by hash (rule D3).
func (d *DAG) TopologicalOrder() []*SignedEntry {
	d.mu.RLock()
	defer d.mu.RUnlock()
	inDegree := make(map[[32]byte]int, len(d.entries))
	for hash := range d.entries {
		inDegree[hash] = 0
	}
	for _, entry := range d.entries {
		for _, parent := range entry.Parents {
			if _, ok := d.entries[parent]; ok {
				inDegree[entry.Hash]++
			}
		}
	}

	// Start with roots
	var queue [][32]byte
	for hash, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, hash)
		}
	}

	var result []*SignedEntry
	for len(queue) > 0 {
		// Sort queue by hash for deterministic concurrent ordering (rule D3)
		sortHashes(queue)

		hash := queue[0]
		queue = queue[1:]
		result = append(result, d.entries[hash])

		for _, child := range d.children[hash] {
			inDegree[child]--
			if inDegree[child] == 0 {
				queue = append(queue, child)
			}
		}
	}

	return result
}

// IsAncestor checks if `ancestor` is an ancestor of `descendant` in the DAG.
func (d *DAG) IsAncestor(ancestor, descendant [32]byte) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if ancestor == descendant {
		return false
	}

	visited := make(map[[32]byte]bool)
	return d.isAncestorDFS(ancestor, descendant, visited)
}

func (d *DAG) isAncestorDFS(target, current [32]byte, visited map[[32]byte]bool) bool {
	if visited[current] {
		return false
	}
	visited[current] = true

	entry := d.entries[current]
	if entry == nil {
		return false
	}

	for _, parent := range entry.Parents {
		if parent == target {
			return true
		}
		if d.isAncestorDFS(target, parent, visited) {
			return true
		}
	}
	return false
}

// AreConcurrent returns true if neither entry is an ancestor of the other.
func (d *DAG) AreConcurrent(a, b [32]byte) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	visited1 := make(map[[32]byte]bool)
	visited2 := make(map[[32]byte]bool)
	return !d.isAncestorDFS(a, b, visited1) && !d.isAncestorDFS(b, a, visited2) && a != b
}

// CompareHashes provides deterministic ordering for concurrent entries (rule D3).
func CompareHashes(a, b [32]byte) int {
	return bytes.Compare(a[:], b[:])
}
