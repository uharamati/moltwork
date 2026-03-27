package dag

import (
	"bytes"
	"fmt"
	"sync"
)

// DAG is an in-memory directed acyclic graph of log entries.
type DAG struct {
	mu       sync.RWMutex
	entries  map[[32]byte]*SignedEntry
	children map[[32]byte][][32]byte // parent -> children
	roots    [][32]byte              // entries with no parents
}

// New creates an empty DAG.
func New() *DAG {
	return &DAG{
		entries:  make(map[[32]byte]*SignedEntry),
		children: make(map[[32]byte][][32]byte),
	}
}

// Has checks if an entry exists in the DAG.
func (d *DAG) Has(hash [32]byte) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, ok := d.entries[hash]
	return ok
}

// Get retrieves an entry by hash.
func (d *DAG) Get(hash [32]byte) *SignedEntry {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.entries[hash]
}

// Insert adds an entry to the DAG.
// Returns error if any parent is missing (rule D4: parents must exist).
func (d *DAG) Insert(entry *SignedEntry) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok := d.entries[entry.Hash]; ok {
		return nil // idempotent
	}

	// Validate all parents exist (rule D4)
	for _, parent := range entry.Parents {
		if _, ok := d.entries[parent]; !ok {
			return fmt.Errorf("missing parent %x", parent[:8])
		}
	}

	d.entries[entry.Hash] = entry

	if len(entry.Parents) == 0 {
		d.roots = append(d.roots, entry.Hash)
	}

	for _, parent := range entry.Parents {
		d.children[parent] = append(d.children[parent], entry.Hash)
	}

	return nil
}

// has is the lock-free internal version for use under an existing lock.
func (d *DAG) has(hash [32]byte) bool {
	_, ok := d.entries[hash]
	return ok
}

// InsertBatch inserts multiple entries, resolving intra-batch dependencies.
// Entries may reference parents within the same batch.
func (d *DAG) InsertBatch(entries []*SignedEntry) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Build index of batch entries
	batchIndex := make(map[[32]byte]*SignedEntry, len(entries))
	for _, e := range entries {
		batchIndex[e.Hash] = e
	}

	// Topologically sort the batch itself
	sorted, err := topoSortBatch(entries, batchIndex, d)
	if err != nil {
		return err
	}

	// Insert in topological order (inline to avoid double-locking)
	for _, entry := range sorted {
		if d.has(entry.Hash) {
			continue
		}
		for _, parent := range entry.Parents {
			if !d.has(parent) {
				return fmt.Errorf("insert batch entry %x: missing parent %x", entry.Hash[:8], parent[:8])
			}
		}
		d.entries[entry.Hash] = entry
		if len(entry.Parents) == 0 {
			d.roots = append(d.roots, entry.Hash)
		}
		for _, parent := range entry.Parents {
			d.children[parent] = append(d.children[parent], entry.Hash)
		}
	}
	return nil
}

// topoSortBatch sorts batch entries respecting intra-batch dependencies.
// Caller must hold the DAG lock (uses has() directly to avoid deadlock).
func topoSortBatch(entries []*SignedEntry, batchIndex map[[32]byte]*SignedEntry, existing *DAG) ([]*SignedEntry, error) {
	inDegree := make(map[[32]byte]int)
	for _, e := range entries {
		inDegree[e.Hash] = 0
	}

	// Count intra-batch dependencies
	for _, e := range entries {
		for _, parent := range e.Parents {
			if _, inBatch := batchIndex[parent]; inBatch {
				inDegree[e.Hash]++
			} else if !existing.has(parent) {
				return nil, fmt.Errorf("entry %x references unknown parent %x", e.Hash[:8], parent[:8])
			}
		}
	}

	// Kahn's algorithm
	var queue []*SignedEntry
	for _, e := range entries {
		if inDegree[e.Hash] == 0 {
			queue = append(queue, e)
		}
	}

	var sorted []*SignedEntry
	for len(queue) > 0 {
		// Sort queue deterministically by hash for concurrent entries (rule D3)
		sortByHash(queue)
		current := queue[0]
		queue = queue[1:]
		sorted = append(sorted, current)

		// Find entries in batch that depend on current
		for _, e := range entries {
			for _, parent := range e.Parents {
				if parent == current.Hash {
					inDegree[e.Hash]--
					if inDegree[e.Hash] == 0 {
						queue = append(queue, e)
					}
				}
			}
		}
	}

	if len(sorted) != len(entries) {
		return nil, fmt.Errorf("cycle detected in batch")
	}
	return sorted, nil
}

// Len returns the number of entries in the DAG.
func (d *DAG) Len() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.entries)
}

// Entries returns all entries (unordered).
func (d *DAG) Entries() []*SignedEntry {
	d.mu.RLock()
	defer d.mu.RUnlock()
	result := make([]*SignedEntry, 0, len(d.entries))
	for _, e := range d.entries {
		result = append(result, e)
	}
	return result
}

// Roots returns entries with no parents.
func (d *DAG) Roots() [][32]byte {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.roots
}

// Tips returns entries with no children (the frontier).
func (d *DAG) Tips() [][32]byte {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var tips [][32]byte
	for hash := range d.entries {
		if len(d.children[hash]) == 0 {
			tips = append(tips, hash)
		}
	}
	// Deterministic ordering (rule D3)
	sortHashes(tips)
	return tips
}

// sortByHash sorts entries by their hash for deterministic ordering.
func sortByHash(entries []*SignedEntry) {
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0 && bytes.Compare(entries[j].Hash[:], entries[j-1].Hash[:]) < 0; j-- {
			entries[j], entries[j-1] = entries[j-1], entries[j]
		}
	}
}

func sortHashes(hashes [][32]byte) {
	for i := 1; i < len(hashes); i++ {
		for j := i; j > 0 && bytes.Compare(hashes[j][:], hashes[j-1][:]) < 0; j-- {
			hashes[j], hashes[j-1] = hashes[j-1], hashes[j]
		}
	}
}
