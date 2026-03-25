package dag

import "crypto/ed25519"

// Fork represents a detected fork: same author, same parent, different entries (rule D2).
type Fork struct {
	Author  ed25519.PublicKey
	Parent  [32]byte
	EntryA  [32]byte
	EntryB  [32]byte
}

// DetectForks scans the DAG for forks (same author, same parent, different content).
// This indicates a compromised or malfunctioning agent.
func (d *DAG) DetectForks() []Fork {
	// Map: (author, parent) -> list of entry hashes
	type key struct {
		author [32]byte
		parent [32]byte
	}
	seen := make(map[key][][32]byte)

	for _, entry := range d.entries {
		var authorArr [32]byte
		copy(authorArr[:], entry.AuthorKey)
		for _, parent := range entry.Parents {
			k := key{author: authorArr, parent: parent}
			seen[k] = append(seen[k], entry.Hash)
		}
	}

	var forks []Fork
	for k, hashes := range seen {
		if len(hashes) > 1 {
			// Found a fork: same author published multiple entries with same parent
			for i := 0; i < len(hashes)-1; i++ {
				forks = append(forks, Fork{
					Author: ed25519.PublicKey(k.author[:]),
					Parent: k.parent,
					EntryA: hashes[i],
					EntryB: hashes[i+1],
				})
			}
		}
	}
	return forks
}
