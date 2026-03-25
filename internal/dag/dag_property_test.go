package dag

import (
	"testing"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/crypto"

	"pgregory.net/rapid"
)

func TestTopologicalOrderDeterministic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Create a DAG with N entries (2-10) from different authors
		n := rapid.IntRange(2, 10).Draw(t, "num_entries")

		kp, err := crypto.GenerateSigningKeyPair()
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}

		d := New()
		var entries []*SignedEntry

		for i := 0; i < n; i++ {
			payload, _ := moltcbor.Marshal(moltcbor.Message{
				ChannelID: []byte("test"),
				Content:   crypto.RandomBytes(16),
			})
			var parents [][32]byte
			if len(entries) > 0 {
				parents = [][32]byte{entries[len(entries)-1].Hash}
			}
			entry, err := NewSignedEntry(moltcbor.EntryTypeMessage, payload, kp, parents)
			if err != nil {
				t.Fatalf("new entry: %v", err)
			}
			d.Insert(entry)
			entries = append(entries, entry)
		}

		// Get ordering twice — should be identical
		order1 := d.TopologicalOrder()
		order2 := d.TopologicalOrder()

		if len(order1) != len(order2) {
			t.Fatalf("order lengths differ: %d vs %d", len(order1), len(order2))
		}

		for i := range order1 {
			if order1[i] != order2[i] {
				t.Fatalf("order differs at index %d", i)
			}
		}
	})
}
