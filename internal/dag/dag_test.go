package dag

import (
	"testing"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/crypto"
)

func makeEntry(t *testing.T, kp *crypto.SigningKeyPair, parents [][32]byte, content string) *SignedEntry {
	t.Helper()
	payload, _ := moltcbor.Marshal(moltcbor.Message{
		ChannelID: []byte("chan-1"),
		Content:   []byte(content),
	})
	entry, err := NewSignedEntry(moltcbor.EntryTypeMessage, payload, kp, parents)
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

func TestNewSignedEntryAndVerify(t *testing.T) {
	kp, _ := crypto.GenerateSigningKeyPair()
	entry := makeEntry(t, kp, nil, "hello")

	if err := VerifyEntry(entry); err != nil {
		t.Fatalf("valid entry failed verification: %v", err)
	}

	if entry.Hash == [32]byte{} {
		t.Error("hash should not be zero")
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	kp, _ := crypto.GenerateSigningKeyPair()
	entry := makeEntry(t, kp, nil, "hello")

	entry.Signature[0] ^= 0xff
	if err := VerifyEntry(entry); err == nil {
		t.Error("tampered signature should fail")
	}
}

func TestVerifyRejectsTamperedHash(t *testing.T) {
	kp, _ := crypto.GenerateSigningKeyPair()
	entry := makeEntry(t, kp, nil, "hello")

	entry.Hash[0] ^= 0xff
	if err := VerifyEntry(entry); err == nil {
		t.Error("tampered hash should fail")
	}
}

func TestDAGInsert(t *testing.T) {
	kp, _ := crypto.GenerateSigningKeyPair()
	d := New()

	e1 := makeEntry(t, kp, nil, "first")
	if err := d.Insert(e1); err != nil {
		t.Fatal(err)
	}

	e2 := makeEntry(t, kp, [][32]byte{e1.Hash}, "second")
	if err := d.Insert(e2); err != nil {
		t.Fatal(err)
	}

	if d.Len() != 2 {
		t.Errorf("expected 2 entries, got %d", d.Len())
	}
}

func TestDAGRejectsMissingParent(t *testing.T) {
	kp, _ := crypto.GenerateSigningKeyPair()
	d := New()

	fakeParent := [32]byte{0x01, 0x02, 0x03}
	e := makeEntry(t, kp, [][32]byte{fakeParent}, "orphan")

	if err := d.Insert(e); err == nil {
		t.Error("should reject entry with missing parent")
	}
}

func TestDAGIdempotentInsert(t *testing.T) {
	kp, _ := crypto.GenerateSigningKeyPair()
	d := New()

	e := makeEntry(t, kp, nil, "first")
	d.Insert(e)
	d.Insert(e) // duplicate

	if d.Len() != 1 {
		t.Errorf("expected 1 entry after duplicate insert, got %d", d.Len())
	}
}

func TestDAGTopologicalOrder(t *testing.T) {
	kp, _ := crypto.GenerateSigningKeyPair()
	d := New()

	e1 := makeEntry(t, kp, nil, "first")
	d.Insert(e1)

	e2 := makeEntry(t, kp, [][32]byte{e1.Hash}, "second")
	d.Insert(e2)

	e3 := makeEntry(t, kp, [][32]byte{e2.Hash}, "third")
	d.Insert(e3)

	order := d.TopologicalOrder()
	if len(order) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(order))
	}

	// First must be e1 (root)
	if order[0].Hash != e1.Hash {
		t.Error("first entry should be root")
	}
	// e2 before e3
	if order[1].Hash != e2.Hash {
		t.Error("second entry should be e2")
	}
	if order[2].Hash != e3.Hash {
		t.Error("third entry should be e3")
	}
}

func TestDAGConcurrentEntriesDeterministicOrder(t *testing.T) {
	kpA, _ := crypto.GenerateSigningKeyPair()
	kpB, _ := crypto.GenerateSigningKeyPair()
	d := New()

	root := makeEntry(t, kpA, nil, "root")
	d.Insert(root)

	// Two concurrent entries from different authors, same parent
	eA := makeEntry(t, kpA, [][32]byte{root.Hash}, "from A")
	eB := makeEntry(t, kpB, [][32]byte{root.Hash}, "from B")
	d.Insert(eA)
	d.Insert(eB)

	order := d.TopologicalOrder()
	if len(order) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(order))
	}

	// Root first
	if order[0].Hash != root.Hash {
		t.Error("root should be first")
	}

	// Concurrent entries ordered by hash
	if CompareHashes(order[1].Hash, order[2].Hash) > 0 {
		t.Error("concurrent entries should be ordered by hash")
	}

	// Verify determinism: run again
	order2 := d.TopologicalOrder()
	for i := range order {
		if order[i].Hash != order2[i].Hash {
			t.Error("topological order should be deterministic")
		}
	}
}

func TestDAGIsAncestor(t *testing.T) {
	kp, _ := crypto.GenerateSigningKeyPair()
	d := New()

	e1 := makeEntry(t, kp, nil, "first")
	d.Insert(e1)
	e2 := makeEntry(t, kp, [][32]byte{e1.Hash}, "second")
	d.Insert(e2)
	e3 := makeEntry(t, kp, [][32]byte{e2.Hash}, "third")
	d.Insert(e3)

	if !d.IsAncestor(e1.Hash, e3.Hash) {
		t.Error("e1 should be ancestor of e3")
	}
	if d.IsAncestor(e3.Hash, e1.Hash) {
		t.Error("e3 should not be ancestor of e1")
	}
	if d.IsAncestor(e1.Hash, e1.Hash) {
		t.Error("entry should not be its own ancestor")
	}
}

func TestDAGAreConcurrent(t *testing.T) {
	kpA, _ := crypto.GenerateSigningKeyPair()
	kpB, _ := crypto.GenerateSigningKeyPair()
	d := New()

	root := makeEntry(t, kpA, nil, "root")
	d.Insert(root)

	eA := makeEntry(t, kpA, [][32]byte{root.Hash}, "branch A")
	eB := makeEntry(t, kpB, [][32]byte{root.Hash}, "branch B")
	d.Insert(eA)
	d.Insert(eB)

	if !d.AreConcurrent(eA.Hash, eB.Hash) {
		t.Error("eA and eB should be concurrent")
	}
	if d.AreConcurrent(root.Hash, eA.Hash) {
		t.Error("root and eA should not be concurrent (root is ancestor)")
	}
}

func TestDAGTips(t *testing.T) {
	kp, _ := crypto.GenerateSigningKeyPair()
	d := New()

	e1 := makeEntry(t, kp, nil, "first")
	d.Insert(e1)
	e2 := makeEntry(t, kp, [][32]byte{e1.Hash}, "second")
	d.Insert(e2)

	tips := d.Tips()
	if len(tips) != 1 {
		t.Fatalf("expected 1 tip, got %d", len(tips))
	}
	if tips[0] != e2.Hash {
		t.Error("tip should be e2")
	}
}

func TestDAGForkDetection(t *testing.T) {
	kp, _ := crypto.GenerateSigningKeyPair()
	d := New()

	root := makeEntry(t, kp, nil, "root")
	d.Insert(root)

	// Same author, same parent, different content = FORK
	fork1 := makeEntry(t, kp, [][32]byte{root.Hash}, "fork branch 1")
	fork2 := makeEntry(t, kp, [][32]byte{root.Hash}, "fork branch 2")
	d.Insert(fork1)
	d.Insert(fork2)

	forks := d.DetectForks()
	if len(forks) != 1 {
		t.Fatalf("expected 1 fork, got %d", len(forks))
	}
	if forks[0].Parent != root.Hash {
		t.Error("fork parent should be root")
	}
}

func TestDAGNoConcurrentForkFalsePositive(t *testing.T) {
	kpA, _ := crypto.GenerateSigningKeyPair()
	kpB, _ := crypto.GenerateSigningKeyPair()
	d := New()

	root := makeEntry(t, kpA, nil, "root")
	d.Insert(root)

	// Different authors, same parent = NOT a fork
	eA := makeEntry(t, kpA, [][32]byte{root.Hash}, "from A")
	eB := makeEntry(t, kpB, [][32]byte{root.Hash}, "from B")
	d.Insert(eA)
	d.Insert(eB)

	forks := d.DetectForks()
	if len(forks) != 0 {
		t.Errorf("different authors with same parent should not be a fork, got %d forks", len(forks))
	}
}

func TestDAGInsertBatch(t *testing.T) {
	kp, _ := crypto.GenerateSigningKeyPair()
	d := New()

	// Create a chain of 3 entries as a batch
	e1 := makeEntry(t, kp, nil, "first")

	// Manually set parents for batch entries
	payload2, _ := moltcbor.Marshal(moltcbor.Message{ChannelID: []byte("c"), Content: []byte("second")})
	e2, _ := NewSignedEntry(moltcbor.EntryTypeMessage, payload2, kp, [][32]byte{e1.Hash})

	payload3, _ := moltcbor.Marshal(moltcbor.Message{ChannelID: []byte("c"), Content: []byte("third")})
	e3, _ := NewSignedEntry(moltcbor.EntryTypeMessage, payload3, kp, [][32]byte{e2.Hash})

	// Insert as batch (out of order)
	err := d.InsertBatch([]*SignedEntry{e3, e1, e2})
	if err != nil {
		t.Fatal(err)
	}

	if d.Len() != 3 {
		t.Errorf("expected 3 entries, got %d", d.Len())
	}

	// Verify order
	order := d.TopologicalOrder()
	if order[0].Hash != e1.Hash {
		t.Error("first should be e1")
	}
}
