package dag

import (
	"bytes"
	"testing"

	"moltwork/internal/crypto"
)

func TestDetectForks_CleanDAG(t *testing.T) {
	kp, _ := crypto.GenerateSigningKeyPair()
	d := New()

	// Linear chain: root -> e1 -> e2
	root := makeEntry(t, kp, nil, "root")
	d.Insert(root)

	e1 := makeEntry(t, kp, [][32]byte{root.Hash}, "first")
	d.Insert(e1)

	e2 := makeEntry(t, kp, [][32]byte{e1.Hash}, "second")
	d.Insert(e2)

	forks := d.DetectForks()
	if len(forks) != 0 {
		t.Errorf("clean linear DAG should have no forks, got %d", len(forks))
	}
}

func TestDetectForks_CleanDAGEmpty(t *testing.T) {
	d := New()

	forks := d.DetectForks()
	if len(forks) != 0 {
		t.Errorf("empty DAG should have no forks, got %d", len(forks))
	}
}

func TestDetectForks_SingleFork(t *testing.T) {
	kp, _ := crypto.GenerateSigningKeyPair()
	d := New()

	root := makeEntry(t, kp, nil, "root")
	d.Insert(root)

	// Same author, same parent, different content = fork
	forkA := makeEntry(t, kp, [][32]byte{root.Hash}, "branch A")
	forkB := makeEntry(t, kp, [][32]byte{root.Hash}, "branch B")
	d.Insert(forkA)
	d.Insert(forkB)

	forks := d.DetectForks()
	if len(forks) != 1 {
		t.Fatalf("expected 1 fork, got %d", len(forks))
	}

	f := forks[0]
	if f.Parent != root.Hash {
		t.Error("fork parent should be root")
	}
	if !bytes.Equal(f.Author, kp.Public) {
		t.Error("fork author should match the signing key")
	}

	// EntryA and EntryB should be the two forked entries (order may vary)
	gotA := f.EntryA == forkA.Hash || f.EntryA == forkB.Hash
	gotB := f.EntryB == forkA.Hash || f.EntryB == forkB.Hash
	if !gotA || !gotB {
		t.Error("fork entries should reference both forked entries")
	}
	if f.EntryA == f.EntryB {
		t.Error("fork entries should be different")
	}
}

func TestDetectForks_ThreeWayFork(t *testing.T) {
	kp, _ := crypto.GenerateSigningKeyPair()
	d := New()

	root := makeEntry(t, kp, nil, "root")
	d.Insert(root)

	// Three entries from the same author with the same parent
	a := makeEntry(t, kp, [][32]byte{root.Hash}, "branch A")
	b := makeEntry(t, kp, [][32]byte{root.Hash}, "branch B")
	c := makeEntry(t, kp, [][32]byte{root.Hash}, "branch C")
	d.Insert(a)
	d.Insert(b)
	d.Insert(c)

	forks := d.DetectForks()
	// 3 entries with same (author, parent) produces 2 Fork pairs: (0,1) and (1,2)
	if len(forks) != 2 {
		t.Fatalf("expected 2 fork pairs for a 3-way fork, got %d", len(forks))
	}
}

func TestDetectForks_MultipleForkPoints(t *testing.T) {
	kp, _ := crypto.GenerateSigningKeyPair()
	d := New()

	root := makeEntry(t, kp, nil, "root")
	d.Insert(root)

	// Fork at root
	a1 := makeEntry(t, kp, [][32]byte{root.Hash}, "root fork 1")
	a2 := makeEntry(t, kp, [][32]byte{root.Hash}, "root fork 2")
	d.Insert(a1)
	d.Insert(a2)

	// Fork again at a1
	b1 := makeEntry(t, kp, [][32]byte{a1.Hash}, "a1 fork 1")
	b2 := makeEntry(t, kp, [][32]byte{a1.Hash}, "a1 fork 2")
	d.Insert(b1)
	d.Insert(b2)

	forks := d.DetectForks()
	if len(forks) != 2 {
		t.Fatalf("expected 2 forks (one at root, one at a1), got %d", len(forks))
	}

	// Collect fork parents
	parents := make(map[[32]byte]bool)
	for _, f := range forks {
		parents[f.Parent] = true
	}
	if !parents[root.Hash] {
		t.Error("expected a fork at root")
	}
	if !parents[a1.Hash] {
		t.Error("expected a fork at a1")
	}
}

func TestDetectForks_DifferentAuthorsNotAFork(t *testing.T) {
	kpA, _ := crypto.GenerateSigningKeyPair()
	kpB, _ := crypto.GenerateSigningKeyPair()
	d := New()

	root := makeEntry(t, kpA, nil, "root")
	d.Insert(root)

	// Two different authors both building on root — this is normal concurrency, not a fork
	eA := makeEntry(t, kpA, [][32]byte{root.Hash}, "from author A")
	eB := makeEntry(t, kpB, [][32]byte{root.Hash}, "from author B")
	d.Insert(eA)
	d.Insert(eB)

	forks := d.DetectForks()
	if len(forks) != 0 {
		t.Errorf("different authors with same parent should not be a fork, got %d forks", len(forks))
	}
}

func TestDetectForks_MultipleAuthorsEachForking(t *testing.T) {
	kpA, _ := crypto.GenerateSigningKeyPair()
	kpB, _ := crypto.GenerateSigningKeyPair()
	d := New()

	root := makeEntry(t, kpA, nil, "root")
	d.Insert(root)

	// Author A forks
	a1 := makeEntry(t, kpA, [][32]byte{root.Hash}, "A fork 1")
	a2 := makeEntry(t, kpA, [][32]byte{root.Hash}, "A fork 2")
	d.Insert(a1)
	d.Insert(a2)

	// Author B also forks
	b1 := makeEntry(t, kpB, [][32]byte{root.Hash}, "B fork 1")
	b2 := makeEntry(t, kpB, [][32]byte{root.Hash}, "B fork 2")
	d.Insert(b1)
	d.Insert(b2)

	forks := d.DetectForks()
	if len(forks) != 2 {
		t.Fatalf("expected 2 forks (one per author), got %d", len(forks))
	}

	// Each fork should reference a different author
	authors := make(map[string]bool)
	for _, f := range forks {
		authors[string(f.Author)] = true
	}
	if len(authors) != 2 {
		t.Error("expected forks from 2 distinct authors")
	}
}

func TestDetectForks_RootEntriesNoFalsePositive(t *testing.T) {
	kpA, _ := crypto.GenerateSigningKeyPair()
	kpB, _ := crypto.GenerateSigningKeyPair()
	d := New()

	// Two different authors each create a root entry (no parents)
	r1 := makeEntry(t, kpA, nil, "root A")
	r2 := makeEntry(t, kpB, nil, "root B")
	d.Insert(r1)
	d.Insert(r2)

	forks := d.DetectForks()
	if len(forks) != 0 {
		t.Errorf("different root entries from different authors should not be forks, got %d", len(forks))
	}
}

func TestDetectForks_SameAuthorDifferentParentsNotAFork(t *testing.T) {
	kp, _ := crypto.GenerateSigningKeyPair()
	d := New()

	r1 := makeEntry(t, kp, nil, "root 1")
	r2 := makeEntry(t, kp, nil, "root 2")
	d.Insert(r1)
	d.Insert(r2)

	// Same author creates entries from different parents — not a fork
	e1 := makeEntry(t, kp, [][32]byte{r1.Hash}, "child of r1")
	e2 := makeEntry(t, kp, [][32]byte{r2.Hash}, "child of r2")
	d.Insert(e1)
	d.Insert(e2)

	forks := d.DetectForks()
	// Note: r1 and r2 are both roots with no parents, so they won't trigger
	// fork detection (fork detection is keyed on (author, parent) and root
	// entries have no parents to iterate over).
	// e1 and e2 have different parents, so also not a fork.
	if len(forks) != 0 {
		t.Errorf("same author with different parents should not be a fork, got %d forks", len(forks))
	}
}
