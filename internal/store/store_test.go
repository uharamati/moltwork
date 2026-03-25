package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "moltwork-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// --- LogDB Tests ---

func TestLogDBOpenClose(t *testing.T) {
	dir := tempDir(t)
	db, err := OpenLogDB(filepath.Join(dir, "log.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
}

func TestLogDBInsertAndGet(t *testing.T) {
	dir := tempDir(t)
	db, err := OpenLogDB(filepath.Join(dir, "log.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	hash := []byte("hash-1")
	raw := []byte("raw-cbor-data")
	author := []byte("author-key")
	sig := []byte("signature")
	parents := [][]byte{[]byte("parent-1"), []byte("parent-2")}

	err = db.InsertEntry(hash, raw, author, sig, 4, 1000, parents)
	if err != nil {
		t.Fatal(err)
	}

	entry, err := db.GetEntry(hash)
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil {
		t.Fatal("entry should exist")
	}

	if !bytes.Equal(entry.RawCBOR, raw) {
		t.Error("raw cbor mismatch")
	}
	if !bytes.Equal(entry.AuthorKey, author) {
		t.Error("author mismatch")
	}
	if len(entry.Parents) != 2 {
		t.Errorf("expected 2 parents, got %d", len(entry.Parents))
	}
}

func TestLogDBHasEntry(t *testing.T) {
	dir := tempDir(t)
	db, err := OpenLogDB(filepath.Join(dir, "log.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	has, _ := db.HasEntry([]byte("nonexistent"))
	if has {
		t.Error("should not have nonexistent entry")
	}

	db.InsertEntry([]byte("hash-1"), []byte("data"), []byte("author"), []byte("sig"), 1, 1000, nil)

	has, _ = db.HasEntry([]byte("hash-1"))
	if !has {
		t.Error("should have inserted entry")
	}
}

func TestLogDBRejectsOversized(t *testing.T) {
	dir := tempDir(t)
	db, err := OpenLogDB(filepath.Join(dir, "log.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	oversized := make([]byte, MaxEntrySize+1)
	err = db.InsertEntry([]byte("hash"), oversized, []byte("author"), []byte("sig"), 1, 1000, nil)
	if err == nil {
		t.Error("should reject oversized entry")
	}
}

func TestLogDBAllHashes(t *testing.T) {
	dir := tempDir(t)
	db, err := OpenLogDB(filepath.Join(dir, "log.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	db.InsertEntry([]byte("h1"), []byte("d1"), []byte("a"), []byte("s"), 1, 100, nil)
	db.InsertEntry([]byte("h2"), []byte("d2"), []byte("a"), []byte("s"), 1, 200, nil)
	db.InsertEntry([]byte("h3"), []byte("d3"), []byte("a"), []byte("s"), 1, 300, nil)

	hashes, err := db.AllHashes()
	if err != nil {
		t.Fatal(err)
	}
	if len(hashes) != 3 {
		t.Errorf("expected 3 hashes, got %d", len(hashes))
	}
}

func TestLogDBEntriesByType(t *testing.T) {
	dir := tempDir(t)
	db, err := OpenLogDB(filepath.Join(dir, "log.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	db.InsertEntry([]byte("h1"), []byte("d1"), []byte("a"), []byte("s"), 1, 100, nil)
	db.InsertEntry([]byte("h2"), []byte("d2"), []byte("a"), []byte("s"), 4, 200, nil)
	db.InsertEntry([]byte("h3"), []byte("d3"), []byte("a"), []byte("s"), 1, 300, nil)

	entries, err := db.EntriesByType(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries of type 1, got %d", len(entries))
	}
}

func TestLogDBDuplicateInsertIgnored(t *testing.T) {
	dir := tempDir(t)
	db, err := OpenLogDB(filepath.Join(dir, "log.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	hash := []byte("hash-dup")
	db.InsertEntry(hash, []byte("d1"), []byte("a"), []byte("s"), 1, 100, nil)
	db.InsertEntry(hash, []byte("d2"), []byte("a"), []byte("s"), 1, 200, nil) // duplicate

	count, _ := db.EntryCount()
	if count != 1 {
		t.Errorf("expected 1 entry after duplicate insert, got %d", count)
	}
}

// --- KeyDB Tests ---

func TestKeyDBOpenClose(t *testing.T) {
	dir := tempDir(t)
	db, err := OpenKeyDB(filepath.Join(dir, "keys.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
}

func TestKeyDBFilePermissions(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "keys.db")
	db, err := OpenKeyDB(path)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("key db permissions: got %o, want 0600", perm)
	}
}

func TestKeyDBIdentity(t *testing.T) {
	dir := tempDir(t)
	db, err := OpenKeyDB(filepath.Join(dir, "keys.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	pub, priv, err := db.GetIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if pub != nil || priv != nil {
		t.Error("should be nil before setting")
	}

	db.SetIdentity([]byte("pub"), []byte("priv"))

	pub, priv, err = db.GetIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, []byte("pub")) {
		t.Error("public key mismatch")
	}
	if !bytes.Equal(priv, []byte("priv")) {
		t.Error("private key mismatch")
	}
}

func TestKeyDBPairwiseSecret(t *testing.T) {
	dir := tempDir(t)
	db, err := OpenKeyDB(filepath.Join(dir, "keys.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	peer := []byte("peer-key")
	secret := []byte("shared-secret")

	db.SetPairwiseSecret(peer, secret, 0)

	got, epoch, err := db.GetPairwiseSecret(peer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Error("secret mismatch")
	}
	if epoch != 0 {
		t.Error("epoch should be 0")
	}

	// Update with rotation
	db.SetPairwiseSecret(peer, []byte("new-secret"), 1)
	got, epoch, _ = db.GetPairwiseSecret(peer)
	if !bytes.Equal(got, []byte("new-secret")) {
		t.Error("rotated secret mismatch")
	}
	if epoch != 1 {
		t.Error("epoch should be 1")
	}
}

func TestKeyDBGroupKey(t *testing.T) {
	dir := tempDir(t)
	db, err := OpenKeyDB(filepath.Join(dir, "keys.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	chanID := []byte("chan-1")
	key1 := []byte("group-key-epoch-0")
	key2 := []byte("group-key-epoch-1")

	db.SetGroupKey(chanID, 0, key1)
	db.SetGroupKey(chanID, 1, key2)

	got, epoch, err := db.GetGroupKey(chanID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, key2) {
		t.Error("should return latest epoch key")
	}
	if epoch != 1 {
		t.Error("epoch should be 1")
	}
}

func TestKeyDBPSK(t *testing.T) {
	dir := tempDir(t)
	db, err := OpenKeyDB(filepath.Join(dir, "keys.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	psk, _ := db.GetPSK()
	if psk != nil {
		t.Error("should be nil before setting")
	}

	db.SetPSK([]byte("workspace-psk"))
	psk, _ = db.GetPSK()
	if !bytes.Equal(psk, []byte("workspace-psk")) {
		t.Error("psk mismatch")
	}
}

func TestKeyDBPlatformToken(t *testing.T) {
	dir := tempDir(t)
	db, err := OpenKeyDB(filepath.Join(dir, "keys.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	db.SetPlatformToken([]byte("xoxb-abc"), "slack", "toriihq.slack.com")

	tok, platform, domain, err := db.GetPlatformToken()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tok, []byte("xoxb-abc")) {
		t.Error("token mismatch")
	}
	if platform != "slack" {
		t.Error("platform mismatch")
	}
	if domain != "toriihq.slack.com" {
		t.Error("domain mismatch")
	}
}
