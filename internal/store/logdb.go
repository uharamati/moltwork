package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// LogDB manages the append-only log database.
type LogDB struct {
	db *sql.DB
}

// OpenLogDB opens or creates the log database with WAL mode and busy timeout (rule S1).
// Runs integrity check on startup (rule S4).
func OpenLogDB(path string) (*LogDB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create log db dir: %w", err)
	}

	db, err := sql.Open("sqlite", path+"?_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open log db: %w", err)
	}

	// WAL mode (rule S1)
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}

	// Integrity check on startup (rule S4)
	var result string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&result); err != nil {
		db.Close()
		return nil, fmt.Errorf("integrity check: %w", err)
	}
	if result != "ok" {
		db.Close()
		return nil, fmt.Errorf("integrity check failed: %s", result)
	}

	s := &LogDB{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *LogDB) migrate() error {
	// Enable foreign keys
	if _, err := s.db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return fmt.Errorf("enable foreign keys: %w", err)
	}

	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS entries (
			hash         BLOB PRIMARY KEY,
			raw_cbor     BLOB NOT NULL,
			author_key   BLOB NOT NULL,
			signature    BLOB NOT NULL,
			entry_type   INTEGER NOT NULL,
			created_at   INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS entry_parents (
			entry_hash   BLOB NOT NULL REFERENCES entries(hash),
			parent_hash  BLOB NOT NULL,
			PRIMARY KEY (entry_hash, parent_hash)
		);

		CREATE INDEX IF NOT EXISTS idx_entries_author ON entries(author_key);
		CREATE INDEX IF NOT EXISTS idx_entries_type ON entries(entry_type);
		CREATE INDEX IF NOT EXISTS idx_entries_created ON entries(created_at);
		CREATE INDEX IF NOT EXISTS idx_entries_type_author ON entries(entry_type, author_key);
		CREATE INDEX IF NOT EXISTS idx_parents_parent ON entry_parents(parent_hash);
	`)
	if err != nil {
		return fmt.Errorf("migrate log db: %w", err)
	}
	return nil
}

// MaxEntrySize is the maximum raw entry size (rule S5).
const MaxEntrySize = 65536

// InsertEntry stores a log entry with its parent references.
// Enforces max entry size (rule S5). All queries parameterized (rule S3).
func (s *LogDB) InsertEntry(hash, rawCBOR, authorKey, signature []byte, entryType int, createdAt int64, parents [][]byte) error {
	if len(rawCBOR) > MaxEntrySize {
		return fmt.Errorf("entry size %d exceeds maximum %d", len(rawCBOR), MaxEntrySize)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Parameterized insert (rule S3)
	_, err = tx.Exec(
		"INSERT OR IGNORE INTO entries (hash, raw_cbor, author_key, signature, entry_type, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		hash, rawCBOR, authorKey, signature, entryType, createdAt,
	)
	if err != nil {
		return fmt.Errorf("insert entry: %w", err)
	}

	for _, parent := range parents {
		_, err = tx.Exec(
			"INSERT OR IGNORE INTO entry_parents (entry_hash, parent_hash) VALUES (?, ?)",
			hash, parent,
		)
		if err != nil {
			return fmt.Errorf("insert parent: %w", err)
		}
	}

	return tx.Commit()
}

// HasEntry checks if an entry exists by hash.
func (s *LogDB) HasEntry(hash []byte) (bool, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM entries WHERE hash = ?", hash).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("has entry: %w", err)
	}
	return count > 0, nil
}

// GetEntry retrieves a raw entry by hash.
func (s *LogDB) GetEntry(hash []byte) (*RawEntry, error) {
	var e RawEntry
	err := s.db.QueryRow(
		"SELECT hash, raw_cbor, author_key, signature, entry_type, created_at FROM entries WHERE hash = ?",
		hash,
	).Scan(&e.Hash, &e.RawCBOR, &e.AuthorKey, &e.Signature, &e.EntryType, &e.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get entry: %w", err)
	}

	parents, err := s.GetParents(hash)
	if err != nil {
		return nil, err
	}
	e.Parents = parents
	return &e, nil
}

// GetParents returns the parent hashes for an entry.
func (s *LogDB) GetParents(entryHash []byte) ([][]byte, error) {
	rows, err := s.db.Query("SELECT parent_hash FROM entry_parents WHERE entry_hash = ?", entryHash)
	if err != nil {
		return nil, fmt.Errorf("get parents: %w", err)
	}
	defer rows.Close()

	var parents [][]byte
	for rows.Next() {
		var parent []byte
		if err := rows.Scan(&parent); err != nil {
			return nil, fmt.Errorf("scan parent: %w", err)
		}
		parents = append(parents, parent)
	}
	return parents, rows.Err()
}

// GetChildren returns entry hashes that reference this hash as a parent.
func (s *LogDB) GetChildren(parentHash []byte) ([][]byte, error) {
	rows, err := s.db.Query("SELECT entry_hash FROM entry_parents WHERE parent_hash = ?", parentHash)
	if err != nil {
		return nil, fmt.Errorf("get children: %w", err)
	}
	defer rows.Close()

	var children [][]byte
	for rows.Next() {
		var child []byte
		if err := rows.Scan(&child); err != nil {
			return nil, fmt.Errorf("scan child: %w", err)
		}
		children = append(children, child)
	}
	return children, rows.Err()
}

// AllHashes returns all entry hashes in the log.
func (s *LogDB) AllHashes() ([][]byte, error) {
	rows, err := s.db.Query("SELECT hash FROM entries")
	if err != nil {
		return nil, fmt.Errorf("all hashes: %w", err)
	}
	defer rows.Close()

	var hashes [][]byte
	for rows.Next() {
		var h []byte
		if err := rows.Scan(&h); err != nil {
			return nil, fmt.Errorf("scan hash: %w", err)
		}
		hashes = append(hashes, h)
	}
	return hashes, rows.Err()
}

// EntriesByType returns all entries of a given type.
func (s *LogDB) EntriesByType(entryType int) ([]*RawEntry, error) {
	rows, err := s.db.Query(
		"SELECT hash, raw_cbor, author_key, signature, entry_type, created_at FROM entries WHERE entry_type = ? ORDER BY created_at",
		entryType,
	)
	if err != nil {
		return nil, fmt.Errorf("entries by type: %w", err)
	}
	defer rows.Close()

	var entries []*RawEntry
	for rows.Next() {
		var e RawEntry
		if err := rows.Scan(&e.Hash, &e.RawCBOR, &e.AuthorKey, &e.Signature, &e.EntryType, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan entry: %w", err)
		}
		entries = append(entries, &e)
	}
	return entries, rows.Err()
}

// EntriesSince returns entries created after the given timestamp, ordered by time.
func (s *LogDB) EntriesSince(since int64, limit int) ([]*RawEntry, error) {
	rows, err := s.db.Query(
		"SELECT hash, raw_cbor, author_key, signature, entry_type, created_at FROM entries WHERE created_at > ? ORDER BY created_at LIMIT ?",
		since, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("entries since: %w", err)
	}
	defer rows.Close()

	var entries []*RawEntry
	for rows.Next() {
		var e RawEntry
		if err := rows.Scan(&e.Hash, &e.RawCBOR, &e.AuthorKey, &e.Signature, &e.EntryType, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan entry: %w", err)
		}
		entries = append(entries, &e)
	}
	return entries, rows.Err()
}

// EntriesByTypeAndChannel returns message entries for a specific channel, ordered by time.
// Requires decoding CBOR to match channel ID, so this scans message-type entries.
func (s *LogDB) EntriesByTypeInRange(entryType int, since int64, limit int) ([]*RawEntry, error) {
	rows, err := s.db.Query(
		"SELECT hash, raw_cbor, author_key, signature, entry_type, created_at FROM entries WHERE entry_type = ? AND created_at > ? ORDER BY created_at LIMIT ?",
		entryType, since, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("entries by type in range: %w", err)
	}
	defer rows.Close()

	var entries []*RawEntry
	for rows.Next() {
		var e RawEntry
		if err := rows.Scan(&e.Hash, &e.RawCBOR, &e.AuthorKey, &e.Signature, &e.EntryType, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan entry: %w", err)
		}
		entries = append(entries, &e)
	}
	return entries, rows.Err()
}

// LatestTimestamp returns the most recent created_at timestamp in the log.
func (s *LogDB) LatestTimestamp() (int64, error) {
	var ts int64
	err := s.db.QueryRow("SELECT COALESCE(MAX(created_at), 0) FROM entries").Scan(&ts)
	return ts, err
}

// EntryCount returns the total number of entries.
func (s *LogDB) EntryCount() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM entries").Scan(&count)
	return count, err
}

// GetEntriesByAuthor returns entries from a specific author after a timestamp (rule R2).
func (s *LogDB) GetEntriesByAuthor(authorKey []byte, afterTimestamp int64) ([]*RawEntry, error) {
	rows, err := s.db.Query(
		"SELECT hash, raw_cbor, author_key, signature, entry_type, created_at FROM entries WHERE author_key = ? AND created_at > ? ORDER BY created_at",
		authorKey, afterTimestamp,
	)
	if err != nil {
		return nil, fmt.Errorf("entries by author: %w", err)
	}
	defer rows.Close()

	var entries []*RawEntry
	for rows.Next() {
		var e RawEntry
		if err := rows.Scan(&e.Hash, &e.RawCBOR, &e.AuthorKey, &e.Signature, &e.EntryType, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan entry: %w", err)
		}
		entries = append(entries, &e)
	}
	return entries, rows.Err()
}

// MarkEntryRejected flags an entry as rejected (rule R2).
// Creates a rejected_entries table if needed and records the rejection.
func (s *LogDB) MarkEntryRejected(hash []byte, reason string) error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS rejected_entries (
			hash   BLOB PRIMARY KEY,
			reason TEXT NOT NULL
		)`)
	if err != nil {
		return err
	}
	_, err = s.db.Exec("INSERT OR IGNORE INTO rejected_entries (hash, reason) VALUES (?, ?)", hash, reason)
	return err
}

// IsEntryRejected checks if an entry has been marked as rejected.
func (s *LogDB) IsEntryRejected(hash []byte) (bool, error) {
	// Table may not exist yet
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='rejected_entries'").Scan(&count)
	if err != nil || count == 0 {
		return false, nil
	}
	err = s.db.QueryRow("SELECT COUNT(*) FROM rejected_entries WHERE hash = ?", hash).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Close closes the database.
func (s *LogDB) Close() error {
	return s.db.Close()
}

// RawEntry represents a stored log entry.
type RawEntry struct {
	Hash      []byte
	RawCBOR   []byte
	AuthorKey []byte
	Signature []byte
	EntryType int
	CreatedAt int64
	Parents   [][]byte
}
