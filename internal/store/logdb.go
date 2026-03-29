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

	// Schema version tracking — allows future migrations to be applied in order.
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		version INTEGER NOT NULL DEFAULT 1
	)`); err != nil {
		return fmt.Errorf("create schema_version: %w", err)
	}
	s.db.Exec("INSERT OR IGNORE INTO schema_version (id, version) VALUES (1, 1)")

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

		CREATE TABLE IF NOT EXISTS rejected_entries (
			hash   BLOB PRIMARY KEY,
			reason TEXT NOT NULL
		);

		CREATE VIRTUAL TABLE IF NOT EXISTS message_fts USING fts5(
			hash_hex, content, author, channel
		);
	`)
	if err != nil {
		return fmt.Errorf("migrate log db: %w", err)
	}

	// Migration v2: add channel_id and timestamp to FTS index (M7, L2).
	// FTS5 tables can't be ALTERed — drop and recreate with new columns.
	// The backfillFTSIndex on startup will repopulate.
	var version int
	s.db.QueryRow("SELECT version FROM schema_version WHERE id = 1").Scan(&version)
	if version < 2 {
		s.db.Exec("DROP TABLE IF EXISTS message_fts")
		s.db.Exec(`CREATE VIRTUAL TABLE IF NOT EXISTS message_fts USING fts5(
			hash_hex, content, author, channel, channel_id UNINDEXED, timestamp UNINDEXED
		)`)
		s.db.Exec("UPDATE schema_version SET version = 2 WHERE id = 1")
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

// HashesSince returns entry hashes with created_at > since.
// Used by incremental sync to exchange only recent hashes instead of the full set.
// Uses idx_entries_created index for efficient range queries.
func (s *LogDB) HashesSince(since int64) ([][]byte, error) {
	rows, err := s.db.Query("SELECT hash FROM entries WHERE created_at > ?", since)
	if err != nil {
		return nil, fmt.Errorf("hashes since: %w", err)
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

// MaxCreatedAt returns the maximum created_at timestamp across all entries.
// Returns 0 if the log is empty.
func (s *LogDB) MaxCreatedAt() (int64, error) {
	var ts int64
	err := s.db.QueryRow("SELECT COALESCE(MAX(created_at), 0) FROM entries").Scan(&ts)
	return ts, err
}

// AllEntries returns all entries in the log with their parent hashes.
// Uses a single JOIN query instead of N+1 GetParents calls.
func (s *LogDB) AllEntries() ([]*RawEntry, error) {
	rows, err := s.db.Query(`
		SELECT e.hash, e.raw_cbor, e.author_key, e.signature, e.entry_type, e.created_at, p.parent_hash
		FROM entries e
		LEFT JOIN entry_parents p ON e.hash = p.entry_hash
		ORDER BY e.created_at, e.hash`)
	if err != nil {
		return nil, fmt.Errorf("all entries: %w", err)
	}
	defer rows.Close()

	entryMap := make(map[string]*RawEntry)
	var order []string
	for rows.Next() {
		var hash, rawCBOR, authorKey, signature []byte
		var entryType int
		var createdAt int64
		var parentHash []byte
		if err := rows.Scan(&hash, &rawCBOR, &authorKey, &signature, &entryType, &createdAt, &parentHash); err != nil {
			return nil, fmt.Errorf("scan entry: %w", err)
		}
		key := fmt.Sprintf("%x", hash)
		if existing, ok := entryMap[key]; ok {
			if parentHash != nil {
				existing.Parents = append(existing.Parents, parentHash)
			}
		} else {
			e := &RawEntry{
				Hash:      hash,
				RawCBOR:   rawCBOR,
				AuthorKey: authorKey,
				Signature: signature,
				EntryType: entryType,
				CreatedAt: createdAt,
			}
			if parentHash != nil {
				e.Parents = [][]byte{parentHash}
			}
			entryMap[key] = e
			order = append(order, key)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	entries := make([]*RawEntry, 0, len(order))
	for _, key := range order {
		entries = append(entries, entryMap[key])
	}
	return entries, nil
}

// AllEntriesPaginated returns entries with offset/limit for paginated retrieval.
// Unlike AllEntries(), this avoids loading the entire log into memory.
func (s *LogDB) AllEntriesPaginated(offset, limit int) ([]*RawEntry, error) {
	rows, err := s.db.Query(`
		SELECT e.hash, e.raw_cbor, e.author_key, e.signature, e.entry_type, e.created_at, p.parent_hash
		FROM entries e
		LEFT JOIN entry_parents p ON e.hash = p.entry_hash
		ORDER BY e.created_at, e.hash
		LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("paginated entries: %w", err)
	}
	defer rows.Close()

	entryMap := make(map[string]*RawEntry)
	var order []string
	for rows.Next() {
		var hash, rawCBOR, authorKey, signature []byte
		var entryType int
		var createdAt int64
		var parentHash []byte
		if err := rows.Scan(&hash, &rawCBOR, &authorKey, &signature, &entryType, &createdAt, &parentHash); err != nil {
			return nil, fmt.Errorf("scan entry: %w", err)
		}
		key := fmt.Sprintf("%x", hash)
		if existing, ok := entryMap[key]; ok {
			if parentHash != nil {
				existing.Parents = append(existing.Parents, parentHash)
			}
		} else {
			e := &RawEntry{
				Hash:      hash,
				RawCBOR:   rawCBOR,
				AuthorKey: authorKey,
				Signature: signature,
				EntryType: entryType,
				CreatedAt: createdAt,
			}
			if parentHash != nil {
				e.Parents = [][]byte{parentHash}
			}
			entryMap[key] = e
			order = append(order, key)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	entries := make([]*RawEntry, 0, len(order))
	for _, key := range order {
		entries = append(entries, entryMap[key])
	}
	return entries, nil
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
func (s *LogDB) MarkEntryRejected(hash []byte, reason string) error {
	_, err := s.db.Exec("INSERT OR IGNORE INTO rejected_entries (hash, reason) VALUES (?, ?)", hash, reason)
	return err
}

// IsEntryRejected checks if an entry has been marked as rejected.
func (s *LogDB) IsEntryRejected(hash []byte) (bool, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM rejected_entries WHERE hash = ?", hash).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// IndexMessageForSearch adds a decoded message to the FTS5 search index.
// Called by the connector after decoding message entries.
func (s *LogDB) IndexMessageForSearch(hashHex, content, author, channel, channelID string, timestamp int64) error {
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO message_fts (hash_hex, content, author, channel, channel_id, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
		hashHex, content, author, channel, channelID, timestamp,
	)
	return err
}

// RemoveMessageFromSearch removes a deleted message from the FTS5 index.
func (s *LogDB) RemoveMessageFromSearch(hashHex string) error {
	_, err := s.db.Exec("DELETE FROM message_fts WHERE hash_hex = ?", hashHex)
	return err
}

// UpdateMessageSearchContent updates the content of an existing FTS entry (for edits).
func (s *LogDB) UpdateMessageSearchContent(hashHex, newContent string) error {
	_, err := s.db.Exec(
		"UPDATE message_fts SET content = ? WHERE hash_hex = ?",
		newContent, hashHex,
	)
	return err
}

// SearchFTS performs a full-text search across all indexed messages.
func (s *LogDB) SearchFTS(query string, limit int) ([]FTSResult, error) {
	rows, err := s.db.Query(
		"SELECT hash_hex, content, author, channel, channel_id, timestamp FROM message_fts WHERE message_fts MATCH ? ORDER BY timestamp DESC LIMIT ?",
		query, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("fts search: %w", err)
	}
	defer rows.Close()

	var results []FTSResult
	for rows.Next() {
		var r FTSResult
		if err := rows.Scan(&r.HashHex, &r.Content, &r.Author, &r.Channel, &r.ChannelID, &r.Timestamp); err != nil {
			return nil, fmt.Errorf("scan fts: %w", err)
		}
		results = append(results, r)
	}
	return results, rows.Err()
}

// FTSResult is a search result from the full-text index.
type FTSResult struct {
	HashHex   string
	Content   string
	Author    string
	Channel   string
	ChannelID string
	Timestamp int64
}

// UnindexedMessageCount returns the number of message entries not yet in the FTS index.
func (s *LogDB) UnindexedMessageCount(messageType int) (int, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM entries e
		 WHERE e.entry_type = ?
		 AND hex(e.hash) NOT IN (SELECT hash_hex FROM message_fts)`,
		messageType,
	).Scan(&count)
	return count, err
}

// LatestAttestationTime returns the most recent attestation timestamp for an agent.
// Uses the compound index on (author_key, entry_type, created_at) for O(1) lookup.
func (s *LogDB) LatestAttestationTime(authorKey []byte, entryType int) (int64, error) {
	var ts int64
	err := s.db.QueryRow(
		"SELECT COALESCE(MAX(created_at), 0) FROM entries WHERE author_key = ? AND entry_type = ?",
		authorKey, entryType,
	).Scan(&ts)
	return ts, err
}

// IntegrityCheck runs PRAGMA integrity_check and returns the result.
func (s *LogDB) IntegrityCheck() (string, error) {
	var result string
	err := s.db.QueryRow("PRAGMA integrity_check").Scan(&result)
	return result, err
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
