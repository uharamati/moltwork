package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// DiagDB manages the diagnostics log database (diagnostics.db).
// Separate from the workspace log and key databases — expendable data.
type DiagDB struct {
	db *sql.DB
}

// DiagEntry is a structured diagnostic log entry.
type DiagEntry struct {
	ID            int64          `json:"id,omitempty"`
	Timestamp     string         `json:"timestamp"`
	Component     string         `json:"component"`
	Severity      string         `json:"severity"`
	CorrelationID string         `json:"correlation_id,omitempty"`
	Tier          int            `json:"tier"`
	HumanMessage  string         `json:"human_message,omitempty"`
	Detail        map[string]any `json:"detail,omitempty"`
}

// LogFilter specifies query parameters for log retrieval.
type LogFilter struct {
	TimeStart     string // ISO 8601
	TimeEnd       string // ISO 8601
	Severity      string // minimum severity level
	Component     string
	CorrelationID string
	Tier          int // max tier to return (1, 2, or 3)
	Search        string
	Limit         int
	Offset        int
}

// severityRank maps severity strings to numeric ranks for filtering.
var severityRank = map[string]int{
	"debug": 0,
	"info":  1,
	"warn":  2,
	"error": 3,
	"fatal": 4,
}

// OpenDiagDB opens or creates the diagnostics database with WAL mode (rule S1).
func OpenDiagDB(path string) (*DiagDB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create diag db dir: %w", err)
	}

	db, err := sql.Open("sqlite", path+"?_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open diag db: %w", err)
	}

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}

	s := &DiagDB{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *DiagDB) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS log_entries (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp       TEXT NOT NULL,
			component       TEXT NOT NULL,
			severity        TEXT NOT NULL,
			correlation_id  TEXT,
			tier            INTEGER NOT NULL,
			human_message   TEXT,
			detail          TEXT,
			created_at      INTEGER NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_log_timestamp ON log_entries(timestamp);
		CREATE INDEX IF NOT EXISTS idx_log_severity ON log_entries(severity);
		CREATE INDEX IF NOT EXISTS idx_log_component ON log_entries(component);
		CREATE INDEX IF NOT EXISTS idx_log_correlation ON log_entries(correlation_id);
		CREATE INDEX IF NOT EXISTS idx_log_tier ON log_entries(tier);
		CREATE INDEX IF NOT EXISTS idx_log_created ON log_entries(created_at);
	`)
	if err != nil {
		return fmt.Errorf("migrate diag db: %w", err)
	}
	return nil
}

// InsertLog writes a diagnostic log entry.
func (s *DiagDB) InsertLog(entry DiagEntry) error {
	var detailJSON []byte
	if entry.Detail != nil {
		var err error
		detailJSON, err = json.Marshal(entry.Detail)
		if err != nil {
			return fmt.Errorf("marshal detail: %w", err)
		}
	}

	_, err := s.db.Exec(
		`INSERT INTO log_entries (timestamp, component, severity, correlation_id, tier, human_message, detail, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.Timestamp,
		entry.Component,
		entry.Severity,
		nullableString(entry.CorrelationID),
		entry.Tier,
		nullableString(entry.HumanMessage),
		nullableBytes(detailJSON),
		time.Now().UnixMilli(),
	)
	return err
}

// Query retrieves log entries matching the filter.
func (s *DiagDB) Query(f LogFilter) ([]DiagEntry, error) {
	var conditions []string
	var args []any

	if f.TimeStart != "" {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, f.TimeStart)
	}
	if f.TimeEnd != "" {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, f.TimeEnd)
	}
	if f.Severity != "" {
		minRank, ok := severityRank[f.Severity]
		if ok {
			// Include all severities at or above the minimum
			var sevs []string
			for sev, rank := range severityRank {
				if rank >= minRank {
					sevs = append(sevs, "?")
					args = append(args, sev)
				}
			}
			conditions = append(conditions, "severity IN ("+strings.Join(sevs, ",")+")")
		}
	}
	if f.Component != "" {
		conditions = append(conditions, "component = ?")
		args = append(args, f.Component)
	}
	if f.CorrelationID != "" {
		conditions = append(conditions, "correlation_id = ?")
		args = append(args, f.CorrelationID)
	}
	if f.Tier > 0 {
		conditions = append(conditions, "tier <= ?")
		args = append(args, f.Tier)
	}
	if f.Search != "" {
		conditions = append(conditions, "human_message LIKE ?")
		args = append(args, "%"+f.Search+"%")
	}

	query := "SELECT id, timestamp, component, severity, correlation_id, tier, human_message, detail FROM log_entries"
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY timestamp DESC"

	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	query += fmt.Sprintf(" LIMIT %d", limit)
	if f.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", f.Offset)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query diag logs: %w", err)
	}
	defer rows.Close()

	var entries []DiagEntry
	for rows.Next() {
		var e DiagEntry
		var corrID, humanMsg, detailStr sql.NullString
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Component, &e.Severity, &corrID, &e.Tier, &humanMsg, &detailStr); err != nil {
			return nil, fmt.Errorf("scan diag entry: %w", err)
		}
		e.CorrelationID = corrID.String
		e.HumanMessage = humanMsg.String
		if detailStr.Valid && detailStr.String != "" {
			if err := json.Unmarshal([]byte(detailStr.String), &e.Detail); err != nil {
				e.Detail = map[string]any{"_raw": detailStr.String, "_error": "corrupt JSON"}
			}
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// Prune deletes entries older than maxAge or if the database exceeds maxBytes.
// Size-based pruning runs first (keeps newest entries), then age-based pruning.
// This order prevents losing recent logs when both limits are hit.
func (s *DiagDB) Prune(maxAge time.Duration, maxBytes int64) error {
	// Prune by size first — keeps the newest entries
	if maxBytes > 0 {
		size, err := s.SizeBytes()
		if err != nil {
			return err
		}
		for size > maxBytes {
			// Delete oldest 1000 entries at a time
			if _, err := s.db.Exec("DELETE FROM log_entries WHERE id IN (SELECT id FROM log_entries ORDER BY created_at ASC LIMIT 1000)"); err != nil {
				return fmt.Errorf("prune by size: %w", err)
			}
			size, err = s.SizeBytes()
			if err != nil {
				return err
			}
		}
	}

	// Then prune by age
	cutoff := time.Now().Add(-maxAge).UnixMilli()
	if _, err := s.db.Exec("DELETE FROM log_entries WHERE created_at < ?", cutoff); err != nil {
		return fmt.Errorf("prune by age: %w", err)
	}

	return nil
}

// SizeBytes returns the database file size.
func (s *DiagDB) SizeBytes() (int64, error) {
	var pageCount, pageSize int64
	if err := s.db.QueryRow("PRAGMA page_count").Scan(&pageCount); err != nil {
		return 0, err
	}
	if err := s.db.QueryRow("PRAGMA page_size").Scan(&pageSize); err != nil {
		return 0, err
	}
	return pageCount * pageSize, nil
}

// EntryCount returns the number of log entries.
func (s *DiagDB) EntryCount() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM log_entries").Scan(&count)
	return count, err
}

// Close closes the database.
func (s *DiagDB) Close() error {
	return s.db.Close()
}

func nullableString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func nullableBytes(b []byte) sql.NullString {
	if b == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: string(b), Valid: true}
}
