package store

import (
	"path/filepath"
	"testing"
	"time"
)

func openTestDiagDB(t *testing.T) *DiagDB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test_diag.db")
	db, err := OpenDiagDB(path)
	if err != nil {
		t.Fatalf("open diag db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestDiagDBInsertAndQuery(t *testing.T) {
	db := openTestDiagDB(t)

	entry := DiagEntry{
		Timestamp:     "2026-03-24T10:00:00.000Z",
		Component:     "connector",
		Severity:      "info",
		CorrelationID: "abc-123",
		Tier:          1,
		HumanMessage:  "The Moltwork connector has started.",
		Detail:        map[string]any{"peer_count": float64(3)},
	}

	if err := db.InsertLog(entry); err != nil {
		t.Fatalf("insert: %v", err)
	}

	entries, err := db.Query(LogFilter{Tier: 3})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	got := entries[0]
	if got.Component != "connector" {
		t.Errorf("component: got %s, want connector", got.Component)
	}
	if got.CorrelationID != "abc-123" {
		t.Errorf("correlation_id: got %s, want abc-123", got.CorrelationID)
	}
	if got.HumanMessage != "The Moltwork connector has started." {
		t.Errorf("human_message: got %s", got.HumanMessage)
	}
	if got.Detail["peer_count"] != float64(3) {
		t.Errorf("detail peer_count: got %v", got.Detail["peer_count"])
	}
}

func TestDiagDBFilterBySeverity(t *testing.T) {
	db := openTestDiagDB(t)

	for _, sev := range []string{"debug", "info", "warn", "error", "fatal"} {
		db.InsertLog(DiagEntry{
			Timestamp: "2026-03-24T10:00:00.000Z",
			Component: "test",
			Severity:  sev,
			Tier:      2,
		})
	}

	entries, err := db.Query(LogFilter{Severity: "warn", Tier: 3})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) != 3 { // warn, error, fatal
		t.Errorf("expected 3 entries (warn+error+fatal), got %d", len(entries))
	}

	entries, err = db.Query(LogFilter{Severity: "error", Tier: 3})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) != 2 { // error, fatal
		t.Errorf("expected 2 entries (error+fatal), got %d", len(entries))
	}
}

func TestDiagDBFilterByComponent(t *testing.T) {
	db := openTestDiagDB(t)

	db.InsertLog(DiagEntry{Timestamp: "2026-03-24T10:00:00Z", Component: "gossip", Severity: "info", Tier: 2})
	db.InsertLog(DiagEntry{Timestamp: "2026-03-24T10:00:01Z", Component: "crypto", Severity: "info", Tier: 2})
	db.InsertLog(DiagEntry{Timestamp: "2026-03-24T10:00:02Z", Component: "gossip", Severity: "warn", Tier: 1})

	entries, err := db.Query(LogFilter{Component: "gossip", Tier: 3})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 gossip entries, got %d", len(entries))
	}
}

func TestDiagDBFilterByCorrelationID(t *testing.T) {
	db := openTestDiagDB(t)

	db.InsertLog(DiagEntry{Timestamp: "2026-03-24T10:00:00Z", Component: "api", Severity: "info", Tier: 2, CorrelationID: "req-001"})
	db.InsertLog(DiagEntry{Timestamp: "2026-03-24T10:00:01Z", Component: "connector", Severity: "error", Tier: 1, CorrelationID: "req-001"})
	db.InsertLog(DiagEntry{Timestamp: "2026-03-24T10:00:02Z", Component: "api", Severity: "info", Tier: 2, CorrelationID: "req-002"})

	entries, err := db.Query(LogFilter{CorrelationID: "req-001", Tier: 3})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries for req-001, got %d", len(entries))
	}
}

func TestDiagDBFilterByTier(t *testing.T) {
	db := openTestDiagDB(t)

	db.InsertLog(DiagEntry{Timestamp: "2026-03-24T10:00:00Z", Component: "test", Severity: "info", Tier: 1})
	db.InsertLog(DiagEntry{Timestamp: "2026-03-24T10:00:01Z", Component: "test", Severity: "info", Tier: 2})
	db.InsertLog(DiagEntry{Timestamp: "2026-03-24T10:00:02Z", Component: "test", Severity: "debug", Tier: 3})

	entries, err := db.Query(LogFilter{Tier: 1})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("tier 1: expected 1 entry, got %d", len(entries))
	}

	entries, err = db.Query(LogFilter{Tier: 2})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("tier <=2: expected 2 entries, got %d", len(entries))
	}
}

func TestDiagDBFilterBySearch(t *testing.T) {
	db := openTestDiagDB(t)

	db.InsertLog(DiagEntry{Timestamp: "2026-03-24T10:00:00Z", Component: "test", Severity: "info", Tier: 1, HumanMessage: "connector started successfully"})
	db.InsertLog(DiagEntry{Timestamp: "2026-03-24T10:00:01Z", Component: "test", Severity: "error", Tier: 1, HumanMessage: "Slack token revoked"})

	entries, err := db.Query(LogFilter{Search: "Slack", Tier: 3})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 match for 'Slack', got %d", len(entries))
	}
}

func TestDiagDBFilterByTimeRange(t *testing.T) {
	db := openTestDiagDB(t)

	db.InsertLog(DiagEntry{Timestamp: "2026-03-24T09:00:00Z", Component: "test", Severity: "info", Tier: 2})
	db.InsertLog(DiagEntry{Timestamp: "2026-03-24T10:00:00Z", Component: "test", Severity: "info", Tier: 2})
	db.InsertLog(DiagEntry{Timestamp: "2026-03-24T11:00:00Z", Component: "test", Severity: "info", Tier: 2})

	entries, err := db.Query(LogFilter{TimeStart: "2026-03-24T09:30:00Z", TimeEnd: "2026-03-24T10:30:00Z", Tier: 3})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry in range, got %d", len(entries))
	}
}

func TestDiagDBPagination(t *testing.T) {
	db := openTestDiagDB(t)

	for i := 0; i < 10; i++ {
		db.InsertLog(DiagEntry{
			Timestamp: "2026-03-24T10:00:00Z",
			Component: "test",
			Severity:  "info",
			Tier:      2,
		})
	}

	entries, err := db.Query(LogFilter{Tier: 3, Limit: 3, Offset: 0})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("page 1: expected 3, got %d", len(entries))
	}

	entries, err = db.Query(LogFilter{Tier: 3, Limit: 3, Offset: 8})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("last page: expected 2, got %d", len(entries))
	}
}

func TestDiagDBPruneByAge(t *testing.T) {
	db := openTestDiagDB(t)

	// Insert entries with old created_at via direct SQL
	oldTime := time.Now().Add(-48 * time.Hour).UnixMilli()
	db.db.Exec("INSERT INTO log_entries (timestamp, component, severity, tier, created_at) VALUES (?, ?, ?, ?, ?)",
		"2026-03-22T10:00:00Z", "test", "info", 2, oldTime)
	db.InsertLog(DiagEntry{Timestamp: "2026-03-24T10:00:00Z", Component: "test", Severity: "info", Tier: 2})

	count, _ := db.EntryCount()
	if count != 2 {
		t.Fatalf("expected 2 entries before prune, got %d", count)
	}

	if err := db.Prune(24*time.Hour, 0); err != nil {
		t.Fatalf("prune: %v", err)
	}

	count, _ = db.EntryCount()
	if count != 1 {
		t.Errorf("expected 1 entry after prune, got %d", count)
	}
}

func TestDiagDBEntryCountAndSize(t *testing.T) {
	db := openTestDiagDB(t)

	count, err := db.EntryCount()
	if err != nil {
		t.Fatalf("entry count: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 entries, got %d", count)
	}

	db.InsertLog(DiagEntry{Timestamp: "2026-03-24T10:00:00Z", Component: "test", Severity: "info", Tier: 2})

	count, _ = db.EntryCount()
	if count != 1 {
		t.Errorf("expected 1 entry, got %d", count)
	}

	size, err := db.SizeBytes()
	if err != nil {
		t.Fatalf("size: %v", err)
	}
	if size <= 0 {
		t.Error("size should be positive")
	}
}

func TestDiagDBNullableFields(t *testing.T) {
	db := openTestDiagDB(t)

	// Insert with no optional fields
	db.InsertLog(DiagEntry{
		Timestamp: "2026-03-24T10:00:00Z",
		Component: "test",
		Severity:  "debug",
		Tier:      3,
	})

	entries, err := db.Query(LogFilter{Tier: 3})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].CorrelationID != "" {
		t.Error("correlation_id should be empty")
	}
	if entries[0].HumanMessage != "" {
		t.Error("human_message should be empty")
	}
}
