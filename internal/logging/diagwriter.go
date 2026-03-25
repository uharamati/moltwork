package logging

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"moltwork/internal/store"
)

// DiagWriter routes structured log entries to the diagnostics database.
// Falls back to stderr if the database write fails.
type DiagWriter struct {
	db       *store.DiagDB
	fallback io.Writer
	mu       sync.Mutex
	tier3    bool // whether to write tier 3 (debug) entries
}

// NewDiagWriter creates a DiagWriter that writes to the given diagnostics DB.
func NewDiagWriter(db *store.DiagDB, tier3Enabled bool) *DiagWriter {
	return &DiagWriter{
		db:       db,
		fallback: os.Stderr,
		tier3:    tier3Enabled,
	}
}

// Write stores a log entry in the diagnostics database.
func (dw *DiagWriter) Write(component, severity, correlationID, humanMessage, msg string, fields map[string]any) {
	tier := defaultTier(severity)
	if tier == 3 && !dw.tier3 {
		return
	}

	entry := store.DiagEntry{
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		Component:     component,
		Severity:      severity,
		CorrelationID: correlationID,
		Tier:          tier,
		HumanMessage:  humanMessage,
		Detail:        fields,
	}

	dw.mu.Lock()
	defer dw.mu.Unlock()

	if err := dw.db.InsertLog(entry); err != nil {
		// Fallback: write error to stderr, don't lose the log
		fmt.Fprintf(dw.fallback, "[diag-fallback] %s %s %s: %s (db write failed: %v)\n",
			entry.Timestamp, entry.Severity, entry.Component, msg, err)
	}
}

// WriteTiered stores a log entry with an explicit tier override.
func (dw *DiagWriter) WriteTiered(tier int, component, severity, correlationID, humanMessage, msg string, fields map[string]any) {
	if tier == 3 && !dw.tier3 {
		return
	}

	entry := store.DiagEntry{
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		Component:     component,
		Severity:      severity,
		CorrelationID: correlationID,
		Tier:          tier,
		HumanMessage:  humanMessage,
		Detail:        fields,
	}

	dw.mu.Lock()
	defer dw.mu.Unlock()

	if err := dw.db.InsertLog(entry); err != nil {
		fmt.Fprintf(dw.fallback, "[diag-fallback] %s %s %s: %s (db write failed: %v)\n",
			entry.Timestamp, entry.Severity, entry.Component, msg, err)
	}
}

// defaultTier assigns a tier based on severity.
func defaultTier(severity string) int {
	switch severity {
	case "debug":
		return 3
	case "info":
		return 2
	case "warn", "error", "fatal":
		return 1
	default:
		return 2
	}
}
