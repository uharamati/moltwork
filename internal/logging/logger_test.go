package logging

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestLoggerOutput(t *testing.T) {
	var buf bytes.Buffer
	log := New("test").WithOutput(&buf)

	log.Info("hello", map[string]any{"key": "value"})

	var entry Entry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log entry: %v", err)
	}

	if entry.Level != LevelInfo {
		t.Errorf("expected level info, got %s", entry.Level)
	}
	if entry.Component != "test" {
		t.Errorf("expected component test, got %s", entry.Component)
	}
	if entry.Message != "hello" {
		t.Errorf("expected message hello, got %s", entry.Message)
	}
	if entry.Fields["key"] != "value" {
		t.Errorf("expected field key=value, got %v", entry.Fields["key"])
	}
}

func TestLoggerRedactsSensitiveFields(t *testing.T) {
	var buf bytes.Buffer
	log := New("test").WithOutput(&buf)

	log.Info("auth", map[string]any{
		"private_key": "supersecret",
		"token":       "abc123",
		"username":    "alice",
	})

	var entry Entry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log entry: %v", err)
	}

	if entry.Fields["private_key"] != "[REDACTED]" {
		t.Errorf("private_key should be redacted, got %v", entry.Fields["private_key"])
	}
	if entry.Fields["token"] != "[REDACTED]" {
		t.Errorf("token should be redacted, got %v", entry.Fields["token"])
	}
	if entry.Fields["username"] != "alice" {
		t.Errorf("username should not be redacted, got %v", entry.Fields["username"])
	}
}

func TestCorrelationID(t *testing.T) {
	var buf bytes.Buffer
	log := New("test").WithOutput(&buf).WithCorrelation("req-123")

	log.Info("correlated")

	var entry Entry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log entry: %v", err)
	}

	if entry.CorrelationID != "req-123" {
		t.Errorf("expected correlation_id req-123, got %s", entry.CorrelationID)
	}
}
