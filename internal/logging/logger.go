package logging

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

type Level string

const (
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
	LevelFatal Level = "fatal"
)

type Entry struct {
	Timestamp     string         `json:"timestamp"`
	Level         Level          `json:"level"`
	Component     string         `json:"component"`
	CorrelationID string         `json:"correlation_id,omitempty"`
	Message       string         `json:"message"`
	Fields        map[string]any `json:"fields,omitempty"`
}

type Logger struct {
	component     string
	correlationID string
	out           io.Writer
	diagWriter    *DiagWriter
	mu            sync.Mutex
}

func New(component string) *Logger {
	return &Logger{
		component: component,
		out:       os.Stderr,
	}
}

func (l *Logger) WithOutput(w io.Writer) *Logger {
	return &Logger{
		component:     l.component,
		correlationID: l.correlationID,
		out:           w,
		diagWriter:    l.diagWriter,
	}
}

func (l *Logger) WithCorrelation(id string) *Logger {
	return &Logger{
		component:     l.component,
		correlationID: id,
		out:           l.out,
		diagWriter:    l.diagWriter,
	}
}

// WithDiagWriter returns a new Logger that also writes to the diagnostics database.
func (l *Logger) WithDiagWriter(dw *DiagWriter) *Logger {
	return &Logger{
		component:     l.component,
		correlationID: l.correlationID,
		out:           l.out,
		diagWriter:    dw,
	}
}

func (l *Logger) log(level Level, msg string, fields map[string]any) {
	// Redact sensitive fields before logging
	safe := RedactFields(fields)

	entry := Entry{
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		Level:         level,
		Component:     l.component,
		CorrelationID: l.correlationID,
		Message:       msg,
		Fields:        safe,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	l.mu.Lock()
	l.out.Write(data)
	l.out.Write([]byte("\n"))
	l.mu.Unlock()

	// Also write to diagnostics DB if available
	if l.diagWriter != nil {
		l.diagWriter.Write(l.component, string(level), l.correlationID, "", msg, safe)
	}
}

// LogTiered writes a log entry with an explicit tier and human message.
// Use this for key events where the tier and human-facing text must be controlled.
func (l *Logger) LogTiered(level Level, tier int, humanMsg string, msg string, fields ...map[string]any) {
	f := mergeFields(fields)
	safe := RedactFields(f)

	entry := Entry{
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		Level:         level,
		Component:     l.component,
		CorrelationID: l.correlationID,
		Message:       msg,
		Fields:        safe,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	l.mu.Lock()
	l.out.Write(data)
	l.out.Write([]byte("\n"))
	l.mu.Unlock()

	if l.diagWriter != nil {
		l.diagWriter.WriteTiered(tier, l.component, string(level), l.correlationID, humanMsg, msg, safe)
	}
}

func (l *Logger) Debug(msg string, fields ...map[string]any) {
	l.log(LevelDebug, msg, mergeFields(fields))
}

func (l *Logger) Info(msg string, fields ...map[string]any) {
	l.log(LevelInfo, msg, mergeFields(fields))
}

func (l *Logger) Warn(msg string, fields ...map[string]any) {
	l.log(LevelWarn, msg, mergeFields(fields))
}

func (l *Logger) Error(msg string, fields ...map[string]any) {
	l.log(LevelError, msg, mergeFields(fields))
}

func (l *Logger) Fatal(msg string, fields ...map[string]any) {
	l.log(LevelFatal, msg, mergeFields(fields))
	os.Exit(1)
}

func mergeFields(fields []map[string]any) map[string]any {
	if len(fields) == 0 {
		return nil
	}
	return fields[0]
}
