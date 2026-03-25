package errors

import (
	"errors"
	"fmt"
)

// Severity indicates how OpenClaw should handle the error.
type Severity string

const (
	// Transient means the connector will auto-retry with backoff. OpenClaw waits.
	Transient Severity = "transient"
	// Degraded means partial failure, connector won't auto-retry. OpenClaw decides.
	Degraded Severity = "degraded"
	// Fatal means human intervention is required. OpenClaw must inform the human.
	Fatal Severity = "fatal"
)

// Error is a structured Moltwork error carrying a machine-readable code,
// severity, human-safe message, and structured detail.
type Error struct {
	Code         string         `json:"error_code"`
	Severity     Severity       `json:"severity"`
	HumanMessage string         `json:"human_message"`
	Detail       map[string]any `json:"detail,omitempty"`
	Cause        error          `json:"-"` // never exposed to API
}

func (e *Error) Error() string {
	return e.Code + ": " + e.HumanMessage
}

func (e *Error) Unwrap() error {
	return e.Cause
}

// New creates a structured error.
func New(code string, sev Severity, humanMsg string, detail map[string]any) *Error {
	return &Error{
		Code:         code,
		Severity:     sev,
		HumanMessage: humanMsg,
		Detail:       detail,
	}
}

// Wrap wraps an underlying Go error in a structured error.
func Wrap(err error, code string, sev Severity, humanMsg string, detail map[string]any) *Error {
	return &Error{
		Code:         code,
		Severity:     sev,
		HumanMessage: humanMsg,
		Detail:       detail,
		Cause:        err,
	}
}

// WithOnboardingStep adds onboarding step context to the error's detail map.
func WithOnboardingStep(e *Error, step int, completed []int) *Error {
	if e.Detail == nil {
		e.Detail = make(map[string]any)
	}
	e.Detail["onboarding_step"] = step
	e.Detail["onboarding_completed"] = completed
	return e
}

// IsError extracts a structured *Error from any error using errors.As.
func IsError(err error) (*Error, bool) {
	var mErr *Error
	if errors.As(err, &mErr) {
		return mErr, true
	}
	return nil, false
}

// Unknown creates a generic error for unexpected failures.
// The underlying error message is never exposed to the human.
func Unknown(component, operation string, err error) *Error {
	return &Error{
		Code:         fmt.Sprintf("%s.%s.unknown", component, operation),
		Severity:     Degraded,
		HumanMessage: fmt.Sprintf("Something unexpected happened during %s. Check the logs for details.", operation),
		Cause:        err,
	}
}
