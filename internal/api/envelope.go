package api

import (
	"errors"
	"net/http"

	merrors "moltwork/internal/errors"
)

// Envelope is the standard API response wrapper.
type Envelope struct {
	OK            bool     `json:"ok"`
	CorrelationID string   `json:"correlation_id"`
	Result        any      `json:"result,omitempty"`
	Error         *APIError `json:"error,omitempty"`
}

// APIError is the structured error in an envelope response.
type APIError struct {
	ErrorCode    string         `json:"error_code"`
	Severity     string         `json:"severity"`
	HumanMessage string         `json:"human_message"`
	Detail       map[string]any `json:"detail,omitempty"`
}

// writeSuccess writes a successful envelope response.
func writeSuccess(w http.ResponseWriter, r *http.Request, result any) {
	corrID, _ := r.Context().Value(correlationIDKey).(string)
	writeJSON(w, Envelope{
		OK:            true,
		CorrelationID: corrID,
		Result:        result,
	})
}

// writeError writes an error envelope response.
// If err is a *merrors.Error, its fields are used. Otherwise, it is wrapped
// in merrors.Unknown to prevent leaking internal error strings (G7).
func writeError(w http.ResponseWriter, r *http.Request, err error, httpCode int) {
	corrID, _ := r.Context().Value(correlationIDKey).(string)

	var mErr *merrors.Error
	if !errors.As(err, &mErr) {
		mErr = merrors.Unknown("internal", "request", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpCode)

	env := Envelope{
		OK:            false,
		CorrelationID: corrID,
		Error: &APIError{
			ErrorCode:    mErr.Code,
			Severity:     string(mErr.Severity),
			HumanMessage: mErr.HumanMessage,
			Detail:       mErr.Detail,
		},
	}
	writeJSON(w, env)
}

// httpCodeForSeverity returns a suggested HTTP status code for an error severity.
func httpCodeForSeverity(sev merrors.Severity) int {
	switch sev {
	case merrors.Transient:
		return http.StatusServiceUnavailable // 503
	case merrors.Degraded:
		return http.StatusConflict // 409
	case merrors.Fatal:
		return http.StatusUnprocessableEntity // 422
	default:
		return http.StatusInternalServerError
	}
}
