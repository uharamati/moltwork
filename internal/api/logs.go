package api

import (
	"net/http"
	"strconv"

	merrors "moltwork/internal/errors"
	"moltwork/internal/store"
)

func (s *Server) handleLogsQuery(w http.ResponseWriter, r *http.Request) {
	if s.diagDB == nil {
		writeError(w, r, merrors.StorageIntegrityDiagnosticsCorrupted(), 503)
		return
	}

	tier, _ := strconv.Atoi(r.URL.Query().Get("tier"))
	if tier <= 0 {
		tier = 1
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	filter := store.LogFilter{
		TimeStart:     r.URL.Query().Get("time_start"),
		TimeEnd:       r.URL.Query().Get("time_end"),
		Severity:      r.URL.Query().Get("severity"),
		Component:     r.URL.Query().Get("component"),
		CorrelationID: r.URL.Query().Get("correlation_id"),
		Tier:          tier,
		Search:        r.URL.Query().Get("search"),
		Limit:         limit,
		Offset:        offset,
	}

	entries, err := s.diagDB.Query(filter)
	if err != nil {
		writeError(w, r, err, 500)
		return
	}

	writeSuccess(w, r, map[string]any{
		"entries": entries,
		"count":   len(entries),
	})
}
