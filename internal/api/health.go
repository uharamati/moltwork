package api

import (
	"net/http"

	"moltwork/internal/health"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if s.healthChecker == nil {
		writeJSON(w, health.HealthResponse{
			OK:           false,
			Status:       health.Initializing,
			HumanSummary: "Health checker is not yet available.",
		})
		return
	}
	resp := s.healthChecker.Check()
	writeJSON(w, resp)
}
