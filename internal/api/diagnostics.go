package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	merrors "moltwork/internal/errors"
	"moltwork/internal/store"
)

func (s *Server) handleDiagnosticsBundle(w http.ResponseWriter, r *http.Request) {
	if s.diagDB == nil {
		writeError(w, r, merrors.StorageIntegrityDiagnosticsCorrupted(), 503)
		return
	}

	// Build the bundle from safe data sources only.
	// Structural redaction: this code never accesses keyDB private material.
	bundle := map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339Nano),
		"go_version":   runtime.Version(),
		"os":           runtime.GOOS,
		"arch":         runtime.GOARCH,
	}

	// Health snapshot
	if s.healthChecker != nil {
		bundle["health"] = s.healthChecker.Check()
	}

	// Last 24h of tier 3 logs
	cutoff := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339Nano)
	logs, err := s.diagDB.Query(store.LogFilter{
		TimeStart: cutoff,
		Tier:      3,
		Limit:     10000,
	})
	if err == nil {
		bundle["logs"] = logs
		bundle["log_count"] = len(logs)
	}

	// Agent registry summary (counts only — no public keys by default)
	if s.conn != nil && s.conn.Registry() != nil {
		regSummary := map[string]any{
			"total_agents": s.conn.Registry().Count(),
		}
		var revoked int
		for _, a := range s.conn.Registry().All() {
			if a.Revoked {
				revoked++
			}
		}
		regSummary["revoked_agents"] = revoked

		if r.URL.Query().Get("include_public_keys") == "true" {
			var keys []string
			for _, a := range s.conn.Registry().All() {
				keys = append(keys, fmt.Sprintf("%x", a.PublicKey))
			}
			regSummary["public_keys"] = keys
		}
		bundle["registry"] = regSummary
	}

	// Gossip state (peer count, no IPs by default)
	if s.conn != nil && s.conn.GossipNode() != nil {
		gossipState := map[string]any{
			"peer_count": len(s.conn.GossipNode().Tracker().Peers()),
			"peer_id":    s.conn.GossipNode().Host().ID().String(),
		}
		bundle["gossip"] = gossipState
	}

	// Database sizes
	dbInfo := map[string]any{}
	if s.conn != nil && s.conn.LogDB() != nil {
		count, _ := s.conn.LogDB().EntryCount()
		dbInfo["log_entry_count"] = count
	}
	diagSize, _ := s.diagDB.SizeBytes()
	diagCount, _ := s.diagDB.EntryCount()
	dbInfo["diagnostics_size_bytes"] = diagSize
	dbInfo["diagnostics_entry_count"] = diagCount
	bundle["databases"] = dbInfo

	// Write to temp file with 0600 permissions
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		writeError(w, r, err, 500)
		return
	}

	tmpDir := os.TempDir()
	filename := fmt.Sprintf("moltwork-diag-%d.json", time.Now().Unix())
	bundlePath := filepath.Join(tmpDir, filename)
	if err := os.WriteFile(bundlePath, data, 0600); err != nil {
		writeError(w, r, err, 500)
		return
	}

	writeSuccess(w, r, map[string]any{
		"bundle_path": bundlePath,
	})
}
