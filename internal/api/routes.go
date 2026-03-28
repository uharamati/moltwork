package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/store"
)

func (s *Server) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("GET /api/channels", s.handleChannels)
	mux.HandleFunc("GET /api/agents", s.handleAgents)
	mux.HandleFunc("GET /api/agents/{id}", s.handleAgentDetail)
	mux.HandleFunc("GET /api/org/relationships", s.handleGetOrgRelationships)
	mux.HandleFunc("GET /api/attestations", s.handleGetAttestations)
	mux.HandleFunc("GET /api/attestations/{agent_id}", s.handleGetAgentAttestations)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	// Check if workspace has been bootstrapped by looking for a trust boundary entry.
	// This is true even before /api/join is called, preventing double-bootstrap.
	_, tbDomain, tbErr := s.conn.GetTrustBoundary()
	bootstrapped := tbErr == nil && tbDomain != ""

	entryCount, _ := s.conn.LogDB().EntryCount()
	status := map[string]any{
		"status":       "running",
		"bootstrapped": bootstrapped,
		"agent_key":    fmt.Sprintf("%x", s.conn.KeyPair().Public),
		"entry_count":  entryCount,
		"agent_count":  s.conn.Registry().Count(),
		"version":      s.version,
	}

	if s.conn.GossipNode() != nil {
		status["peer_count"] = len(s.conn.GossipNode().Tracker().Peers())
		status["peer_id"] = s.conn.GossipNode().Host().ID().String()
	}

	writeSuccess(w, r, status)
}

func (s *Server) handleChannels(w http.ResponseWriter, r *http.Request) {
	channels := s.conn.Channels().List(s.conn.KeyPair().Public)
	registry := s.conn.Registry()

	result := make([]map[string]any, 0, len(channels))
	for _, ch := range channels {
		// Resolve member public keys to display names
		members := make([]map[string]any, 0, len(ch.Members))
		for keyHex := range ch.Members {
			member := map[string]any{
				"public_key": keyHex,
				"is_admin":   ch.Admins[keyHex],
			}
			// Look up agent details from registry
			if agents := registry.All(); len(agents) > 0 {
				for _, a := range agents {
					if fmt.Sprintf("%x", a.PublicKey) == keyHex {
						member["display_name"] = a.DisplayName
						member["human_name"] = a.HumanName
						member["title"] = a.Title
						member["team"] = a.Team
						member["revoked"] = a.Revoked
						break
					}
				}
			}
			members = append(members, member)
		}

		// Collect admin keys
		adminKeys := make([]string, 0, len(ch.Admins))
		for keyHex := range ch.Admins {
			adminKeys = append(adminKeys, keyHex)
		}

		result = append(result, map[string]any{
			"id":           fmt.Sprintf("%x", ch.ID),
			"name":         ch.Name,
			"description":  ch.Description,
			"type":         ch.Type,
			"member_count": ch.MemberCount(),
			"archived":     ch.Archived,
			"members":      members,
			"admin_keys":   adminKeys,
		})
	}

	writeSuccess(w, r, result)
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	agents := s.conn.Registry().All()
	myKey := fmt.Sprintf("%x", s.conn.KeyPair().Public)

	result := make([]map[string]any, 0, len(agents))
	selfFound := false
	for _, a := range agents {
		keyHex := fmt.Sprintf("%x", a.PublicKey)
		if keyHex == myKey {
			selfFound = true
		}
		result = append(result, map[string]any{
			"public_key":       keyHex,
			"display_name":     a.DisplayName,
			"human_name":       a.HumanName,
			"platform":         a.Platform,
			"platform_user_id": a.PlatformUserID,
			"title":            a.Title,
			"team":             a.Team,
			"revoked":          a.Revoked,
		})
	}

	// Ensure our own agent is always included
	if !selfFound {
		result = append(result, map[string]any{
			"public_key":       myKey,
			"display_name":     "",
			"platform":         "",
			"platform_user_id": "",
			"title":            "",
			"team":             "",
			"revoked":          false,
		})
	}

	writeSuccess(w, r, result)
}

func (s *Server) handleAgentDetail(w http.ResponseWriter, r *http.Request) {
	idHex := r.PathValue("id")
	pubKey, err := hex.DecodeString(idHex)
	if err != nil || len(pubKey) != 32 {
		httpError(w, "invalid agent ID", 400)
		return
	}

	agent := s.conn.Registry().GetByPublicKey(pubKey)
	if agent == nil {
		httpError(w, "agent not found", 404)
		return
	}

	result := map[string]any{
		"public_key":       idHex,
		"display_name":     agent.DisplayName,
		"platform":         agent.Platform,
		"platform_user_id": agent.PlatformUserID,
		"title":            agent.Title,
		"team":             agent.Team,
		"revoked":          agent.Revoked,
	}

	// Org relationships
	managerRel := s.conn.OrgMap().GetManager(pubKey)
	if managerRel != nil {
		managerAgent := s.conn.Registry().GetByPublicKey(managerRel.ManagerPubKey)
		manager := map[string]any{
			"public_key": fmt.Sprintf("%x", managerRel.ManagerPubKey),
		}
		if managerAgent != nil {
			manager["display_name"] = managerAgent.DisplayName
		}
		result["manager"] = manager
	}

	reports := s.conn.OrgMap().GetDirectReports(pubKey)
	if len(reports) > 0 {
		directReports := make([]map[string]any, 0, len(reports))
		for _, rel := range reports {
			report := map[string]any{
				"public_key": fmt.Sprintf("%x", rel.SubjectPubKey),
			}
			reportAgent := s.conn.Registry().GetByPublicKey(rel.SubjectPubKey)
			if reportAgent != nil {
				report["display_name"] = reportAgent.DisplayName
			}
			directReports = append(directReports, report)
		}
		result["direct_reports"] = directReports
	}

	// Channel memberships
	channels := s.conn.Channels().List(pubKey)
	chList := make([]map[string]any, 0, len(channels))
	for _, ch := range channels {
		chList = append(chList, map[string]any{
			"id":   fmt.Sprintf("%x", ch.ID),
			"name": ch.Name,
			"type": ch.Type,
		})
	}
	result["channels"] = chList

	writeSuccess(w, r, result)
}

// --- Org Relationships (read-only) ---

func (s *Server) handleGetOrgRelationships(w http.ResponseWriter, r *http.Request) {
	agents := s.conn.Registry().All()
	orgMap := s.conn.OrgMap()

	relationships := make([]map[string]any, 0)
	for _, agent := range agents {
		rel := orgMap.GetManager(agent.PublicKey)
		if rel == nil {
			continue
		}
		managerAgent := s.conn.Registry().GetByPublicKey(rel.ManagerPubKey)
		entry := map[string]any{
			"subject_key":  fmt.Sprintf("%x", rel.SubjectPubKey),
			"manager_key":  fmt.Sprintf("%x", rel.ManagerPubKey),
			"subject_name": agent.DisplayName,
			"timestamp":    rel.Timestamp,
		}
		if managerAgent != nil {
			entry["manager_name"] = managerAgent.DisplayName
		}
		relationships = append(relationships, entry)
	}

	writeSuccess(w, r, relationships)
}

// --- Attestations (read-only) ---

func (s *Server) handleGetAttestations(w http.ResponseWriter, r *http.Request) {
	entries, err := s.conn.LogDB().EntriesByType(int(moltcbor.EntryTypeAttestation))
	if err != nil {
		httpError(w, err.Error(), 500)
		return
	}

	writeSuccess(w, r, s.decodeAttestationEntries(entries))
}

func (s *Server) handleGetAgentAttestations(w http.ResponseWriter, r *http.Request) {
	agentIDHex := r.PathValue("agent_id")
	agentKey, err := hex.DecodeString(agentIDHex)
	if err != nil {
		httpError(w, "invalid agent ID", 400)
		return
	}

	entries, err := s.conn.LogDB().EntriesByType(int(moltcbor.EntryTypeAttestation))
	if err != nil {
		httpError(w, err.Error(), 500)
		return
	}

	// Filter by author
	var filtered []*store.RawEntry
	for _, e := range entries {
		if hex.EncodeToString(e.AuthorKey) == hex.EncodeToString(agentKey) {
			filtered = append(filtered, e)
		}
	}

	writeSuccess(w, r, s.decodeAttestationEntries(filtered))
}

func (s *Server) decodeAttestationEntries(entries []*store.RawEntry) []map[string]any {
	result := make([]map[string]any, 0)
	for _, raw := range entries {
		payload := decodePayloadFromRaw(raw)
		if payload == nil {
			continue
		}
		var att moltcbor.Attestation
		if err := moltcbor.Unmarshal(payload, &att); err != nil {
			continue
		}

		authorName := ""
		agent := s.conn.Registry().GetByPublicKey(raw.AuthorKey)
		if agent != nil {
			authorName = agent.DisplayName
		}

		result = append(result, map[string]any{
			"author_key":       hex.EncodeToString(raw.AuthorKey),
			"author_name":      authorName,
			"platform":         att.Platform,
			"workspace_domain": att.WorkspaceDomain,
			"platform_user_id": att.PlatformUserID,
			"timestamp":        att.Timestamp,
		})
	}
	return result
}

// decodePayloadFromRaw extracts the inner payload from a raw log entry.
func decodePayloadFromRaw(raw *store.RawEntry) []byte {
	var sigData struct {
		Parents  [][]byte `cbor:"1,keyasint"`
		Envelope []byte   `cbor:"2,keyasint"`
		Time     int64    `cbor:"3,keyasint"`
	}
	if err := moltcbor.Unmarshal(raw.RawCBOR, &sigData); err != nil {
		return nil
	}

	var env moltcbor.Envelope
	if err := moltcbor.Unmarshal(sigData.Envelope, &env); err != nil {
		return nil
	}

	return env.Payload
}

func writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
