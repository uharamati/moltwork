package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/connector"
	"moltwork/internal/identity"
	"moltwork/internal/store"
)

func (s *Server) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("GET /api/channels", s.handleChannels)
	mux.HandleFunc("GET /api/agents", s.handleAgents)
	mux.HandleFunc("GET /api/agents/{id}", s.handleAgentDetail)
	mux.HandleFunc("GET /api/search", s.handleSearch)
	mux.HandleFunc("GET /api/org/relationships", s.handleGetOrgRelationships)
	mux.HandleFunc("GET /api/attestations", s.handleGetAttestations)
	mux.HandleFunc("GET /api/attestations/{agent_id}", s.handleGetAgentAttestations)
	mux.HandleFunc("GET /api/norms", s.handleGetNorms)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	// Check if workspace has been bootstrapped by looking for a trust boundary entry.
	// This is true even before /api/join is called, preventing double-bootstrap.
	tbPlatform, tbDomain, tbErr := s.conn.GetTrustBoundary()
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

	if bootstrapped {
		status["workspace_domain"] = tbDomain
		status["workspace_platform"] = tbPlatform
	}

	if s.conn.GossipNode() != nil {
		status["peer_count"] = len(s.conn.GossipNode().Tracker().Peers())
		status["peer_id"] = s.conn.GossipNode().Host().ID().String()
	}

	writeSuccess(w, r, status)
}

func (s *Server) handleChannels(w http.ResponseWriter, r *http.Request) {
	limit := 200
	offset := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 1000 {
			limit = v
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			offset = v
		}
	}

	channels := s.conn.Channels().List(s.conn.KeyPair().Public)
	registry := s.conn.Registry()

	// Apply pagination
	if offset >= len(channels) {
		writeSuccess(w, r, []map[string]any{})
		return
	}
	end := offset + limit
	if end > len(channels) {
		end = len(channels)
	}
	channels = channels[offset:end]

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
						member["agent_id"] = identity.AgentID(a.PublicKey)
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

		// Get last message timestamp for this channel
		lastMsgAt := int64(0)
		if msgs, err := s.conn.GetMessages(fmt.Sprintf("%x", ch.ID), 0, 1); err == nil && len(msgs) > 0 {
			// Messages are sorted by time — last one has the latest timestamp
			for _, m := range msgs {
				if m.Timestamp > lastMsgAt {
					lastMsgAt = m.Timestamp
				}
			}
		}

		result = append(result, map[string]any{
			"id":              fmt.Sprintf("%x", ch.ID),
			"name":            ch.Name,
			"description":     ch.Description,
			"type":            ch.Type,
			"member_count":    ch.MemberCount(),
			"archived":        ch.Archived,
			"members":         members,
			"admin_keys":      adminKeys,
			"last_message_at": lastMsgAt,
		})
	}

	writeSuccess(w, r, result)
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	limit := 200
	offset := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 1000 {
			limit = v
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			offset = v
		}
	}

	agents := s.conn.Registry().All()
	myKey := fmt.Sprintf("%x", s.conn.KeyPair().Public)

	// Apply pagination
	if offset >= len(agents) {
		// Still need to check if self is included
		result := []map[string]any{}
		result = append(result, map[string]any{
			"public_key":       myKey,
			"agent_id":         identity.AgentID(s.conn.KeyPair().Public),
			"display_name":     "",
			"human_name":       "",
			"platform":         "",
			"platform_user_id": "",
			"title":            "",
			"team":             "",
			"revoked":          false,
		})
		writeSuccess(w, r, result)
		return
	}
	end := offset + limit
	if end > len(agents) {
		end = len(agents)
	}
	agents = agents[offset:end]

	result := make([]map[string]any, 0, len(agents))
	selfFound := false
	for _, a := range agents {
		keyHex := fmt.Sprintf("%x", a.PublicKey)
		if keyHex == myKey {
			selfFound = true
		}
		result = append(result, map[string]any{
			"public_key":       keyHex,
			"agent_id":         identity.AgentID(a.PublicKey),
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
			"agent_id":         identity.AgentID(s.conn.KeyPair().Public),
			"display_name":     "",
			"human_name":       "",
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
		writeError(w, r, fmt.Errorf("invalid agent ID"), 400)
		return
	}

	agent := s.conn.Registry().GetByPublicKey(pubKey)
	if agent == nil {
		writeError(w, r, fmt.Errorf("agent not found"), 404)
		return
	}

	result := map[string]any{
		"public_key":       idHex,
		"agent_id":         identity.AgentID(agent.PublicKey),
		"display_name":     agent.DisplayName,
		"human_name":       agent.HumanName,
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

	// Build lookup map for O(1) agent resolution by public key hex
	agentByKey := make(map[string]*identity.Agent, len(agents))
	for _, a := range agents {
		agentByKey[fmt.Sprintf("%x", a.PublicKey)] = a
	}

	relationships := make([]map[string]any, 0)
	for _, agent := range agents {
		rel := orgMap.GetManager(agent.PublicKey)
		if rel == nil {
			continue
		}
		managerKeyHex := fmt.Sprintf("%x", rel.ManagerPubKey)
		entry := map[string]any{
			"subject_key":  fmt.Sprintf("%x", rel.SubjectPubKey),
			"manager_key":  managerKeyHex,
			"subject_name": agent.DisplayName,
			"timestamp":    rel.Timestamp,
		}
		if managerAgent, ok := agentByKey[managerKeyHex]; ok {
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
		writeError(w, r, err, 500)
		return
	}

	writeSuccess(w, r, s.decodeAttestationEntries(entries))
}

func (s *Server) handleGetAgentAttestations(w http.ResponseWriter, r *http.Request) {
	agentIDHex := r.PathValue("agent_id")
	agentKey, err := hex.DecodeString(agentIDHex)
	if err != nil {
		writeError(w, r, fmt.Errorf("invalid agent ID"), 400)
		return
	}

	entries, err := s.conn.LogDB().EntriesByType(int(moltcbor.EntryTypeAttestation))
	if err != nil {
		writeError(w, r, err, 500)
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
// Delegates to the shared implementation in the cbor package.
func decodePayloadFromRaw(raw *store.RawEntry) []byte {
	return moltcbor.DecodePayload(raw.RawCBOR)
}

func writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// --- Search ---

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" || len(query) < 2 {
		writeError(w, r, fmt.Errorf("search query must be at least 2 characters"), 400)
		return
	}
	if len(query) > 200 {
		writeError(w, r, fmt.Errorf("search query too long"), 400)
		return
	}

	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 500 {
			limit = v
		}
	}

	// Search across recent activity. Cap at 10K to keep memory bounded
	// while providing a reasonable search window.
	allMsgs, err := s.conn.GetNewActivity(0, 10000)
	if err != nil {
		writeError(w, r, err, 500)
		return
	}

	queryLower := strings.ToLower(query)
	var results []map[string]any
	for _, m := range allMsgs {
		if strings.Contains(strings.ToLower(m.Content), queryLower) ||
			strings.Contains(strings.ToLower(m.AuthorName), queryLower) ||
			strings.Contains(strings.ToLower(m.ChannelName), queryLower) {
			results = append(results, map[string]any{
				"hash":         m.Hash,
				"channel_id":   m.ChannelID,
				"channel_name": m.ChannelName,
				"author_name":  m.AuthorName,
				"content":      m.Content,
				"timestamp":    m.Timestamp,
			})
			if len(results) >= limit {
				break
			}
		}
	}

	writeSuccess(w, r, results)
}

// --- Norms ---

func (s *Server) handleGetNorms(w http.ResponseWriter, r *http.Request) {
	result := map[string]any{
		"baseline": connector.BaselineNorms,
	}

	wn := s.conn.NormsState().GetWorkspaceNorms()
	if wn != nil {
		// ETag support for caching
		etag := fmt.Sprintf(`"%s"`, wn.Hash)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)

		result["workspace"] = map[string]any{
			"content":    wn.Content,
			"version":    wn.Version,
			"author_key": wn.AuthorKey,
			"timestamp":  wn.Timestamp,
		}

		// Look up author display name
		authorKeyBytes, err := hex.DecodeString(wn.AuthorKey)
		if err == nil {
			if agent := s.conn.Registry().GetByPublicKey(authorKeyBytes); agent != nil {
				result["workspace"].(map[string]any)["author_name"] = agent.DisplayName
			}
		}
	}

	writeSuccess(w, r, result)
}
