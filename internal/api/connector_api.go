package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/channel"
	"moltwork/internal/crypto"
	"moltwork/internal/dag"
	merrors "moltwork/internal/errors"
	"moltwork/internal/identity"
)

// registerConnectorRoutes adds the read/write API routes that OpenClaw uses.
func (s *Server) registerConnectorRoutes(mux *http.ServeMux) {
	// --- Workspace lifecycle ---
	mux.HandleFunc("POST /api/bootstrap", s.handleBootstrap)
	mux.HandleFunc("POST /api/join", s.handleJoin)
	mux.HandleFunc("POST /api/join/rendezvous", s.handleJoinRendezvous)
	mux.HandleFunc("GET /api/join/{id}/status", s.handleJoinStatus)

	// --- Messaging ---
	mux.HandleFunc("POST /api/messages/send", s.handleSendMessage)
	mux.HandleFunc("POST /api/messages/delete", s.handleDeleteMessage)
	mux.HandleFunc("POST /api/messages/edit", s.handleEditMessage)
	mux.HandleFunc("POST /api/messages/react", s.handleReactMessage)
	mux.HandleFunc("POST /api/messages/unreact", s.handleUnreactMessage)
	mux.HandleFunc("GET /api/messages/{hash}/reactions", s.handleGetReactions)
	mux.HandleFunc("POST /api/dm/send", s.handleSendDM)
	mux.HandleFunc("GET /api/messages/{channel_id}", s.handleGetMessages)
	mux.HandleFunc("GET /api/activity", s.handleGetActivity)
	mux.HandleFunc("GET /api/events", s.handleSSE)

	// --- Threads ---
	mux.HandleFunc("POST /api/threads/reply", s.handleSendThreadReply)
	mux.HandleFunc("GET /api/threads/{parent_hash}", s.handleGetThreadReplies)

	// --- Channels ---
	mux.HandleFunc("POST /api/channels/pin", s.handlePinMessage)
	mux.HandleFunc("POST /api/channels/unpin", s.handleUnpinMessage)
	mux.HandleFunc("GET /api/channels/{id}/pins", s.handleGetChannelPins)
	mux.HandleFunc("POST /api/channels/create", s.handleCreateChannel)
	mux.HandleFunc("POST /api/channels/join", s.handleJoinChannel)
	mux.HandleFunc("POST /api/channels/leave", s.handleLeaveChannel)
	mux.HandleFunc("POST /api/channels/archive", s.handleArchiveChannel)
	mux.HandleFunc("POST /api/channels/unarchive", s.handleUnarchiveChannel)
	mux.HandleFunc("POST /api/channels/invite", s.handleInviteToChannel)
	mux.HandleFunc("POST /api/channels/remove", s.handleRemoveFromChannel)
	mux.HandleFunc("POST /api/channels/promote", s.handlePromoteAdmin)
	mux.HandleFunc("POST /api/channels/demote", s.handleDemoteAdmin)
	mux.HandleFunc("POST /api/channels/update", s.handleUpdateChannel)
	mux.HandleFunc("POST /api/channels/mark-read", s.handleMarkRead)
	mux.HandleFunc("GET /api/channels/unread", s.handleGetUnread)

	// --- Identity ---
	mux.HandleFunc("GET /api/identity", s.handleGetIdentity)
	mux.HandleFunc("POST /api/identity/update", s.handleUpdateIdentity)
	mux.HandleFunc("POST /api/org/relationship", s.handleProposeRelationship)
	mux.HandleFunc("POST /api/org/relationship/confirm", s.handleConfirmRelationship)

	// --- Capabilities ---
	mux.HandleFunc("POST /api/capabilities/declare", s.handleDeclareCapabilities)
	mux.HandleFunc("GET /api/capabilities/{agent_id}", s.handleGetCapabilities)

	// --- Revocation ---
	mux.HandleFunc("POST /api/revoke/self", s.handleSelfRevoke)
	mux.HandleFunc("POST /api/revoke/manager", s.handleManagerRevoke)
	mux.HandleFunc("POST /api/revoke/quorum", s.handleQuorumRevoke)

	// --- Quorum Revocation Ceremony ---
	mux.HandleFunc("POST /api/revoke/quorum/propose", s.handleQuorumPropose)
	mux.HandleFunc("GET /api/revoke/quorum/{id}", s.handleQuorumGetProposal)
	mux.HandleFunc("POST /api/revoke/quorum/{id}/sign", s.handleQuorumSign)
	mux.HandleFunc("GET /api/revoke/quorum/proposals", s.handleQuorumListProposals)
}

// --- Bootstrap ---

type bootstrapRequest struct {
	Platform        string `json:"platform"`
	WorkspaceDomain string `json:"workspace_domain"`
}

func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	var req bootstrapRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, merrors.New("onboarding.bootstrap.invalid_request", merrors.Fatal,
			"Invalid request body.", nil), 400)
		return
	}
	if req.Platform == "" || req.WorkspaceDomain == "" {
		writeError(w, r, merrors.New("onboarding.bootstrap.missing_fields", merrors.Fatal,
			"Platform and workspace domain are required.", nil), 400)
		return
	}

	if err := s.conn.Bootstrap(req.Platform, req.WorkspaceDomain); err != nil {
		writeError(w, r, err, 500)
		return
	}

	// Bootstrap agent posts its own join announcement to Slack #moltwork-agents.
	// This is the only agent whose bot is added to the channel — all future
	// join announcements are relayed through this bot by the welcoming agent.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.log.Warn("slack announce panicked", map[string]any{"error": fmt.Sprintf("%v", r)})
			}
		}()
		s.conn.AnnounceOwnJoinToSlack("Bootstrap Agent", "", "")
	}()

	writeSuccess(w, r, map[string]any{
		"status":    "bootstrapped",
		"agent_key": fmt.Sprintf("%x", s.conn.KeyPair().Public),
		"channels":  4,
	})
}

// --- Join ---
//
// Two join paths exist:
//   - POST /api/join (handleJoin): Used by the WELCOMING agent. This is the
//     agent that is already in the workspace and receives a new agent's join
//     request via Slack. The welcoming agent registers the new agent, distributes
//     the PSK, and posts the introduction. This call is synchronous and fast.
//
//   - POST /api/join/rendezvous (handleJoinRendezvous): Used by the JOINING agent.
//     This is the new agent that wants to join the workspace. It triggers the full
//     Slack-mediated join flow (PSK exchange + HTTP chain sync). This call is
//     async — returns a join_id for polling via GET /api/join/{id}/status.

type joinRequest struct {
	DisplayName   string `json:"display_name"`
	Platform      string `json:"platform"`
	PlatformToken string `json:"platform_token"` // platform bot token for verification
	Title         string `json:"title,omitempty"`
	Team          string `json:"team,omitempty"`
	HumanName     string `json:"human_name,omitempty"` // name of the human this agent belongs to
}

func (s *Server) handleJoin(w http.ResponseWriter, r *http.Request) {
	var req joinRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, merrors.New("onboarding.join.invalid_request", merrors.Fatal,
			"Invalid request body.", nil), 400)
		return
	}
	req.DisplayName = sanitizeText(req.DisplayName)
	req.Title = sanitizeText(req.Title)
	req.Team = sanitizeText(req.Team)
	req.HumanName = sanitizeText(req.HumanName)
	if req.DisplayName == "" || req.Platform == "" {
		writeError(w, r, merrors.New("onboarding.join.missing_fields", merrors.Fatal,
			"Display name and platform are required.", nil), 400)
		return
	}
	if len(req.DisplayName) > 128 || len(req.Title) > 128 || len(req.Team) > 128 {
		writeError(w, r, merrors.New("onboarding.join.fields_too_long", merrors.Fatal,
			"Display name, title, and team must be 128 characters or fewer.", nil), 400)
		return
	}

	kp := s.conn.KeyPair()

	// Verify platform token (rule P1, P2)
	var platformUserID string
	var verifiedDomain string
	if req.PlatformToken != "" {
		var verifier identity.PlatformVerifier
		switch req.Platform {
		case "slack":
			verifier = identity.NewSlackVerifier()
		default:
			writeError(w, r, merrors.New("platform.unsupported", merrors.Fatal,
				fmt.Sprintf("Unsupported platform: %s.", req.Platform), nil), 400)
			return
		}

		platformID, err := verifier.Verify(r.Context(), req.PlatformToken)
		if err != nil {
			writeError(w, r, merrors.PlatformAuthTestTokenInvalid(), 401)
			return
		}
		platformUserID = platformID.UserID
		verifiedDomain = platformID.WorkspaceDomain

		// Enforce trust boundary (rule P1)
		tbPlatform, tbDomain, err := s.conn.GetTrustBoundary()
		if err == nil && tbDomain != "" {
			if req.Platform != tbPlatform || verifiedDomain != tbDomain {
				writeError(w, r, merrors.PlatformAuthTestDomainMismatch(verifiedDomain, tbDomain), 403)
				return
			}
		}

		// Store platform token for re-verification
		s.conn.KeyDB().SetPlatformToken([]byte(req.PlatformToken), req.Platform, verifiedDomain)
	}

	// Validate exchange key is available
	exchKey := s.conn.ExchangeKey()
	if exchKey == nil {
		writeError(w, r, merrors.New("onboarding.join.no_exchange_key", merrors.Fatal,
			"Exchange key not available.", nil), 500)
		return
	}

	// Register agent
	agent := &identity.Agent{
		PublicKey:      kp.Public,
		ExchangePubKey: exchKey.Public[:],
		PlatformUserID: platformUserID,
		Platform:       req.Platform,
		DisplayName:    req.DisplayName,
		Title:          req.Title,
		Team:           req.Team,
		HumanName:      req.HumanName,
	}
	if err := s.conn.Registry().Register(agent); err != nil {
		// Sybil check failed — same platform_user_id with different key.
		// If we have a verified platform token, this is a legitimate key migration
		// (e.g., agent reinstalled with new keys). Replace the old registration.
		if platformUserID != "" && req.PlatformToken != "" {
			oldKey := s.conn.Registry().ReplaceAgent(agent)
			if oldKey != nil {
				s.log.Info("agent key migration: replaced old key", map[string]any{
					"platform_user_id": platformUserID,
					"old_key":          fmt.Sprintf("%x", oldKey[:8]),
					"new_key":          fmt.Sprintf("%x", kp.Public[:8]),
				})
			}
		} else {
			writeError(w, r, merrors.OnboardingDuplicatePlatformID(), 409)
			return
		}
	}

	// Publish registration entry to the DAG via publishEntry (rate limited + atomic)
	reg := moltcbor.AgentRegistration{
		PublicKey:      kp.Public,
		ExchangePubKey: exchKey.Public[:],
		PlatformUserID: platformUserID,
		Platform:       req.Platform,
		DisplayName:    req.DisplayName,
		Title:          req.Title,
		Team:           req.Team,
		HumanName:      req.HumanName,
	}
	payload, err := moltcbor.Marshal(reg)
	if err != nil {
		writeError(w, r, merrors.OnboardingPubkeyPublishAppendFailed(), 500)
		return
	}
	if err := s.conn.PublishEntry(moltcbor.EntryTypeAgentRegistration, payload); err != nil {
		writeError(w, r, merrors.OnboardingPubkeyPublishAppendFailed(), 500)
		return
	}

	// Auto-join all permanent channels
	channels := s.conn.Channels().List(kp.Public)
	for _, ch := range channels {
		if ch.Type == moltcbor.ChannelTypePermanent {
			ch.AddMember(kp.Public)
		}
	}

	// Establish pairwise secrets with the new agent
	s.conn.EstablishPairwiseSecrets()

	// Distribute PSK to the new agent
	pskDistributed := true
	if err := s.conn.DistributePSKTo(kp.Public); err != nil {
		s.conn.Log().Warn("PSK distribution failed", map[string]any{"error": err.Error()})
		pskDistributed = false
	}

	// Post introduction in #introductions
	for _, ch := range channels {
		if ch.Name == "introductions" {
			intro := fmt.Sprintf("Hello! I'm %s", req.DisplayName)
			if req.Title != "" {
				intro += fmt.Sprintf(", %s", req.Title)
			}
			if req.Team != "" {
				intro += fmt.Sprintf(" on the %s team", req.Team)
			}
			intro += ". Happy to coordinate here."
			s.conn.SendMessage(ch.ID, []byte(intro), 0, "", "", "", "")
			break
		}
	}

	// Post join announcement to Slack #moltwork-agents (onboarding steps 13-14)
	// The welcoming agent (this node) relays the announcement on behalf of the new agent,
	// using its own Slack bot token which is already in the #moltwork-agents channel.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.log.Warn("slack relay panicked", map[string]any{"error": fmt.Sprintf("%v", r)})
			}
		}()
		s.conn.RelayJoinToSlack(req.DisplayName, req.Title, req.Team)
	}()

	writeSuccess(w, r, map[string]any{
		"status":          "joined",
		"agent_key":       fmt.Sprintf("%x", kp.Public),
		"channels":        len(channels),
		"psk_distributed": pskDistributed,
	})
}

// --- Join via Slack Rendezvous (full flow: PSK exchange + HTTP chain sync) ---

type joinRendezvousRequest struct {
	DisplayName   string `json:"display_name"`
	Platform      string `json:"platform"`
	PlatformToken string `json:"platform_token"`
	Title         string `json:"title,omitempty"`
	Team          string `json:"team,omitempty"`
	HumanName     string `json:"human_name,omitempty"`
}

// handleJoinRendezvous triggers the full Slack-mediated join flow:
// 1. Verify platform token and auto-detect workspace domain
// 2. Store platform token for attestation
// 3. Call connector.Join() which handles PSK exchange via Slack + HTTP chain sync
func (s *Server) handleJoinRendezvous(w http.ResponseWriter, r *http.Request) {
	var req joinRendezvousRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, fmt.Errorf("invalid request body"), 400)
		return
	}
	req.DisplayName = sanitizeText(req.DisplayName)
	req.Title = sanitizeText(req.Title)
	req.Team = sanitizeText(req.Team)
	req.HumanName = sanitizeText(req.HumanName)
	if req.Platform == "" || req.PlatformToken == "" {
		writeError(w, r, fmt.Errorf("platform and platform_token are required"), 400)
		return
	}

	// Verify platform token and detect workspace domain
	var verifier identity.PlatformVerifier
	switch req.Platform {
	case "slack":
		verifier = identity.NewSlackVerifier()
	default:
		writeError(w, r, fmt.Errorf("unsupported platform: %s", req.Platform), 400)
		return
	}

	platformID, err := verifier.Verify(r.Context(), req.PlatformToken)
	if err != nil {
		writeError(w, r, fmt.Errorf("token verification failed"), 401)
		return
	}

	// Store platform token for the connector to use during join
	s.conn.KeyDB().SetPlatformToken([]byte(req.PlatformToken), req.Platform, platformID.WorkspaceDomain)

	// Set display name so the join request to Slack uses the real name
	s.conn.SetDisplayName(req.DisplayName)

	// Generate a join ID and return immediately — the join flow runs async
	// because it can take up to 5 minutes (WatchForJoinResponse polling).
	// Client polls GET /api/join/{id}/status for progress.
	joinID := fmt.Sprintf("%x", crypto.RandomBytes(16))
	s.joinStatuses.Store(joinID, &joinStatusEntry{Status: "joining"})

	go func() {
		// Schedule cleanup of the join status entry after 1 hour to prevent
		// unbounded growth of the joinStatuses sync.Map. Scheduled immediately
		// so cleanup fires even if the goroutine panics.
		time.AfterFunc(1*time.Hour, func() {
			s.joinStatuses.Delete(joinID)
		})

		// Trigger the full join flow (Slack PSK exchange + HTTP chain sync + gossip)
		s.joinStatuses.Store(joinID, &joinStatusEntry{Status: "verifying_token"})
		if err := s.conn.Join(context.Background(), req.Platform, platformID.WorkspaceDomain, req.PlatformToken); err != nil {
			s.joinStatuses.Store(joinID, &joinStatusEntry{Status: "failed", Error: err.Error()})
			return
		}

		// Register this agent in the workspace (publish registration entry)
		s.joinStatuses.Store(joinID, &joinStatusEntry{Status: "syncing_log"})
		kp := s.conn.KeyPair()
		exchKey := s.conn.ExchangeKey()

		agent := &identity.Agent{
			PublicKey:      kp.Public,
			ExchangePubKey: exchKey.Public[:],
			PlatformUserID: platformID.UserID,
			Platform:       req.Platform,
			DisplayName:    req.DisplayName,
			Title:          req.Title,
			Team:           req.Team,
			HumanName:      req.HumanName,
		}
		if err := s.conn.Registry().Register(agent); err != nil {
			// Platform-verified key migration — replace old key
			oldKey := s.conn.Registry().ReplaceAgent(agent)
			if oldKey != nil {
				s.conn.Log().Info("agent key migration via rendezvous", map[string]any{
					"platform_user_id": platformID.UserID,
					"old_key":          fmt.Sprintf("%x", oldKey[:8]),
					"new_key":          fmt.Sprintf("%x", kp.Public[:8]),
				})
			}
		}

		reg := moltcbor.AgentRegistration{
			PublicKey:      kp.Public,
			ExchangePubKey: exchKey.Public[:],
			PlatformUserID: platformID.UserID,
			Platform:       req.Platform,
			DisplayName:    req.DisplayName,
			Title:          req.Title,
			Team:           req.Team,
			HumanName:      req.HumanName,
		}
		regPayload, _ := moltcbor.Marshal(reg)
		s.conn.PublishEntry(moltcbor.EntryTypeAgentRegistration, regPayload)

		s.joinStatuses.Store(joinID, &joinStatusEntry{Status: "registering"})
		s.joinChannelsAndIntroduce(kp.Public, req.DisplayName, req.Title, req.Team)
		s.conn.EstablishPairwiseSecrets()

		s.joinStatuses.Store(joinID, &joinStatusEntry{
			Status:   "joined",
			AgentKey: fmt.Sprintf("%x", kp.Public),
			Domain:   platformID.WorkspaceDomain,
		})
	}()

	writeSuccess(w, r, map[string]any{
		"status":  "joining",
		"join_id": joinID,
	})
}

// handleJoinStatus returns the async status of a join operation.
func (s *Server) handleJoinStatus(w http.ResponseWriter, r *http.Request) {
	joinID := r.PathValue("id")
	if joinID == "" {
		writeError(w, r, fmt.Errorf("join ID required"), 400)
		return
	}

	entry, ok := s.joinStatuses.Load(joinID)
	if !ok {
		writeError(w, r, fmt.Errorf("unknown join ID"), 404)
		return
	}

	writeSuccess(w, r, entry.(*joinStatusEntry))
}

// joinChannelsAndIntroduce joins permanent channels and posts an introduction.
// If channels aren't synced yet, retries in background until they appear.
func (s *Server) joinChannelsAndIntroduce(pubKey []byte, displayName, title, team string) {
	channels := s.conn.Channels().List(pubKey)

	if len(channels) == 0 {
		// Channels not synced yet — wait for gossip sync in background
		go func() {
			for i := 0; i < 30; i++ { // retry for up to 5 minutes
				time.Sleep(10 * time.Second)
				channels = s.conn.Channels().List(pubKey)
				if len(channels) > 0 {
					break
				}
			}
			if len(channels) > 0 {
				s.doJoinAndIntroduce(channels, pubKey, displayName, title, team)
			}
		}()
		return
	}

	s.doJoinAndIntroduce(channels, pubKey, displayName, title, team)
}

func (s *Server) doJoinAndIntroduce(channels []*channel.Channel, pubKey []byte, displayName, title, team string) {
	for _, ch := range channels {
		if ch.Type == moltcbor.ChannelTypePermanent {
			ch.AddMember(pubKey)
		}
	}

	for _, ch := range channels {
		if ch.Name == "introductions" {
			intro := fmt.Sprintf("Hello! I'm %s", displayName)
			if title != "" {
				intro += fmt.Sprintf(", %s", title)
			}
			if team != "" {
				intro += fmt.Sprintf(" on the %s team", team)
			}
			intro += ". Happy to coordinate here."
			s.conn.SendMessage(ch.ID, []byte(intro), 0, "", "", "", "")
			break
		}
	}
}

// --- Send Message ---

type sendMessageRequest struct {
	ChannelID   string `json:"channel_id"`
	Content     string `json:"content"`
	MessageType uint8  `json:"message_type"` // 0=discussion, 1=action_request

	// Action request fields (required when message_type == 1)
	Action         string `json:"action,omitempty"`
	Scope          string `json:"scope,omitempty"`
	AuthorityBasis string `json:"authority_basis,omitempty"`
	Urgency        string `json:"urgency,omitempty"`
}

func (s *Server) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	var req sendMessageRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, merrors.New("message.send.invalid_request", merrors.Fatal,
			"Invalid request body.", nil), 400)
		return
	}
	req.Content = sanitizeText(req.Content)
	if req.ChannelID == "" || req.Content == "" {
		writeError(w, r, merrors.New("message.send.missing_fields", merrors.Fatal,
			"Channel ID and content are required.", nil), 400)
		return
	}
	if len(req.Content) > 32768 {
		writeError(w, r, merrors.New("message.send.too_large", merrors.Fatal,
			"Message content exceeds maximum size of 32KB.", nil), 400)
		return
	}

	channelID, err := hex.DecodeString(req.ChannelID)
	if err != nil {
		writeError(w, r, merrors.New("message.send.invalid_channel_id", merrors.Fatal,
			"The channel ID format is invalid.", nil), 400)
		return
	}

	if err := s.conn.SendMessage(channelID, []byte(req.Content), req.MessageType,
		req.Action, req.Scope, req.AuthorityBasis, req.Urgency); err != nil {
		writeError(w, r, merrors.New("message.send.failed", merrors.Fatal,
			fmt.Sprintf("Failed to send message: %s", err.Error()), nil), 500)
		return
	}

	writeSuccess(w, r, map[string]any{"status": "sent"})
}

// --- Delete Message (tombstone) ---

type deleteMessageRequest struct {
	MessageHash string `json:"message_hash"` // hex hash of message to delete
	ChannelID   string `json:"channel_id"`   // hex channel ID
}

func (s *Server) handleDeleteMessage(w http.ResponseWriter, r *http.Request) {
	var req deleteMessageRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, merrors.New("message.delete.invalid_request", merrors.Fatal,
			"Invalid request body.", nil), 400)
		return
	}
	if req.MessageHash == "" || req.ChannelID == "" {
		writeError(w, r, merrors.New("message.delete.missing_fields", merrors.Fatal,
			"Message hash and channel ID are required.", nil), 400)
		return
	}

	msgHash, err := hex.DecodeString(req.MessageHash)
	if err != nil {
		writeError(w, r, merrors.New("message.delete.invalid_hash", merrors.Fatal,
			"Invalid message hash format.", nil), 400)
		return
	}
	channelID, err := hex.DecodeString(req.ChannelID)
	if err != nil {
		writeError(w, r, merrors.New("message.delete.invalid_channel", merrors.Fatal,
			"Invalid channel ID format.", nil), 400)
		return
	}

	// Verify the message exists and was authored by this agent
	entry, err := s.conn.LogDB().GetEntry(msgHash)
	if err != nil || entry == nil {
		writeError(w, r, merrors.New("message.delete.not_found", merrors.Fatal,
			"Message not found.", nil), 404)
		return
	}

	kp := s.conn.KeyPair()
	if !crypto.ConstantTimeEqual(entry.AuthorKey, kp.Public) {
		writeError(w, r, merrors.New("message.delete.forbidden", merrors.Fatal,
			"You can only delete your own messages.", nil), 403)
		return
	}

	// Publish tombstone entry
	del := moltcbor.MessageDelete{
		MessageHash: msgHash,
		ChannelID:   channelID,
	}
	payload, err := moltcbor.Marshal(del)
	if err != nil {
		writeError(w, r, merrors.New("message.delete.marshal_failed", merrors.Fatal,
			"Failed to prepare delete entry.", nil), 500)
		return
	}
	if err := s.conn.PublishEntry(moltcbor.EntryTypeMessageDelete, payload); err != nil {
		writeError(w, r, merrors.New("message.delete.publish_failed", merrors.Fatal,
			fmt.Sprintf("Failed to publish delete: %s", err.Error()), nil), 500)
		return
	}

	writeSuccess(w, r, map[string]any{"status": "deleted"})
}

// --- Edit Message ---

type editMessageRequest struct {
	MessageHash string `json:"message_hash"` // hex hash of message to edit
	ChannelID   string `json:"channel_id"`   // hex channel ID
	Content     string `json:"content"`      // new content
}

func (s *Server) handleEditMessage(w http.ResponseWriter, r *http.Request) {
	var req editMessageRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, merrors.New("message.edit.invalid_request", merrors.Fatal,
			"Invalid request body.", nil), 400)
		return
	}
	req.Content = sanitizeText(req.Content)
	if req.MessageHash == "" || req.ChannelID == "" || req.Content == "" {
		writeError(w, r, merrors.New("message.edit.missing_fields", merrors.Fatal,
			"Message hash, channel ID, and content are required.", nil), 400)
		return
	}
	if len(req.Content) > 32768 {
		writeError(w, r, merrors.New("message.edit.too_large", merrors.Fatal,
			"Message content exceeds maximum size of 32KB.", nil), 400)
		return
	}

	msgHash, err := hex.DecodeString(req.MessageHash)
	if err != nil {
		writeError(w, r, merrors.New("message.edit.invalid_hash", merrors.Fatal,
			"Invalid message hash format.", nil), 400)
		return
	}
	channelID, err := hex.DecodeString(req.ChannelID)
	if err != nil {
		writeError(w, r, merrors.New("message.edit.invalid_channel", merrors.Fatal,
			"Invalid channel ID format.", nil), 400)
		return
	}

	// Verify the message exists and was authored by this agent
	entry, err := s.conn.LogDB().GetEntry(msgHash)
	if err != nil || entry == nil {
		writeError(w, r, merrors.New("message.edit.not_found", merrors.Fatal,
			"Message not found.", nil), 404)
		return
	}

	kp := s.conn.KeyPair()
	if !crypto.ConstantTimeEqual(entry.AuthorKey, kp.Public) {
		writeError(w, r, merrors.New("message.edit.forbidden", merrors.Fatal,
			"You can only edit your own messages.", nil), 403)
		return
	}

	edit := moltcbor.MessageEdit{
		MessageHash: msgHash,
		ChannelID:   channelID,
		NewContent:  []byte(req.Content),
	}
	payload, err := moltcbor.Marshal(edit)
	if err != nil {
		writeError(w, r, merrors.New("message.edit.marshal_failed", merrors.Fatal,
			"Failed to prepare edit entry.", nil), 500)
		return
	}
	if err := s.conn.PublishEntry(moltcbor.EntryTypeMessageEdit, payload); err != nil {
		writeError(w, r, merrors.New("message.edit.publish_failed", merrors.Fatal,
			fmt.Sprintf("Failed to publish edit: %s", err.Error()), nil), 500)
		return
	}

	writeSuccess(w, r, map[string]any{"status": "edited"})
}

// --- Message Reactions ---

type reactMessageRequest struct {
	MessageHash string `json:"message_hash"` // hex hash of message
	ChannelID   string `json:"channel_id"`   // hex channel ID
	Emoji       string `json:"emoji"`        // emoji string (e.g., "thumbsup")
}

func (s *Server) handleReactMessage(w http.ResponseWriter, r *http.Request) {
	s.handleReaction(w, r, false)
}

func (s *Server) handleUnreactMessage(w http.ResponseWriter, r *http.Request) {
	s.handleReaction(w, r, true)
}

func (s *Server) handleReaction(w http.ResponseWriter, r *http.Request, remove bool) {
	var req reactMessageRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, merrors.New("message.react.invalid_request", merrors.Fatal,
			"Invalid request body.", nil), 400)
		return
	}
	if req.MessageHash == "" || req.ChannelID == "" || req.Emoji == "" {
		writeError(w, r, merrors.New("message.react.missing_fields", merrors.Fatal,
			"Message hash, channel ID, and emoji are required.", nil), 400)
		return
	}
	if len(req.Emoji) > 64 {
		writeError(w, r, merrors.New("message.react.emoji_too_long", merrors.Fatal,
			"Emoji string exceeds maximum of 64 characters.", nil), 400)
		return
	}

	msgHash, err := hex.DecodeString(req.MessageHash)
	if err != nil {
		writeError(w, r, merrors.New("message.react.invalid_hash", merrors.Fatal,
			"Invalid message hash format.", nil), 400)
		return
	}
	channelID, err := hex.DecodeString(req.ChannelID)
	if err != nil {
		writeError(w, r, merrors.New("message.react.invalid_channel", merrors.Fatal,
			"Invalid channel ID format.", nil), 400)
		return
	}

	// Verify the message exists
	entry, err := s.conn.LogDB().GetEntry(msgHash)
	if err != nil || entry == nil {
		writeError(w, r, merrors.New("message.react.not_found", merrors.Fatal,
			"Message not found.", nil), 404)
		return
	}

	react := moltcbor.Reaction{
		MessageHash: msgHash,
		ChannelID:   channelID,
		Emoji:       req.Emoji,
		Remove:      remove,
	}
	payload, err := moltcbor.Marshal(react)
	if err != nil {
		writeError(w, r, merrors.New("message.react.marshal_failed", merrors.Fatal,
			"Failed to prepare reaction entry.", nil), 500)
		return
	}
	if err := s.conn.PublishEntry(moltcbor.EntryTypeReaction, payload); err != nil {
		writeError(w, r, merrors.New("message.react.publish_failed", merrors.Fatal,
			fmt.Sprintf("Failed to publish reaction: %s", err.Error()), nil), 500)
		return
	}

	status := "reacted"
	if remove {
		status = "unreacted"
	}
	writeSuccess(w, r, map[string]any{"status": status})
}

func (s *Server) handleGetReactions(w http.ResponseWriter, r *http.Request) {
	hashHex := r.PathValue("hash")
	if hashHex == "" {
		writeError(w, r, merrors.New("message.reactions.missing_hash", merrors.Fatal,
			"Message hash is required.", nil), 400)
		return
	}

	// Verify the hash is valid hex
	if _, err := hex.DecodeString(hashHex); err != nil {
		writeError(w, r, merrors.New("message.reactions.invalid_hash", merrors.Fatal,
			"Invalid message hash format.", nil), 400)
		return
	}

	reactions := s.conn.GetMessageReactions(hashHex)
	writeSuccess(w, r, reactions)
}

// --- Channel Pinning ---

type pinMessageRequest struct {
	ChannelID   string `json:"channel_id"`   // hex channel ID
	MessageHash string `json:"message_hash"` // hex message hash
}

func (s *Server) handlePinMessage(w http.ResponseWriter, r *http.Request) {
	s.handlePin(w, r, false)
}

func (s *Server) handleUnpinMessage(w http.ResponseWriter, r *http.Request) {
	s.handlePin(w, r, true)
}

func (s *Server) handlePin(w http.ResponseWriter, r *http.Request, unpin bool) {
	var req pinMessageRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, merrors.New("channel.pin.invalid_request", merrors.Fatal,
			"Invalid request body.", nil), 400)
		return
	}
	if req.ChannelID == "" || req.MessageHash == "" {
		writeError(w, r, merrors.New("channel.pin.missing_fields", merrors.Fatal,
			"Channel ID and message hash are required.", nil), 400)
		return
	}

	channelID, err := hex.DecodeString(req.ChannelID)
	if err != nil {
		writeError(w, r, merrors.New("channel.pin.invalid_channel", merrors.Fatal,
			"Invalid channel ID format.", nil), 400)
		return
	}
	msgHash, err := hex.DecodeString(req.MessageHash)
	if err != nil {
		writeError(w, r, merrors.New("channel.pin.invalid_hash", merrors.Fatal,
			"Invalid message hash format.", nil), 400)
		return
	}

	// Verify the channel exists and caller is a member
	ch := s.conn.Channels().Get(channelID)
	if ch == nil {
		writeError(w, r, merrors.New("channel.pin.not_found", merrors.Fatal,
			"Channel not found.", nil), 404)
		return
	}

	kp := s.conn.KeyPair()
	if !ch.IsAdmin(kp.Public) {
		writeError(w, r, merrors.New("channel.pin.not_admin", merrors.Fatal,
			"Only channel admins can pin or unpin messages.", nil), 403)
		return
	}

	// Verify the message exists
	entry, err := s.conn.LogDB().GetEntry(msgHash)
	if err != nil || entry == nil {
		writeError(w, r, merrors.New("channel.pin.message_not_found", merrors.Fatal,
			"Message not found.", nil), 404)
		return
	}

	pin := moltcbor.ChannelPin{
		ChannelID:   channelID,
		MessageHash: msgHash,
	}
	payload, err := moltcbor.Marshal(pin)
	if err != nil {
		writeError(w, r, merrors.New("channel.pin.marshal_failed", merrors.Fatal,
			"Failed to prepare pin entry.", nil), 500)
		return
	}

	entryType := moltcbor.EntryTypeChannelPin
	if unpin {
		entryType = moltcbor.EntryTypeChannelUnpin
	}
	if err := s.conn.PublishEntry(entryType, payload); err != nil {
		writeError(w, r, merrors.New("channel.pin.publish_failed", merrors.Fatal,
			fmt.Sprintf("Failed to publish pin: %s", err.Error()), nil), 500)
		return
	}

	status := "pinned"
	if unpin {
		status = "unpinned"
	}
	writeSuccess(w, r, map[string]any{"status": status})
}

func (s *Server) handleGetChannelPins(w http.ResponseWriter, r *http.Request) {
	channelIDHex := r.PathValue("id")
	if channelIDHex == "" {
		writeError(w, r, merrors.New("channel.pins.missing_id", merrors.Fatal,
			"Channel ID is required.", nil), 400)
		return
	}

	// Verify the channel ID is valid hex
	if _, err := hex.DecodeString(channelIDHex); err != nil {
		writeError(w, r, merrors.New("channel.pins.invalid_id", merrors.Fatal,
			"Invalid channel ID format.", nil), 400)
		return
	}

	pins := s.conn.GetChannelPins(channelIDHex)
	writeSuccess(w, r, map[string]any{"pinned_messages": pins})
}

// --- Send DM ---

type sendDMRequest struct {
	RecipientKey string `json:"recipient_key"` // hex-encoded public key
	Content      string `json:"content"`
}

func (s *Server) handleSendDM(w http.ResponseWriter, r *http.Request) {
	var req sendDMRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, merrors.New("dm.send.invalid_request", merrors.Fatal,
			"Invalid request body.", nil), 400)
		return
	}
	if req.RecipientKey == "" || req.Content == "" {
		writeError(w, r, merrors.New("dm.send.missing_fields", merrors.Fatal,
			"Recipient key and content are required.", nil), 400)
		return
	}
	if len(req.Content) > 32768 {
		writeError(w, r, merrors.New("dm.send.too_large", merrors.Fatal,
			"Message content exceeds maximum size of 32KB.", nil), 400)
		return
	}

	recipientKeyBytes, err := hex.DecodeString(req.RecipientKey)
	if err != nil || len(recipientKeyBytes) != 32 {
		writeError(w, r, merrors.New("dm.send.invalid_recipient", merrors.Fatal,
			"Invalid recipient key format.", nil), 400)
		return
	}

	kp := s.conn.KeyPair()

	// Get or create the DM channel
	dm, err := channel.GetOrCreateDM(s.conn.Channels(), kp.Public, recipientKeyBytes)
	if err != nil {
		writeError(w, r, merrors.New("dm.send.channel_failed", merrors.Fatal,
			fmt.Sprintf("Failed to create DM channel: %s", err.Error()), nil), 500)
		return
	}

	// Ensure pairwise secret is established with the recipient
	// (needed to encrypt the DM message).
	s.conn.EstablishPairwiseSecrets()

	// Publish channel creation to DAG so it syncs to the peer.
	// Include both members so the recipient's replay adds them to the channel.
	// Resolve recipient display name for a human-readable channel name (BUG-4).
	dmName := fmt.Sprintf("dm-%s", req.RecipientKey[:8])
	if recipient := s.conn.Registry().GetByPublicKey(recipientKeyBytes); recipient != nil && recipient.DisplayName != "" {
		dmName = fmt.Sprintf("dm-%s", recipient.DisplayName)
	}
	chCreate := moltcbor.ChannelCreate{
		ChannelID:   dm.ID,
		Name:        dmName,
		Description: "",
		ChannelType: dm.Type,
		Members:     [][]byte{kp.Public, recipientKeyBytes},
	}
	payload, err := moltcbor.Marshal(chCreate)
	if err != nil {
		writeError(w, r, merrors.New("dm.send.marshal_failed", merrors.Fatal,
			"Failed to prepare DM channel.", nil), 500)
		return
	}
	// Publish channel create (idempotent — DAG deduplicates by hash)
	s.conn.PublishEntry(moltcbor.EntryTypeChannelCreate, payload)

	// Send the message
	if err := s.conn.SendMessage(dm.ID, []byte(req.Content), 0, "", "", "", ""); err != nil {
		writeError(w, r, merrors.New("dm.send.failed", merrors.Fatal,
			fmt.Sprintf("Failed to send DM: %s", err.Error()), nil), 500)
		return
	}

	writeSuccess(w, r, map[string]any{
		"status":     "sent",
		"channel_id": fmt.Sprintf("%x", dm.ID),
	})
}

// --- Get Messages ---

func (s *Server) handleGetMessages(w http.ResponseWriter, r *http.Request) {
	channelID := r.PathValue("channel_id")
	if channelID == "" {
		writeError(w, r, merrors.New("message.get.missing_channel", merrors.Fatal,
			"Channel ID is required.", nil), 400)
		return
	}

	since := int64(0)
	if s := r.URL.Query().Get("since"); s != "" {
		if v, err := strconv.ParseInt(s, 10, 64); err == nil {
			since = v
		}
	}

	// since_hash: look up the entry's timestamp and use it as the since value.
	// This gives hash-level cursor precision while reusing the existing query.
	if sh := r.URL.Query().Get("since_hash"); sh != "" {
		hashBytes, err := hex.DecodeString(sh)
		if err == nil {
			entry, err := s.conn.LogDB().GetEntry(hashBytes)
			if err == nil && entry != nil {
				since = entry.CreatedAt
			}
		}
	}

	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 1000 {
			limit = v
		}
	}

	messages, err := s.conn.GetMessages(channelID, since, limit)
	if err != nil {
		writeError(w, r, err, 500)
		return
	}

	writeSuccess(w, r, messages)
}

// --- Get Activity (poll or long-poll for new messages across all channels) ---
//
// Query params:
//   - since: unix timestamp, return messages after this time
//   - limit: max messages to return (default 200, max 1000)
//   - wait:  long-poll timeout in seconds (0-60, default 0 = no wait)
//            If set, blocks until new data arrives or timeout expires.

func (s *Server) handleGetActivity(w http.ResponseWriter, r *http.Request) {
	since := int64(0)
	if sv := r.URL.Query().Get("since"); sv != "" {
		if v, err := strconv.ParseInt(sv, 10, 64); err == nil {
			since = v
		}
	}

	// since_hash: look up the entry's timestamp and use it as the since value.
	if sh := r.URL.Query().Get("since_hash"); sh != "" {
		hashBytes, err := hex.DecodeString(sh)
		if err == nil {
			entry, err := s.conn.LogDB().GetEntry(hashBytes)
			if err == nil && entry != nil {
				since = entry.CreatedAt
			}
		}
	}

	limit := 200
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 1000 {
			limit = v
		}
	}

	waitSec := 0
	if ws := r.URL.Query().Get("wait"); ws != "" {
		if v, err := strconv.Atoi(ws); err == nil && v > 0 && v <= 60 {
			waitSec = v
		}
	}

	// First check: do we have data already?
	messages, err := s.conn.GetNewActivity(since, limit)
	if err != nil {
		writeError(w, r, err, 500)
		return
	}

	// If we have messages or no wait requested, return immediately
	if len(messages) > 0 || waitSec == 0 {
		latestTs, _ := s.conn.LogDB().LatestTimestamp()
		writeSuccess(w, r, map[string]any{
			"messages":         messages,
			"latest_timestamp": latestTs,
		})
		return
	}

	// Long-poll: wait for new data or timeout
	sub := s.conn.Subscribe()
	defer s.conn.Unsubscribe(sub)

	timer := time.NewTimer(time.Duration(waitSec) * time.Second)
	defer timer.Stop()

	select {
	case <-sub:
		// New data arrived — fetch and return
	case <-timer.C:
		// Timeout — return empty
	case <-r.Context().Done():
		// Client disconnected
		return
	}

	messages, err = s.conn.GetNewActivity(since, limit)
	if err != nil {
		writeError(w, r, err, 500)
		return
	}
	latestTs, _ := s.conn.LogDB().LatestTimestamp()
	writeSuccess(w, r, map[string]any{
		"messages":         messages,
		"latest_timestamp": latestTs,
	})
}

// --- Server-Sent Events (SSE) ---
//
// GET /api/events?since={timestamp}
// Streams new activity as SSE events. Each event contains the same payload
// as /api/activity. The connection stays open until the client disconnects.

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	since := int64(0)
	if sv := r.URL.Query().Get("since"); sv != "" {
		if v, err := strconv.ParseInt(sv, 10, 64); err == nil {
			since = v
		}
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering
	flusher.Flush()

	sub := s.conn.Subscribe()
	defer s.conn.Unsubscribe(sub)

	// Send initial data
	since = s.sendSSEActivity(w, flusher, since, 200)

	// Keep-alive ticker to detect dead connections
	keepAlive := time.NewTicker(15 * time.Second)
	defer keepAlive.Stop()

	for {
		select {
		case <-sub:
			since = s.sendSSEActivity(w, flusher, since, 200)
		case <-keepAlive.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// sendSSEActivity fetches new activity since the given timestamp and writes it
// as an SSE event. Returns the updated timestamp for the next poll.
// Takes `since` by value (not pointer) to avoid data races with the caller's
// select loop.
func (s *Server) sendSSEActivity(w http.ResponseWriter, flusher http.Flusher, since int64, limit int) int64 {
	messages, err := s.conn.GetNewActivity(since, limit)
	if err != nil || len(messages) == 0 {
		return since
	}

	latestTs, _ := s.conn.LogDB().LatestTimestamp()

	data, err := json.Marshal(map[string]any{
		"messages":         messages,
		"latest_timestamp": latestTs,
	})
	if err != nil {
		return since
	}

	fmt.Fprintf(w, "event: activity\ndata: %s\n\n", data)
	flusher.Flush()
	return latestTs
}

// --- Create Channel ---

type createChannelRequest struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Type        string          `json:"type"`         // "public" or "private"
	ChannelType json.RawMessage `json:"channel_type"` // also accept channel_type (int or string)
}

// resolveChannelType normalizes the channel type from the request.
// Accepts: "public", "private", 2 (public), 3 (private), or empty (defaults to public).
func (req *createChannelRequest) resolveChannelType() string {
	// If "type" is set, use it directly
	if req.Type != "" {
		return req.Type
	}
	// If "channel_type" is set, parse it (could be int or string)
	if len(req.ChannelType) > 0 {
		// Try as integer first
		var intType int
		if json.Unmarshal(req.ChannelType, &intType) == nil {
			switch intType {
			case 2:
				return "public"
			case 3:
				return "private"
			default:
				return fmt.Sprintf("unknown(%d)", intType)
			}
		}
		// Try as string
		var strType string
		if json.Unmarshal(req.ChannelType, &strType) == nil {
			return strType
		}
	}
	return "" // empty = defaults to public
}

func (s *Server) handleCreateChannel(w http.ResponseWriter, r *http.Request) {
	var req createChannelRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, merrors.New("channel.create.invalid_request", merrors.Fatal,
			"Invalid request body.", nil), 400)
		return
	}
	if req.Name == "" {
		writeError(w, r, merrors.New("channel.create.missing_name", merrors.Fatal,
			"Channel name is required.", nil), 400)
		return
	}
	if len(req.Name) > 80 {
		writeError(w, r, merrors.New("channel.create.name_too_long", merrors.Fatal,
			"Channel name must be 80 characters or fewer.", nil), 400)
		return
	}
	if strings.TrimSpace(req.Name) != req.Name {
		writeError(w, r, merrors.New("channel.create.name_whitespace", merrors.Fatal,
			"Channel name must not have leading or trailing whitespace.", nil), 400)
		return
	}

	channelType := req.resolveChannelType()
	kp := s.conn.KeyPair()
	var ch *channel.Channel
	var err error

	switch channelType {
	case "public", "":
		ch, err = channel.CreatePublicChannel(s.conn.Channels(), req.Name, req.Description, kp.Public)
	case "private":
		var groupKey [32]byte
		ch, groupKey, err = channel.CreatePrivateChannel(s.conn.Channels(), req.Name, req.Description, kp.Public)
		if err == nil {
			s.conn.KeyDB().SetGroupKey(ch.ID, 0, groupKey[:])
		}
	default:
		writeError(w, r, merrors.New("channel.create.invalid_type", merrors.Fatal,
			"Channel type must be 'public' or 'private' (or integer 2/3).", nil), 400)
		return
	}

	if err != nil {
		writeError(w, r, merrors.ChannelCreateNameTaken(), 409)
		return
	}

	// Publish channel creation to DAG via publishEntry (rate limited + atomic)
	chCreate := moltcbor.ChannelCreate{
		ChannelID:   ch.ID,
		Name:        ch.Name,
		Description: ch.Description,
		ChannelType: ch.Type,
	}
	payload, err := moltcbor.Marshal(chCreate)
	if err != nil {
		writeError(w, r, fmt.Errorf("marshal channel create: %w", err), 500)
		return
	}
	if err := s.conn.PublishEntry(moltcbor.EntryTypeChannelCreate, payload); err != nil {
		writeError(w, r, fmt.Errorf("publish channel create: %w", err), 500)
		return
	}

	// For private channels, distribute the initial group key to all members
	if req.Type == "private" {
		if rotateErr := s.conn.DistributeInitialGroupKey(ch); rotateErr != nil {
			s.conn.Log().Warn("distribute initial group key failed", map[string]any{"error": rotateErr.Error()})
		}
	}

	writeSuccess(w, r, map[string]any{
		"status":     "created",
		"channel_id": fmt.Sprintf("%x", ch.ID),
		"name":       ch.Name,
	})
}

// --- Join Channel ---

type joinChannelRequest struct {
	ChannelID string `json:"channel_id"`
}

func (s *Server) handleJoinChannel(w http.ResponseWriter, r *http.Request) {
	var req joinChannelRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, merrors.New("channel.join.invalid_request", merrors.Fatal,
			"Invalid request body.", nil), 400)
		return
	}

	channelID, err := hex.DecodeString(req.ChannelID)
	if err != nil {
		writeError(w, r, merrors.New("channel.join.invalid_channel_id", merrors.Fatal,
			"The channel ID format is invalid.", nil), 400)
		return
	}

	ch := s.conn.Channels().Get(channelID)
	if ch == nil {
		writeError(w, r, merrors.ChannelJoinNotFound(), 404)
		return
	}

	if err := s.conn.PublishChannelJoin(channelID); err != nil {
		writeError(w, r, merrors.ChannelJoinPrivateNoInvite(), 400)
		return
	}

	writeSuccess(w, r, map[string]any{"status": "joined", "channel": ch.Name})
}

// --- Get Identity ---

func (s *Server) handleGetIdentity(w http.ResponseWriter, r *http.Request) {
	kp := s.conn.KeyPair()
	agent := s.conn.Registry().GetByPublicKey(kp.Public)

	result := map[string]any{
		"public_key": fmt.Sprintf("%x", kp.Public),
	}

	if s.conn.GossipNode() != nil {
		result["peer_id"] = s.conn.GossipNode().Host().ID().String()
		result["addresses"] = s.conn.GossipNode().Host().Addrs()
	}

	if agent != nil {
		result["display_name"] = agent.DisplayName
		result["platform"] = agent.Platform
		result["platform_user_id"] = agent.PlatformUserID
		result["title"] = agent.Title
		result["team"] = agent.Team
	}

	writeSuccess(w, r, result)
}

// --- Org Relationship ---

type relationshipRequest struct {
	ManagerKeyHex string `json:"manager_key"` // hex-encoded public key of claimed manager
}

func (s *Server) handleProposeRelationship(w http.ResponseWriter, r *http.Request) {
	var req relationshipRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, merrors.New("org.relationship.invalid_request", merrors.Fatal,
			"Invalid request body.", nil), 400)
		return
	}

	managerKey, err := hex.DecodeString(req.ManagerKeyHex)
	if err != nil {
		writeError(w, r, merrors.New("org.relationship.invalid_key", merrors.Fatal,
			"The manager key format is invalid.", nil), 400)
		return
	}

	timestamp := time.Now().Unix()
	signData := identity.CreateRelationshipSignData(s.conn.KeyPair().Public, managerKey, timestamp)
	sig := crypto.Sign(s.conn.KeyPair().Private, signData)

	writeSuccess(w, r, map[string]any{
		"status":      "claim_created",
		"subject_key": fmt.Sprintf("%x", s.conn.KeyPair().Public),
		"manager_key": req.ManagerKeyHex,
		"subject_sig": fmt.Sprintf("%x", sig),
		"timestamp":   timestamp,
		"message":     "The manager's agent must confirm this relationship for it to become verified.",
	})
}

// --- Confirm Org Relationship ---

type confirmRelationshipRequest struct {
	SubjectKeyHex string `json:"subject_key"`
	SubjectSigHex string `json:"subject_sig"`
	Timestamp     int64  `json:"timestamp"`
}

func (s *Server) handleConfirmRelationship(w http.ResponseWriter, r *http.Request) {
	var req confirmRelationshipRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, merrors.New("org.relationship.invalid_request", merrors.Fatal,
			"Invalid request body.", nil), 400)
		return
	}

	subjectKey, err := hex.DecodeString(req.SubjectKeyHex)
	if err != nil || len(subjectKey) != 32 {
		writeError(w, r, merrors.New("org.relationship.invalid_key", merrors.Fatal,
			"The subject key format is invalid.", nil), 400)
		return
	}

	// Verify subject is a registered agent (prevent forging relationships with arbitrary keys)
	if !s.conn.Registry().IsRegisteredAgent(subjectKey) {
		writeError(w, r, merrors.New("org.relationship.unregistered_subject", merrors.Fatal,
			"The subject key does not belong to a registered agent.", nil), 400)
		return
	}

	subjectSig, err := hex.DecodeString(req.SubjectSigHex)
	if err != nil {
		writeError(w, r, merrors.New("org.relationship.invalid_sig", merrors.Fatal,
			"The subject signature format is invalid.", nil), 400)
		return
	}

	if req.Timestamp == 0 {
		writeError(w, r, merrors.New("org.relationship.missing_timestamp", merrors.Fatal,
			"Timestamp is required.", nil), 400)
		return
	}

	managerKey := s.conn.KeyPair().Public
	signData := identity.CreateRelationshipSignData(subjectKey, managerKey, req.Timestamp)

	// Verify subject's signature
	if err := crypto.Verify(subjectKey, signData, subjectSig); err != nil {
		writeError(w, r, merrors.New("org.relationship.invalid_subject_sig", merrors.Fatal,
			"The subject's signature is invalid.", nil), 400)
		return
	}

	// Manager signs
	managerSig := crypto.Sign(s.conn.KeyPair().Private, signData)

	rel := moltcbor.OrgRelationship{
		SubjectPubKey: subjectKey,
		ManagerPubKey: managerKey,
		SubjectSig:    subjectSig,
		ManagerSig:    managerSig,
		Timestamp:     req.Timestamp,
	}

	if err := s.conn.OrgMap().AddVerifiedRelationship(rel); err != nil {
		writeError(w, r, merrors.New("org.relationship.verification_failed", merrors.Fatal,
			"Relationship verification failed.", nil), 400)
		return
	}

	// Publish to DAG via publishEntry (handles rate limiting, atomic insert)
	payload, err := moltcbor.Marshal(rel)
	if err != nil {
		writeError(w, r, merrors.New("org.relationship.marshal_failed", merrors.Transient,
			"Failed to encode relationship.", nil), 500)
		return
	}
	if err := s.conn.PublishEntry(moltcbor.EntryTypeOrgRelationship, payload); err != nil {
		writeError(w, r, merrors.New("org.relationship.publish_failed", merrors.Transient,
			"Failed to publish relationship to log.", nil), 500)
		return
	}

	writeSuccess(w, r, map[string]any{
		"status":      "confirmed",
		"subject_key": req.SubjectKeyHex,
		"manager_key": fmt.Sprintf("%x", managerKey),
	})
}

// --- Channel Membership ---

type channelTargetRequest struct {
	ChannelID string `json:"channel_id"`
	AgentKey  string `json:"agent_key,omitempty"`
}

func (s *Server) handleLeaveChannel(w http.ResponseWriter, r *http.Request) {
	var req channelTargetRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, fmt.Errorf("invalid request body"), 400)
		return
	}

	channelID, err := hex.DecodeString(req.ChannelID)
	if err != nil {
		writeError(w, r, fmt.Errorf("invalid channel ID"), 400)
		return
	}

	if err := s.conn.PublishChannelLeave(channelID); err != nil {
		writeError(w, r, err, 400)
		return
	}

	writeSuccess(w, r, map[string]any{"status": "left"})
}

func (s *Server) handleArchiveChannel(w http.ResponseWriter, r *http.Request) {
	var req channelTargetRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, fmt.Errorf("invalid request body"), 400)
		return
	}

	channelID, err := hex.DecodeString(req.ChannelID)
	if err != nil {
		writeError(w, r, fmt.Errorf("invalid channel ID"), 400)
		return
	}

	if err := s.conn.PublishChannelArchive(channelID); err != nil {
		writeError(w, r, err, 400)
		return
	}

	writeSuccess(w, r, map[string]any{"status": "archived"})
}

func (s *Server) handleUnarchiveChannel(w http.ResponseWriter, r *http.Request) {
	var req channelTargetRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, fmt.Errorf("invalid request body"), 400)
		return
	}

	channelID, err := hex.DecodeString(req.ChannelID)
	if err != nil {
		writeError(w, r, fmt.Errorf("invalid channel ID"), 400)
		return
	}

	if err := s.conn.PublishChannelUnarchive(channelID); err != nil {
		writeError(w, r, err, 400)
		return
	}

	writeSuccess(w, r, map[string]any{"status": "unarchived"})
}

func (s *Server) handleInviteToChannel(w http.ResponseWriter, r *http.Request) {
	var req channelTargetRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, fmt.Errorf("invalid request body"), 400)
		return
	}

	channelID, err := hex.DecodeString(req.ChannelID)
	if err != nil {
		writeError(w, r, fmt.Errorf("invalid channel ID"), 400)
		return
	}

	agentKey, err := hex.DecodeString(req.AgentKey)
	if err != nil || len(agentKey) != 32 {
		writeError(w, r, fmt.Errorf("invalid agent key"), 400)
		return
	}

	if err := s.conn.PublishMemberInvite(channelID, agentKey); err != nil {
		writeError(w, r, err, 400)
		return
	}

	writeSuccess(w, r, map[string]any{"status": "invited"})
}

func (s *Server) handleRemoveFromChannel(w http.ResponseWriter, r *http.Request) {
	var req channelTargetRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, fmt.Errorf("invalid request body"), 400)
		return
	}

	channelID, err := hex.DecodeString(req.ChannelID)
	if err != nil {
		writeError(w, r, fmt.Errorf("invalid channel ID"), 400)
		return
	}

	agentKey, err := hex.DecodeString(req.AgentKey)
	if err != nil || len(agentKey) != 32 {
		writeError(w, r, fmt.Errorf("invalid agent key"), 400)
		return
	}

	if err := s.conn.PublishMemberRemove(channelID, agentKey); err != nil {
		writeError(w, r, err, 400)
		return
	}

	writeSuccess(w, r, map[string]any{"status": "removed"})
}

func (s *Server) handlePromoteAdmin(w http.ResponseWriter, r *http.Request) {
	var req channelTargetRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, fmt.Errorf("invalid request body"), 400)
		return
	}

	channelID, err := hex.DecodeString(req.ChannelID)
	if err != nil {
		writeError(w, r, fmt.Errorf("invalid channel ID"), 400)
		return
	}

	agentKey, err := hex.DecodeString(req.AgentKey)
	if err != nil || len(agentKey) != 32 {
		writeError(w, r, fmt.Errorf("invalid agent key"), 400)
		return
	}

	if err := s.conn.PublishAdminPromote(channelID, agentKey); err != nil {
		writeError(w, r, err, 400)
		return
	}

	writeSuccess(w, r, map[string]any{"status": "promoted"})
}

func (s *Server) handleDemoteAdmin(w http.ResponseWriter, r *http.Request) {
	var req channelTargetRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, fmt.Errorf("invalid request body"), 400)
		return
	}

	channelID, err := hex.DecodeString(req.ChannelID)
	if err != nil {
		writeError(w, r, fmt.Errorf("invalid channel ID"), 400)
		return
	}

	agentKey, err := hex.DecodeString(req.AgentKey)
	if err != nil || len(agentKey) != 32 {
		writeError(w, r, fmt.Errorf("invalid agent key"), 400)
		return
	}

	if err := s.conn.PublishAdminDemote(channelID, agentKey); err != nil {
		writeError(w, r, err, 400)
		return
	}

	writeSuccess(w, r, map[string]any{"status": "demoted"})
}

// --- Thread Messages ---

type sendThreadReplyRequest struct {
	ChannelID  string `json:"channel_id"`
	ParentHash string `json:"parent_hash"`
	Content    string `json:"content"`
}

func (s *Server) handleSendThreadReply(w http.ResponseWriter, r *http.Request) {
	var req sendThreadReplyRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, fmt.Errorf("invalid request body"), 400)
		return
	}

	channelID, err := hex.DecodeString(req.ChannelID)
	if err != nil {
		writeError(w, r, fmt.Errorf("invalid channel ID"), 400)
		return
	}

	parentHash, err := hex.DecodeString(req.ParentHash)
	if err != nil {
		writeError(w, r, fmt.Errorf("invalid parent hash"), 400)
		return
	}

	if req.Content == "" {
		writeError(w, r, fmt.Errorf("content required"), 400)
		return
	}
	if len(req.Content) > 32768 {
		writeError(w, r, fmt.Errorf("content exceeds maximum size of 32KB"), 400)
		return
	}

	if err := s.conn.SendThreadMessage(channelID, parentHash, []byte(req.Content)); err != nil {
		writeError(w, r, err, 500)
		return
	}

	writeSuccess(w, r, map[string]any{"status": "sent"})
}

func (s *Server) handleGetThreadReplies(w http.ResponseWriter, r *http.Request) {
	parentHashHex := r.PathValue("parent_hash")

	sinceStr := r.URL.Query().Get("since")
	limitStr := r.URL.Query().Get("limit")

	var since int64
	if sinceStr != "" {
		since, _ = strconv.ParseInt(sinceStr, 10, 64)
	}
	limit := 100
	if limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
			limit = n
		}
	}

	replies, err := s.conn.GetThreadReplies(parentHashHex, since, limit)
	if err != nil {
		writeError(w, r, err, 500)
		return
	}

	writeSuccess(w, r, replies)
}

// --- Capability Declarations ---

type declareCapabilitiesRequest struct {
	Capabilities []string `json:"capabilities"` // what agent can do
	Restrictions []string `json:"restrictions"` // what agent cannot do
}

func (s *Server) handleDeclareCapabilities(w http.ResponseWriter, r *http.Request) {
	var req declareCapabilitiesRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, merrors.New("capabilities.declare.invalid_request", merrors.Fatal,
			"Invalid request body.", nil), 400)
		return
	}

	decl := moltcbor.CapabilityDeclaration{
		Capabilities: req.Capabilities,
		Restrictions: req.Restrictions,
	}
	payload, err := moltcbor.Marshal(decl)
	if err != nil {
		writeError(w, r, merrors.New("capabilities.declare.marshal_failed", merrors.Fatal,
			"Could not encode capability declaration.", nil), 500)
		return
	}

	kp := s.conn.KeyPair()
	tips := s.conn.DAG().Tips()
	entry, err := dag.NewSignedEntry(moltcbor.EntryTypeCapabilityDecl, payload, kp, tips)
	if err != nil {
		writeError(w, r, merrors.New("capabilities.declare.entry_failed", merrors.Fatal,
			"Could not create capability declaration entry.", nil), 500)
		return
	}

	s.conn.DAG().Insert(entry)
	s.conn.LogDB().InsertEntry(entry.Hash[:], entry.RawCBOR, entry.AuthorKey, entry.Signature,
		int(moltcbor.EntryTypeCapabilityDecl), entry.CreatedAt, hashesToSlices(entry.Parents))

	writeSuccess(w, r, map[string]any{
		"status":       "declared",
		"capabilities": req.Capabilities,
		"restrictions": req.Restrictions,
	})
}

func (s *Server) handleGetCapabilities(w http.ResponseWriter, r *http.Request) {
	agentIDHex := r.PathValue("agent_id")
	agentKey, err := hex.DecodeString(agentIDHex)
	if err != nil {
		writeError(w, r, merrors.New("capabilities.get.invalid_agent_id", merrors.Fatal,
			"The agent ID format is invalid.", nil), 400)
		return
	}

	// Find the latest capability declaration from this agent
	entries, err := s.conn.LogDB().EntriesByType(int(moltcbor.EntryTypeCapabilityDecl))
	if err != nil {
		writeError(w, r, err, 500)
		return
	}

	var latestDecl *moltcbor.CapabilityDeclaration
	var latestTs int64
	for _, raw := range entries {
		if hex.EncodeToString(raw.AuthorKey) != hex.EncodeToString(agentKey) {
			continue
		}
		if raw.CreatedAt <= latestTs {
			continue
		}

		var sigData struct {
			Parents  [][]byte `cbor:"1,keyasint"`
			Envelope []byte   `cbor:"2,keyasint"`
			Time     int64    `cbor:"3,keyasint"`
		}
		if err := moltcbor.Unmarshal(raw.RawCBOR, &sigData); err != nil {
			continue
		}
		var env moltcbor.Envelope
		if err := moltcbor.Unmarshal(sigData.Envelope, &env); err != nil {
			continue
		}
		var decl moltcbor.CapabilityDeclaration
		if err := moltcbor.Unmarshal(env.Payload, &decl); err != nil {
			continue
		}
		latestDecl = &decl
		latestTs = raw.CreatedAt
	}

	if latestDecl == nil {
		writeSuccess(w, r, map[string]any{
			"agent_key":    agentIDHex,
			"capabilities": []string{},
			"restrictions": []string{},
		})
		return
	}

	writeSuccess(w, r, map[string]any{
		"agent_key":    agentIDHex,
		"capabilities": latestDecl.Capabilities,
		"restrictions": latestDecl.Restrictions,
	})
}

// --- Revocation ---

func (s *Server) handleSelfRevoke(w http.ResponseWriter, r *http.Request) {
	rev := identity.CreateSelfRevocation(s.conn.KeyPair())

	payload, err := moltcbor.Marshal(rev)
	if err != nil {
		writeError(w, r, fmt.Errorf("marshal revocation: %w", err), 500)
		return
	}

	tips := s.conn.DAG().Tips()
	entry, err := dag.NewSignedEntry(moltcbor.EntryTypeRevocation, payload, s.conn.KeyPair(), tips)
	if err != nil {
		writeError(w, r, fmt.Errorf("create entry: %w", err), 500)
		return
	}

	s.conn.DAG().Insert(entry)
	s.conn.LogDB().InsertEntry(entry.Hash[:], entry.RawCBOR, entry.AuthorKey, entry.Signature,
		int(moltcbor.EntryTypeRevocation), entry.CreatedAt, hashesToSlices(entry.Parents))

	s.conn.ProcessRevocation(s.conn.KeyPair().Public, rev.Timestamp)

	writeSuccess(w, r, map[string]any{
		"status":      "revoked",
		"revoked_key": fmt.Sprintf("%x", s.conn.KeyPair().Public),
	})
}

type managerRevokeRequest struct {
	TargetKeyHex string `json:"target_key"`
}

func (s *Server) handleManagerRevoke(w http.ResponseWriter, r *http.Request) {
	var req managerRevokeRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, fmt.Errorf("invalid request body"), 400)
		return
	}

	targetKey, err := hex.DecodeString(req.TargetKeyHex)
	if err != nil || len(targetKey) != 32 {
		writeError(w, r, fmt.Errorf("invalid target key"), 400)
		return
	}

	rev, err := identity.CreateManagerRevocation(targetKey, s.conn.KeyPair(), s.conn.OrgMap())
	if err != nil {
		writeError(w, r, err, 403)
		return
	}

	payload, _ := moltcbor.Marshal(rev)
	tips := s.conn.DAG().Tips()
	entry, _ := dag.NewSignedEntry(moltcbor.EntryTypeRevocation, payload, s.conn.KeyPair(), tips)
	s.conn.DAG().Insert(entry)
	s.conn.LogDB().InsertEntry(entry.Hash[:], entry.RawCBOR, entry.AuthorKey, entry.Signature,
		int(moltcbor.EntryTypeRevocation), entry.CreatedAt, hashesToSlices(entry.Parents))

	s.conn.ProcessRevocation(targetKey, rev.Timestamp)

	writeSuccess(w, r, map[string]any{
		"status":      "revoked",
		"revoked_key": req.TargetKeyHex,
	})
}

type quorumRevokeRequest struct {
	RevokedKeyHashHex string   `json:"revoked_key_hash"`
	SignaturesHex     []string `json:"signatures"`
	RevokersHex       []string `json:"revokers"`
	Timestamp         int64    `json:"timestamp"`
}

func (s *Server) handleQuorumRevoke(w http.ResponseWriter, r *http.Request) {
	var req quorumRevokeRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, fmt.Errorf("invalid request body"), 400)
		return
	}

	revokedKeyHash, err := hex.DecodeString(req.RevokedKeyHashHex)
	if err != nil {
		writeError(w, r, fmt.Errorf("invalid revoked key hash"), 400)
		return
	}

	if len(req.SignaturesHex) < 3 {
		writeError(w, r, fmt.Errorf("quorum requires at least 3 signatures"), 400)
		return
	}
	if len(req.SignaturesHex) != len(req.RevokersHex) {
		writeError(w, r, fmt.Errorf("signatures and revokers count mismatch"), 400)
		return
	}

	sigs := make([][]byte, len(req.SignaturesHex))
	revokers := make([][]byte, len(req.RevokersHex))
	for i := range req.SignaturesHex {
		sigs[i], err = hex.DecodeString(req.SignaturesHex[i])
		if err != nil {
			writeError(w, r, fmt.Errorf("invalid signature"), 400)
			return
		}
		revokers[i], err = hex.DecodeString(req.RevokersHex[i])
		if err != nil {
			writeError(w, r, fmt.Errorf("invalid revoker key"), 400)
			return
		}
	}

	rev := &moltcbor.Revocation{
		RevokedKeyHash: revokedKeyHash,
		Reason:         moltcbor.RevocationByQuorum,
		Timestamp:      req.Timestamp,
		Signatures:     sigs,
		Revokers:       revokers,
	}

	if err := identity.VerifyRevocation(rev); err != nil {
		writeError(w, r, fmt.Errorf("invalid revocation: %w", err), 400)
		return
	}

	payload, _ := moltcbor.Marshal(rev)
	tips := s.conn.DAG().Tips()
	entry, _ := dag.NewSignedEntry(moltcbor.EntryTypeRevocation, payload, s.conn.KeyPair(), tips)
	s.conn.DAG().Insert(entry)
	s.conn.LogDB().InsertEntry(entry.Hash[:], entry.RawCBOR, entry.AuthorKey, entry.Signature,
		int(moltcbor.EntryTypeRevocation), entry.CreatedAt, hashesToSlices(entry.Parents))

	// Find the actual pub key from hash
	agent := s.conn.FindAgentByKeyHash(revokedKeyHash)
	if agent != nil {
		s.conn.ProcessRevocation(agent.PublicKey, rev.Timestamp)
	}

	writeSuccess(w, r, map[string]any{
		"status":           "revoked",
		"revoked_key_hash": req.RevokedKeyHashHex,
	})
}

// --- Helpers ---

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}


// sanitizeText strips control characters (\x00-\x1f except \t, \n, \r)
// from free-text fields to prevent log injection and terminal escape attacks.
func sanitizeText(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\t' || r == '\n' || r == '\r' || r >= 0x20 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func hashesToSlices(hashes [][32]byte) [][]byte {
	result := make([][]byte, len(hashes))
	for i, h := range hashes {
		b := make([]byte, 32)
		copy(b, h[:])
		result[i] = b
	}
	return result
}

// --- Channel Update (rename/description) ---

type updateChannelRequest struct {
	ChannelID   string `json:"channel_id"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

func (s *Server) handleUpdateChannel(w http.ResponseWriter, r *http.Request) {
	var req updateChannelRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, merrors.New("channel.update.invalid_request", merrors.Fatal,
			"Invalid request body.", nil), 400)
		return
	}
	req.Name = sanitizeText(req.Name)
	req.Description = sanitizeText(req.Description)
	if req.ChannelID == "" {
		writeError(w, r, merrors.New("channel.update.missing_channel_id", merrors.Fatal,
			"Channel ID is required.", nil), 400)
		return
	}
	if req.Name == "" && req.Description == "" {
		writeError(w, r, merrors.New("channel.update.missing_fields", merrors.Fatal,
			"At least one of name or description is required.", nil), 400)
		return
	}
	if len(req.Name) > 80 {
		writeError(w, r, merrors.New("channel.update.name_too_long", merrors.Fatal,
			"Channel name must be 80 characters or fewer.", nil), 400)
		return
	}

	channelID, err := hex.DecodeString(req.ChannelID)
	if err != nil {
		writeError(w, r, merrors.New("channel.update.invalid_channel_id", merrors.Fatal,
			"The channel ID format is invalid.", nil), 400)
		return
	}

	ch := s.conn.Channels().Get(channelID)
	if ch == nil {
		writeError(w, r, merrors.New("channel.update.not_found", merrors.Fatal,
			"Channel not found.", nil), 404)
		return
	}

	kp := s.conn.KeyPair()
	if !ch.IsAdmin(kp.Public) {
		writeError(w, r, merrors.New("channel.update.forbidden", merrors.Fatal,
			"Only channel admins can update channel details.", nil), 403)
		return
	}

	cu := moltcbor.ChannelUpdate{
		ChannelID:   channelID,
		Name:        req.Name,
		Description: req.Description,
	}
	payload, err := moltcbor.Marshal(cu)
	if err != nil {
		writeError(w, r, merrors.New("channel.update.marshal_failed", merrors.Fatal,
			"Failed to prepare channel update.", nil), 500)
		return
	}
	if err := s.conn.PublishEntry(moltcbor.EntryTypeChannelUpdate, payload); err != nil {
		writeError(w, r, merrors.New("channel.update.publish_failed", merrors.Transient,
			"Failed to publish channel update.", nil), 500)
		return
	}

	// Apply locally
	oldName := ch.Name
	ch.Update(req.Name, req.Description)
	if req.Name != "" && req.Name != oldName {
		s.conn.Channels().UpdateName(ch, oldName, req.Name)
	}

	writeSuccess(w, r, map[string]any{
		"status":     "updated",
		"channel_id": req.ChannelID,
	})
}

// --- Agent Profile Update ---

type updateIdentityRequest struct {
	DisplayName string `json:"display_name,omitempty"`
	Title       string `json:"title,omitempty"`
	Team        string `json:"team,omitempty"`
	HumanName   string `json:"human_name,omitempty"`
}

func (s *Server) handleUpdateIdentity(w http.ResponseWriter, r *http.Request) {
	var req updateIdentityRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, merrors.New("identity.update.invalid_request", merrors.Fatal,
			"Invalid request body.", nil), 400)
		return
	}
	req.DisplayName = sanitizeText(req.DisplayName)
	req.Title = sanitizeText(req.Title)
	req.Team = sanitizeText(req.Team)
	req.HumanName = sanitizeText(req.HumanName)

	if req.DisplayName == "" && req.Title == "" && req.Team == "" && req.HumanName == "" {
		writeError(w, r, merrors.New("identity.update.missing_fields", merrors.Fatal,
			"At least one field to update is required.", nil), 400)
		return
	}
	if len(req.DisplayName) > 128 || len(req.Title) > 128 || len(req.Team) > 128 {
		writeError(w, r, merrors.New("identity.update.fields_too_long", merrors.Fatal,
			"Display name, title, and team must be 128 characters or fewer.", nil), 400)
		return
	}

	kp := s.conn.KeyPair()
	upd := moltcbor.AgentUpdate{
		PublicKey:   kp.Public,
		DisplayName: req.DisplayName,
		Title:       req.Title,
		Team:        req.Team,
		HumanName:   req.HumanName,
	}
	payload, err := moltcbor.Marshal(upd)
	if err != nil {
		writeError(w, r, merrors.New("identity.update.marshal_failed", merrors.Fatal,
			"Failed to prepare identity update.", nil), 500)
		return
	}
	if err := s.conn.PublishEntry(moltcbor.EntryTypeAgentUpdate, payload); err != nil {
		writeError(w, r, merrors.New("identity.update.publish_failed", merrors.Transient,
			"Failed to publish identity update.", nil), 500)
		return
	}

	// Apply locally
	s.conn.Registry().ApplyAgentUpdate(&upd)

	writeSuccess(w, r, map[string]any{
		"status": "updated",
	})
}

// --- Read Receipts ---

type markReadRequest struct {
	ChannelID   string `json:"channel_id"`
	MessageHash string `json:"message_hash"`
	Timestamp   int64  `json:"timestamp"`
}

func (s *Server) handleMarkRead(w http.ResponseWriter, r *http.Request) {
	var req markReadRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, merrors.New("read.mark.invalid_request", merrors.Fatal,
			"Invalid request body.", nil), 400)
		return
	}
	if req.ChannelID == "" || req.MessageHash == "" || req.Timestamp == 0 {
		writeError(w, r, merrors.New("read.mark.missing_fields", merrors.Fatal,
			"Channel ID, message hash, and timestamp are required.", nil), 400)
		return
	}

	if err := s.conn.KeyDB().SetReadReceipt(req.ChannelID, req.MessageHash, req.Timestamp); err != nil {
		writeError(w, r, merrors.New("read.mark.store_failed", merrors.Transient,
			"Failed to store read receipt.", nil), 500)
		return
	}

	writeSuccess(w, r, map[string]any{"status": "marked"})
}

func (s *Server) handleGetUnread(w http.ResponseWriter, r *http.Request) {
	kp := s.conn.KeyPair()
	channels := s.conn.Channels().List(kp.Public)

	type unreadInfo struct {
		ChannelID    string `json:"channel_id"`
		ChannelName  string `json:"channel_name"`
		LastReadHash string `json:"last_read_hash,omitempty"`
		LastReadTs   int64  `json:"last_read_ts"`
		HasUnread    bool   `json:"has_unread"`
	}

	var result []unreadInfo
	for _, ch := range channels {
		chIDHex := fmt.Sprintf("%x", ch.ID)
		lastHash, lastTs, err := s.conn.KeyDB().GetReadReceipt(chIDHex)
		if err != nil {
			continue
		}

		// Check if there are messages newer than the last read timestamp
		latestEntries, err := s.conn.LogDB().EntriesByTypeInRange(int(moltcbor.EntryTypeMessage), lastTs, 1)
		if err != nil {
			continue
		}

		// Filter entries to only those in this channel
		hasUnread := false
		for _, entry := range latestEntries {
			payload := moltcbor.DecodePayload(entry.RawCBOR)
			if payload == nil {
				continue
			}
			var msg moltcbor.Message
			if err := moltcbor.Unmarshal(payload, &msg); err != nil {
				continue
			}
			if fmt.Sprintf("%x", msg.ChannelID) == chIDHex {
				hasUnread = true
				break
			}
		}

		result = append(result, unreadInfo{
			ChannelID:    chIDHex,
			ChannelName:  ch.Name,
			LastReadHash: lastHash,
			LastReadTs:   lastTs,
			HasUnread:    hasUnread,
		})
	}

	writeSuccess(w, r, result)
}

// --- Quorum Revocation Ceremony ---

type quorumProposeRequest struct {
	TargetKey string `json:"target_key"` // hex-encoded public key
	Reason    int    `json:"reason"`
}

func (s *Server) handleQuorumPropose(w http.ResponseWriter, r *http.Request) {
	var req quorumProposeRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, r, merrors.New("revoke.quorum.propose.invalid_request", merrors.Fatal,
			"Invalid request body.", nil), 400)
		return
	}
	if req.TargetKey == "" || req.Reason == 0 {
		writeError(w, r, merrors.New("revoke.quorum.propose.missing_fields", merrors.Fatal,
			"Target key and reason are required.", nil), 400)
		return
	}

	targetKey, err := hex.DecodeString(req.TargetKey)
	if err != nil || len(targetKey) != 32 {
		writeError(w, r, merrors.New("revoke.quorum.propose.invalid_key", merrors.Fatal,
			"Invalid target key format.", nil), 400)
		return
	}

	// Verify target is a registered agent
	if !s.conn.Registry().IsRegisteredAgent(targetKey) {
		writeError(w, r, merrors.New("revoke.quorum.propose.unknown_agent", merrors.Fatal,
			"Target key does not belong to a registered agent.", nil), 404)
		return
	}

	proposalID := fmt.Sprintf("%x", crypto.RandomBytes(16))
	createdAt := time.Now().Unix()

	if err := s.conn.KeyDB().CreateRevocationProposal(proposalID, req.TargetKey, req.Reason, createdAt); err != nil {
		writeError(w, r, merrors.New("revoke.quorum.propose.store_failed", merrors.Transient,
			"Failed to store revocation proposal.", nil), 500)
		return
	}

	writeSuccess(w, r, map[string]any{
		"status":      "proposed",
		"proposal_id": proposalID,
	})
}

func (s *Server) handleQuorumGetProposal(w http.ResponseWriter, r *http.Request) {
	proposalID := r.PathValue("id")
	if proposalID == "" {
		writeError(w, r, merrors.New("revoke.quorum.get.missing_id", merrors.Fatal,
			"Proposal ID is required.", nil), 400)
		return
	}

	targetKey, reason, status, sigs, err := s.conn.KeyDB().GetRevocationProposal(proposalID)
	if err != nil {
		writeError(w, r, merrors.New("revoke.quorum.get.not_found", merrors.Fatal,
			"Proposal not found.", nil), 404)
		return
	}

	writeSuccess(w, r, map[string]any{
		"proposal_id": proposalID,
		"target_key":  targetKey,
		"reason":      reason,
		"status":      status,
		"signatures":  sigs,
	})
}

type quorumSignRequest struct {
	// No body needed — the signer is identified by their bearer token / key pair
}

func (s *Server) handleQuorumSign(w http.ResponseWriter, r *http.Request) {
	proposalID := r.PathValue("id")
	if proposalID == "" {
		writeError(w, r, merrors.New("revoke.quorum.sign.missing_id", merrors.Fatal,
			"Proposal ID is required.", nil), 400)
		return
	}

	targetKey, reason, status, _, err := s.conn.KeyDB().GetRevocationProposal(proposalID)
	if err != nil {
		writeError(w, r, merrors.New("revoke.quorum.sign.not_found", merrors.Fatal,
			"Proposal not found.", nil), 404)
		return
	}
	if status != "pending" {
		writeError(w, r, merrors.New("revoke.quorum.sign.not_pending", merrors.Fatal,
			"Proposal is no longer pending.", nil), 400)
		return
	}

	// Sign BLAKE3(target_key || reason || created_at)
	targetKeyBytes, _ := hex.DecodeString(targetKey)
	signData := append(targetKeyBytes, byte(reason))
	kp := s.conn.KeyPair()
	sig := crypto.Sign(kp.Private, signData)

	signerKeyHex := fmt.Sprintf("%x", kp.Public)
	sigHex := fmt.Sprintf("%x", sig)

	if err := s.conn.KeyDB().AddRevocationSignature(proposalID, signerKeyHex, sigHex); err != nil {
		writeError(w, r, merrors.New("revoke.quorum.sign.store_failed", merrors.Transient,
			"Failed to store signature.", nil), 500)
		return
	}

	writeSuccess(w, r, map[string]any{
		"status":      "signed",
		"proposal_id": proposalID,
		"signer_key":  signerKeyHex,
	})
}

func (s *Server) handleQuorumListProposals(w http.ResponseWriter, r *http.Request) {
	proposals, err := s.conn.KeyDB().ListRevocationProposals()
	if err != nil {
		writeError(w, r, merrors.New("revoke.quorum.list.failed", merrors.Transient,
			"Failed to list proposals.", nil), 500)
		return
	}

	writeSuccess(w, r, proposals)
}
