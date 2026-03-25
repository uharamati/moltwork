package api

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"moltwork/internal/crypto"
	"moltwork/internal/logging"
)

// syncSession tracks a PSK-authenticated sync session.
type syncSession struct {
	token   string
	expires time.Time
}

// syncSessionStore manages short-lived session tokens issued after PSK auth.
type syncSessionStore struct {
	mu       sync.Mutex
	sessions map[string]syncSession
}

func newSyncSessionStore() *syncSessionStore {
	return &syncSessionStore{
		sessions: make(map[string]syncSession),
	}
}

func (s *syncSessionStore) create(ttl time.Duration) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Clean expired sessions
	now := time.Now()
	for k, v := range s.sessions {
		if now.After(v.expires) {
			delete(s.sessions, k)
		}
	}

	token := hex.EncodeToString(crypto.RandomBytes(32))
	s.sessions[token] = syncSession{
		token:   token,
		expires: now.Add(ttl),
	}
	return token
}

func (s *syncSessionStore) validate(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[token]
	if !ok {
		return false
	}
	if time.Now().After(sess.expires) {
		delete(s.sessions, token)
		return false
	}
	return true
}

// registerSyncRoutes adds the PSK-authenticated sync endpoints.
// These are exempt from bearer token auth (handled in middleware.go).
func (s *Server) registerSyncRoutes(mux *http.ServeMux) {
	if s.syncSessions == nil {
		s.syncSessions = newSyncSessionStore()
	}
	mux.HandleFunc("POST /api/sync/challenge", s.handleSyncChallenge)
	mux.HandleFunc("POST /api/sync/pull", s.handleSyncPull)
}

// syncChallengeRequest is the client's challenge + proof of PSK knowledge.
type syncChallengeRequest struct {
	Challenge string `json:"challenge"` // base64-encoded 32 random bytes
	Proof     string `json:"proof"`     // base64-encoded BLAKE3(PSK || challenge)
}

// syncChallengeResponse is the server's counter-challenge + session token.
type syncChallengeResponse struct {
	Challenge string `json:"challenge"` // base64-encoded 32 random bytes
	Proof     string `json:"proof"`     // base64-encoded BLAKE3(PSK || challenge)
	Token     string `json:"token"`     // session token for subsequent requests
}

// handleSyncChallenge performs mutual PSK authentication.
// Client proves it knows the PSK, server proves it too, and issues a session token.
func (s *Server) handleSyncChallenge(w http.ResponseWriter, r *http.Request) {
	log := logging.New("sync-api")

	// Rate limit
	source := r.RemoteAddr
	if s.syncLimiter != nil && !s.syncLimiter.allow(source) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	// Get PSK from connector
	psk := s.conn.GetPSK()
	if psk == nil {
		http.Error(w, "workspace not initialized", http.StatusServiceUnavailable)
		return
	}

	// Parse client's challenge
	var req syncChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	clientChallenge, err := base64.StdEncoding.DecodeString(req.Challenge)
	if err != nil || len(clientChallenge) != 32 {
		if s.syncLimiter != nil {
			s.syncLimiter.record(source)
		}
		http.Error(w, "invalid challenge", http.StatusBadRequest)
		return
	}

	clientProof, err := base64.StdEncoding.DecodeString(req.Proof)
	if err != nil {
		if s.syncLimiter != nil {
			s.syncLimiter.record(source)
		}
		http.Error(w, "invalid proof", http.StatusBadRequest)
		return
	}

	// Verify client's proof: BLAKE3(PSK || challenge)
	expected := crypto.Hash(append(psk, clientChallenge...))
	if !crypto.ConstantTimeEqual(expected[:], clientProof) {
		if s.syncLimiter != nil {
			s.syncLimiter.record(source)
		}
		log.Warn("sync challenge: PSK proof verification failed", map[string]any{"source": source})
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	// Generate server's counter-challenge
	serverChallenge := crypto.RandomBytes(32)
	serverProof := crypto.Hash(append(psk, serverChallenge...))

	// Issue session token
	token := s.syncSessions.create(5 * time.Minute)

	log.Info("sync challenge: authenticated", map[string]any{"source": source})

	resp := syncChallengeResponse{
		Challenge: base64.StdEncoding.EncodeToString(serverChallenge),
		Proof:     base64.StdEncoding.EncodeToString(serverProof[:]),
		Token:     token,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// syncPullRequest is the client's request for entries it doesn't have.
type syncPullRequest struct {
	Token       string   `json:"token"`        // session token from challenge
	KnownHashes []string `json:"known_hashes"` // hex-encoded hashes the client already has
}

// syncPullEntry is an entry in the pull response.
type syncPullEntry struct {
	Hash      string   `json:"hash"`       // hex
	RawCBOR   string   `json:"raw_cbor"`   // base64
	AuthorKey string   `json:"author_key"` // hex
	Signature string   `json:"signature"`  // base64
	EntryType int      `json:"entry_type"`
	CreatedAt int64    `json:"created_at"`
	Parents   []string `json:"parents"` // hex
}

// handleSyncPull returns entries the client is missing.
func (s *Server) handleSyncPull(w http.ResponseWriter, r *http.Request) {
	var req syncPullRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Validate session token
	if !s.syncSessions.validate(req.Token) {
		http.Error(w, "invalid or expired session", http.StatusUnauthorized)
		return
	}

	// Build set of known hashes
	knownSet := make(map[string]bool, len(req.KnownHashes))
	for _, h := range req.KnownHashes {
		knownSet[h] = true
	}

	// Get all entries from log
	logDB := s.conn.LogDB()
	allEntries, err := logDB.AllEntries()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Filter to entries the client doesn't have
	var result []syncPullEntry
	for _, e := range allEntries {
		hashHex := hex.EncodeToString(e.Hash)
		if knownSet[hashHex] {
			continue
		}

		parents := make([]string, 0, len(e.Parents))
		for _, p := range e.Parents {
			parents = append(parents, hex.EncodeToString(p))
		}

		result = append(result, syncPullEntry{
			Hash:      hashHex,
			RawCBOR:   base64.StdEncoding.EncodeToString(e.RawCBOR),
			AuthorKey: hex.EncodeToString(e.AuthorKey),
			Signature: base64.StdEncoding.EncodeToString(e.Signature),
			EntryType: e.EntryType,
			CreatedAt: e.CreatedAt,
			Parents:   parents,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"entries": result,
	})
}
