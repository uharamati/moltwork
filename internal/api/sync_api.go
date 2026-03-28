package api

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"

	"moltwork/internal/crypto"
	"moltwork/internal/logging"
)

// stripPort extracts the host/IP from a host:port address.
func stripPort(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// syncSession tracks a PSK-authenticated sync session.
type syncSession struct {
	token    string
	expires  time.Time
	clientIP string
}

// syncSessionStore manages short-lived session tokens issued after PSK auth.
type syncSessionStore struct {
	mu             sync.Mutex
	sessions       map[string]syncSession
	usedChallenges map[string]time.Time // challenge hex -> when used
}

func newSyncSessionStore() *syncSessionStore {
	return &syncSessionStore{
		sessions:       make(map[string]syncSession),
		usedChallenges: make(map[string]time.Time),
	}
}

// markChallengeUsed records a challenge as used and returns false if it was already used.
func (s *syncSessionStore) markChallengeUsed(challenge string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Prune old challenges (older than 2 minutes)
	now := time.Now()
	for k, t := range s.usedChallenges {
		if now.Sub(t) > 2*time.Minute {
			delete(s.usedChallenges, k)
		}
	}
	if _, exists := s.usedChallenges[challenge]; exists {
		return false // already used
	}
	s.usedChallenges[challenge] = now
	return true
}

func (s *syncSessionStore) create(ttl time.Duration, clientIP string) string {
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
		token:    token,
		expires:  now.Add(ttl),
		clientIP: clientIP,
	}
	return token
}

func (s *syncSessionStore) validate(token string, clientIP string) bool {
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
	if sess.clientIP != clientIP {
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

	// Reject replayed challenges
	if !s.syncSessions.markChallengeUsed(req.Challenge) {
		log.Warn("sync challenge: replayed challenge", map[string]any{"source": source})
		http.Error(w, "challenge already used", http.StatusUnauthorized)
		return
	}

	// Generate server's counter-challenge
	serverChallenge := crypto.RandomBytes(32)
	serverProof := crypto.Hash(append(psk, serverChallenge...))

	// Issue session token bound to client IP
	token := s.syncSessions.create(5*time.Minute, stripPort(r.RemoteAddr))

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

const (
	// maxKnownHashes limits the number of hashes a client can send in a sync pull
	// request to prevent OOM from a malicious or buggy client.
	maxKnownHashes = 100000

	// maxSyncPullEntries limits the number of entries returned per sync pull to
	// prevent OOM when serializing large responses. Client should request again
	// with updated known_hashes if has_more is true.
	maxSyncPullEntries = 5000
)

// handleSyncPull returns entries the client is missing.
func (s *Server) handleSyncPull(w http.ResponseWriter, r *http.Request) {
	var req syncPullRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Validate session token (must match originating IP)
	if !s.syncSessions.validate(req.Token, stripPort(r.RemoteAddr)) {
		http.Error(w, "invalid or expired session", http.StatusUnauthorized)
		return
	}

	// Reject oversized known_hashes to prevent OOM from map construction
	if len(req.KnownHashes) > maxKnownHashes {
		http.Error(w, "too many known_hashes", http.StatusBadRequest)
		return
	}

	// Build set of known hashes
	knownSet := make(map[string]bool, len(req.KnownHashes))
	for _, h := range req.KnownHashes {
		knownSet[h] = true
	}

	// Fetch entries in pages to avoid loading the entire log into memory.
	// Filter out entries the client already has and stop when we hit the batch cap.
	logDB := s.conn.LogDB()
	var result []syncPullEntry
	const pageSize = 1000
	offset := 0
	for len(result) < maxSyncPullEntries {
		page, err := logDB.AllEntriesPaginated(offset, pageSize)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if len(page) == 0 {
			break
		}
		for _, e := range page {
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
			if len(result) >= maxSyncPullEntries {
				break
			}
		}
		offset += pageSize
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"entries":  result,
		"has_more": len(result) >= maxSyncPullEntries,
	})
}
