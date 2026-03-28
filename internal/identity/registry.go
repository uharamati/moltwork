package identity

import (
	"crypto/ed25519"
	"fmt"
	"sync"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/crypto"
	"moltwork/internal/store"
)

// AgentID returns a short 5-character hex identifier derived from a public key.
// Deterministic — both sides compute the same ID from the same key.
// Used for human-readable disambiguation when display names collide.
func AgentID(pubKey []byte) string {
	h := crypto.Hash(append([]byte("agent-id:"), pubKey...))
	return fmt.Sprintf("%x", h[:3])[:5] // first 5 hex chars of hash
}

// Agent represents a registered agent in the workspace.
type Agent struct {
	PublicKey      ed25519.PublicKey
	ExchangePubKey []byte // X25519 public key for pairwise secret derivation
	PlatformUserID string
	Platform       string
	DisplayName    string
	Title          string
	Team           string
	HumanName      string // name of the human this agent belongs to
	Revoked        bool
}

// Registry maintains the set of known agents, built from log entries.
type Registry struct {
	mu     sync.RWMutex
	byKey  map[string]*Agent // hex(pubkey) -> Agent
	byPlat map[string]*Agent // platform:userID -> Agent
}

// NewRegistry creates an empty agent registry.
func NewRegistry() *Registry {
	return &Registry{
		byKey:  make(map[string]*Agent),
		byPlat: make(map[string]*Agent),
	}
}

// LoadFromDB builds the registry by scanning AgentRegistration entries from the log.
func (r *Registry) LoadFromDB(logDB *store.LogDB) error {
	entries, err := logDB.EntriesByType(int(moltcbor.EntryTypeAgentRegistration))
	if err != nil {
		return fmt.Errorf("load agent registrations: %w", err)
	}

	for _, raw := range entries {
		// Verify signature first (rule C2)
		if err := crypto.Verify(raw.AuthorKey, raw.RawCBOR, raw.Signature); err != nil {
			continue
		}

		// Decode the signable wrapper to get the inner envelope
		var sigData struct {
			Parents  [][]byte `cbor:"1,keyasint"`
			Envelope []byte   `cbor:"2,keyasint"`
			Time     int64    `cbor:"3,keyasint"`
		}
		if err := moltcbor.Unmarshal(raw.RawCBOR, &sigData); err != nil {
			continue
		}

		var innerEnv moltcbor.Envelope
		if err := moltcbor.Unmarshal(sigData.Envelope, &innerEnv); err != nil {
			continue
		}

		var reg moltcbor.AgentRegistration
		if err := moltcbor.Unmarshal(innerEnv.Payload, &reg); err != nil {
			continue
		}

		r.Register(&Agent{
			PublicKey:      reg.PublicKey,
			ExchangePubKey: reg.ExchangePubKey,
			PlatformUserID: reg.PlatformUserID,
			Platform:       reg.Platform,
			DisplayName:    reg.DisplayName,
			Title:          reg.Title,
			Team:           reg.Team,
			HumanName:      reg.HumanName,
		})
	}

	return nil
}

// maxAgents is the hard limit on registry size to prevent memory exhaustion.
const maxAgents = 10000

// Register adds an agent to the registry.
// Returns error if an agent with the same platform user ID already exists (Sybil prevention).
func (r *Registry) Register(agent *Agent) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Prevent unbounded growth
	if len(r.byKey) >= maxAgents {
		return fmt.Errorf("agent registry full (%d agents)", maxAgents)
	}

	platKey := platformKey(agent.Platform, agent.PlatformUserID)

	// Check for duplicate platform user ID (onboarding step 6)
	if existing, ok := r.byPlat[platKey]; ok {
		if !crypto.ConstantTimeEqual(existing.PublicKey, agent.PublicKey) {
			return fmt.Errorf("agent with platform user ID %s already registered", agent.PlatformUserID)
		}
		// Same agent re-registering — log field changes for auditability
		if existing.DisplayName != agent.DisplayName || existing.Title != agent.Title || existing.Team != agent.Team || existing.HumanName != agent.HumanName {
			existing.DisplayName = agent.DisplayName
			existing.Title = agent.Title
			existing.Team = agent.Team
			existing.HumanName = agent.HumanName
		}
		return nil
	}

	keyStr := fmt.Sprintf("%x", agent.PublicKey)
	r.byKey[keyStr] = agent
	r.byPlat[platKey] = agent
	return nil
}

// GetByPublicKey looks up an agent by their Ed25519 public key.
func (r *Registry) GetByPublicKey(pubKey ed25519.PublicKey) *Agent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byKey[fmt.Sprintf("%x", pubKey)]
}

// GetByPlatformID looks up an agent by platform and user ID.
func (r *Registry) GetByPlatformID(platform, userID string) *Agent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byPlat[platformKey(platform, userID)]
}

// All returns all registered agents.
func (r *Registry) All() []*Agent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*Agent, 0, len(r.byKey))
	for _, a := range r.byKey {
		result = append(result, a)
	}
	return result
}

// MarkRevoked marks an agent as revoked.
func (r *Registry) MarkRevoked(pubKey []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	keyStr := fmt.Sprintf("%x", pubKey)
	if agent, ok := r.byKey[keyStr]; ok {
		agent.Revoked = true
	}
}

// IsRevoked checks if an agent is revoked.
// Accepts []byte to satisfy the gossip.AgentValidator interface.
func (r *Registry) IsRevoked(pubKey []byte) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	keyStr := fmt.Sprintf("%x", pubKey)
	if agent, ok := r.byKey[keyStr]; ok {
		return agent.Revoked
	}
	return false
}

// IsRegisteredAgent checks if a public key belongs to a registered agent (rule C3).
// Accepts []byte to satisfy the gossip.AgentValidator interface.
func (r *Registry) IsRegisteredAgent(pubKey []byte) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.byKey[fmt.Sprintf("%x", pubKey)]
	return ok
}

// RegisterAgentKey marks a public key as registered so subsequent entries
// from this author pass the registration check during gossip sync.
func (r *Registry) RegisterAgentKey(pubKey []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	keyHex := fmt.Sprintf("%x", pubKey)
	if _, ok := r.byKey[keyHex]; !ok {
		r.byKey[keyHex] = &Agent{PublicKey: pubKey}
	}
}

// RegisterAgent registers an agent with full details from a synced registration entry.
func (r *Registry) RegisterAgent(pubKey []byte, displayName, platform, platformUserID, title, team, humanName string) {
	r.Register(&Agent{
		PublicKey:      pubKey,
		PlatformUserID: platformUserID,
		Platform:       platform,
		DisplayName:    displayName,
		Title:          title,
		Team:           team,
		HumanName:      humanName,
	})
}

// Count returns the number of registered agents.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byKey)
}

func platformKey(platform, userID string) string {
	return platform + ":" + userID
}
