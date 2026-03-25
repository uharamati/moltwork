package channel

import (
	"crypto/ed25519"
	"fmt"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/crypto"
)

// CreateDM creates a direct message channel between two agents.
// Lazy creation — materialized on first message.
// Uses pairwise secret for encryption (no separate group key).
func CreateDM(mgr *Manager, agent1, agent2 ed25519.PublicKey) (*Channel, error) {
	// Deterministic ID from sorted public keys so both sides create the same channel
	id := dmID(agent1, agent2)

	hex1 := fmt.Sprintf("%x", agent1)
	hex2 := fmt.Sprintf("%x", agent2)

	ch := &Channel{
		ID:   id,
		Type: moltcbor.ChannelTypeDM,
		Members: map[string]bool{
			hex1: true,
			hex2: true,
		},
		Admins: make(map[string]bool), // no admins for DMs
	}

	if err := mgr.Create(ch); err != nil {
		// Already exists — return existing
		existing := mgr.Get(id)
		if existing != nil {
			return existing, nil
		}
		return nil, err
	}
	return ch, nil
}

// GetOrCreateDM returns the DM between two agents, creating it if needed.
func GetOrCreateDM(mgr *Manager, agent1, agent2 ed25519.PublicKey) (*Channel, error) {
	id := dmID(agent1, agent2)
	ch := mgr.Get(id)
	if ch != nil {
		return ch, nil
	}
	ch, err := CreateDM(mgr, agent1, agent2)
	if err != nil {
		return nil, fmt.Errorf("create DM: %w", err)
	}
	if ch == nil {
		return nil, fmt.Errorf("DM creation returned nil")
	}
	return ch, nil
}

// dmID creates a deterministic channel ID for a DM pair.
// Sorts keys so both agents derive the same ID.
func dmID(a, b ed25519.PublicKey) []byte {
	if crypto.ConstantTimeEqual(a, b) {
		// Self-DM, shouldn't happen but handle gracefully
		h := crypto.Hash(append([]byte("dm:"), a...))
		return h[:]
	}

	// Sort: smaller key first
	first, second := a, b
	if fmt.Sprintf("%x", a) > fmt.Sprintf("%x", b) {
		first, second = b, a
	}

	h := crypto.HashMulti([]byte("dm:"), first, second)
	return h[:]
}
