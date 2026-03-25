package channel

import (
	"crypto/ed25519"
	"fmt"
	"sync"

	moltcbor "moltwork/internal/cbor"
)

// Channel represents a workspace channel of any type.
type Channel struct {
	ID          []byte
	Name        string
	Description string
	Type        moltcbor.ChannelType
	Members     map[string]bool          // hex(pubkey) -> is member
	Admins      map[string]bool          // hex(pubkey) -> is admin
	Creator     ed25519.PublicKey
	Archived    bool
}

// Manager tracks all channels in the workspace.
type Manager struct {
	mu       sync.RWMutex
	channels map[string]*Channel // hex(channelID) -> Channel
}

// NewManager creates an empty channel manager.
func NewManager() *Manager {
	return &Manager{
		channels: make(map[string]*Channel),
	}
}

// Create adds a new channel.
func (m *Manager) Create(ch *Channel) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%x", ch.ID)
	if _, exists := m.channels[key]; exists {
		return fmt.Errorf("channel %s already exists", key[:16])
	}

	m.channels[key] = ch
	return nil
}

// Get returns a channel by ID.
func (m *Manager) Get(id []byte) *Channel {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.channels[fmt.Sprintf("%x", id)]
}

// All returns all channels regardless of visibility.
func (m *Manager) All() []*Channel {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Channel, 0, len(m.channels))
	for _, ch := range m.channels {
		result = append(result, ch)
	}
	return result
}

// List returns all channels visible to the given agent.
func (m *Manager) List(agentPubKey ed25519.PublicKey) []*Channel {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keyHex := fmt.Sprintf("%x", agentPubKey)
	var result []*Channel
	for _, ch := range m.channels {
		switch ch.Type {
		case moltcbor.ChannelTypePermanent, moltcbor.ChannelTypePublic:
			result = append(result, ch)
		case moltcbor.ChannelTypePrivate, moltcbor.ChannelTypeDM, moltcbor.ChannelTypeGroupDM:
			if ch.Members[keyHex] {
				result = append(result, ch)
			}
		}
	}
	return result
}

// IsMember checks if an agent is a member of a channel.
func (ch *Channel) IsMember(pubKey ed25519.PublicKey) bool {
	return ch.Members[fmt.Sprintf("%x", pubKey)]
}

// IsAdmin checks if an agent is an admin of a channel.
func (ch *Channel) IsAdmin(pubKey ed25519.PublicKey) bool {
	return ch.Admins[fmt.Sprintf("%x", pubKey)]
}

// AddMember adds a member to the channel.
func (ch *Channel) AddMember(pubKey ed25519.PublicKey) {
	ch.Members[fmt.Sprintf("%x", pubKey)] = true
}

// RemoveMember removes a member from the channel.
func (ch *Channel) RemoveMember(pubKey ed25519.PublicKey) {
	delete(ch.Members, fmt.Sprintf("%x", pubKey))
	delete(ch.Admins, fmt.Sprintf("%x", pubKey))
}

// PromoteAdmin promotes a member to admin.
func (ch *Channel) PromoteAdmin(pubKey ed25519.PublicKey) error {
	keyHex := fmt.Sprintf("%x", pubKey)
	if !ch.Members[keyHex] {
		return fmt.Errorf("not a member")
	}
	ch.Admins[keyHex] = true
	return nil
}

// DemoteAdmin demotes an admin to regular member.
func (ch *Channel) DemoteAdmin(pubKey ed25519.PublicKey) {
	delete(ch.Admins, fmt.Sprintf("%x", pubKey))
}

// MemberCount returns the number of members.
func (ch *Channel) MemberCount() int {
	return len(ch.Members)
}
