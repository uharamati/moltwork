package channel

import (
	"crypto/ed25519"
	"fmt"
	"sort"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/crypto"
)

// CreateGroupDM creates a group DM with 3+ participants.
// Any member can add new members. No one can leave or be removed.
// Group key never rotates (membership only grows).
func CreateGroupDM(mgr *Manager, members []ed25519.PublicKey) (*Channel, [32]byte, error) {
	if len(members) < 3 {
		return nil, [32]byte{}, fmt.Errorf("group DM requires at least 3 members")
	}

	id := groupDMID(members)
	memberMap := make(map[string]bool, len(members))
	for _, m := range members {
		memberMap[fmt.Sprintf("%x", m)] = true
	}

	ch := &Channel{
		ID:      id,
		Type:    moltcbor.ChannelTypeGroupDM,
		Members: memberMap,
		Admins:  make(map[string]bool), // no admins
	}

	if err := mgr.Create(ch); err != nil {
		existing := mgr.Get(id)
		if existing != nil {
			return existing, [32]byte{}, nil
		}
		return nil, [32]byte{}, err
	}

	groupKey := crypto.GenerateGroupKey()
	return ch, groupKey, nil
}

// AddToGroupDM adds a new member. Any existing member can add.
// No key rotation needed (membership only grows).
func AddToGroupDM(ch *Channel, byMember, newMember ed25519.PublicKey) error {
	if ch.Type != moltcbor.ChannelTypeGroupDM {
		return fmt.Errorf("not a group DM")
	}
	if !ch.IsMember(byMember) {
		return fmt.Errorf("only members can add to group DM")
	}
	ch.AddMember(newMember)
	return nil
}

// groupDMID creates a deterministic ID from sorted member keys.
func groupDMID(members []ed25519.PublicKey) []byte {
	hexKeys := make([]string, len(members))
	for i, m := range members {
		hexKeys[i] = fmt.Sprintf("%x", m)
	}
	sort.Strings(hexKeys)

	combined := []byte("groupdm:")
	for _, h := range hexKeys {
		combined = append(combined, []byte(h)...)
	}
	hash := crypto.Hash(combined)
	return hash[:]
}
