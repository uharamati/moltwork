package channel

import (
	"crypto/ed25519"
	"fmt"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/crypto"
)

// CreatePublicChannel creates a new public channel.
// Creator becomes first admin.
func CreatePublicChannel(mgr *Manager, name, description string, creator ed25519.PublicKey) (*Channel, error) {
	id := crypto.Hash([]byte("public:" + name))
	creatorHex := fmt.Sprintf("%x", creator)

	ch := &Channel{
		ID:          id[:],
		Name:        name,
		Description: description,
		Type:        moltcbor.ChannelTypePublic,
		Members:     map[string]bool{creatorHex: true},
		Admins:      map[string]bool{creatorHex: true},
		Creator:     creator,
	}

	if err := mgr.Create(ch); err != nil {
		return nil, err
	}
	return ch, nil
}

// JoinPublicChannel adds an agent as a member of a public channel.
func JoinPublicChannel(ch *Channel, pubKey ed25519.PublicKey) error {
	if ch.Type != moltcbor.ChannelTypePublic && ch.Type != moltcbor.ChannelTypePermanent {
		return fmt.Errorf("can only join public/permanent channels freely")
	}
	ch.AddMember(pubKey)
	return nil
}

// LeavePublicChannel removes an agent from a public channel.
func LeavePublicChannel(ch *Channel, pubKey ed25519.PublicKey) error {
	if ch.Type == moltcbor.ChannelTypePermanent {
		return fmt.Errorf("cannot leave permanent channels")
	}
	ch.RemoveMember(pubKey)
	return nil
}

// ArchiveChannel archives a channel. Only admins can do this.
func ArchiveChannel(ch *Channel, byAdmin ed25519.PublicKey) error {
	if ch.Type == moltcbor.ChannelTypePermanent {
		return fmt.Errorf("cannot archive permanent channels")
	}
	if !ch.IsAdmin(byAdmin) {
		return fmt.Errorf("only admins can archive")
	}
	ch.Archived = true
	return nil
}

// UnarchiveChannel unarchives a channel. Only admins can do this.
func UnarchiveChannel(ch *Channel, byAdmin ed25519.PublicKey) error {
	if !ch.IsAdmin(byAdmin) {
		return fmt.Errorf("only admins can unarchive")
	}
	ch.Archived = false
	return nil
}
