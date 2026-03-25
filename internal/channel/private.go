package channel

import (
	"crypto/ed25519"
	"fmt"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/crypto"
)

// CreatePrivateChannel creates a new encrypted private channel.
// Creator becomes first admin and first member.
// Returns the channel and its initial group key.
func CreatePrivateChannel(mgr *Manager, name, description string, creator ed25519.PublicKey) (*Channel, [32]byte, error) {
	id := crypto.RandomBytes(32)
	creatorHex := fmt.Sprintf("%x", creator)

	ch := &Channel{
		ID:          id,
		Name:        name,
		Description: description,
		Type:        moltcbor.ChannelTypePrivate,
		Members:     map[string]bool{creatorHex: true},
		Admins:      map[string]bool{creatorHex: true},
		Creator:     creator,
	}

	if err := mgr.Create(ch); err != nil {
		return nil, [32]byte{}, err
	}

	groupKey := crypto.GenerateGroupKey()
	return ch, groupKey, nil
}

// InviteToPrivateChannel invites a member. Only admins can invite.
// The caller is responsible for distributing the group key via pairwise secret.
func InviteToPrivateChannel(ch *Channel, byAdmin, invitee ed25519.PublicKey) error {
	if ch.Type != moltcbor.ChannelTypePrivate {
		return fmt.Errorf("not a private channel")
	}
	if !ch.IsAdmin(byAdmin) {
		return fmt.Errorf("only admins can invite to private channels")
	}
	ch.AddMember(invitee)
	return nil
}

// RemoveFromPrivateChannel removes a member. Only admins can remove.
// The caller is responsible for rotating the group key after removal.
func RemoveFromPrivateChannel(ch *Channel, byAdmin, target ed25519.PublicKey) error {
	if ch.Type != moltcbor.ChannelTypePrivate {
		return fmt.Errorf("not a private channel")
	}
	if !ch.IsAdmin(byAdmin) {
		return fmt.Errorf("only admins can remove from private channels")
	}
	ch.RemoveMember(target)
	return nil
}

// LeavePrivateChannel allows a member to voluntarily leave.
// The caller is responsible for rotating the group key.
func LeavePrivateChannel(ch *Channel, pubKey ed25519.PublicKey) error {
	if ch.Type != moltcbor.ChannelTypePrivate {
		return fmt.Errorf("not a private channel")
	}
	ch.RemoveMember(pubKey)
	return nil
}
