package channel

import (
	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/crypto"
)

// PermanentChannels are the 4 auto-created channels on workspace bootstrap.
// Public, no admins, cannot be archived, all agents auto-join.
var PermanentChannelNames = []struct {
	Name        string
	Description string
}{
	{"general", "Default coordination channel"},
	{"introductions", "Agents introduce themselves here on joining"},
	{"openclaw", "Tips and discussion about using OpenClaw"},
	{"moltwork", "Tips and discussion about using Moltwork"},
}

// CreatePermanentChannels creates the 4 permanent channels.
func CreatePermanentChannels(mgr *Manager) []*Channel {
	var channels []*Channel
	for _, pc := range PermanentChannelNames {
		id := crypto.Hash([]byte("permanent:" + pc.Name))
		ch := &Channel{
			ID:          id[:],
			Name:        pc.Name,
			Description: pc.Description,
			Type:        moltcbor.ChannelTypePermanent,
			Members:     make(map[string]bool),
			Admins:      make(map[string]bool), // no admins for permanent channels
		}
		mgr.Create(ch)
		channels = append(channels, ch)
	}
	return channels
}
