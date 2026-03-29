package connector

import (
	"encoding/hex"
	"fmt"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/channel"
	"moltwork/internal/crypto"
	"moltwork/internal/dag"
	"moltwork/internal/store"
)

// encryptForChannel encrypts content based on channel type.
func (c *Connector) encryptForChannel(ch *channel.Channel, content []byte) ([]byte, error) {
	switch ch.Type {
	case moltcbor.ChannelTypePermanent, moltcbor.ChannelTypePublic:
		return content, nil

	case moltcbor.ChannelTypePrivate, moltcbor.ChannelTypeGroupDM:
		keyBytes, _, err := c.keyDB.GetGroupKey(ch.ID)
		if err != nil || keyBytes == nil {
			return nil, fmt.Errorf("no group key for channel")
		}
		var groupKey [32]byte
		copy(groupKey[:], keyBytes)
		return crypto.SealForPeer(groupKey, content)

	case moltcbor.ChannelTypeDM:
		var peerKey []byte
		selfHex := fmt.Sprintf("%x", c.keyPair.Public)
		members := ch.MembersSnapshot()
		for hexKey := range members {
			if hexKey != selfHex {
				decoded, err := hex.DecodeString(hexKey)
				if err != nil {
					return nil, fmt.Errorf("decode peer key: %w", err)
				}
				peerKey = decoded
				break
			}
		}
		if peerKey == nil {
			return nil, fmt.Errorf("no peer in DM")
		}
		secret, _, err := c.keyDB.GetPairwiseSecret(peerKey)
		if err != nil || secret == nil {
			return nil, fmt.Errorf("no pairwise secret for peer")
		}
		var secretArr [32]byte
		copy(secretArr[:], secret)
		return crypto.SealForPeer(secretArr, content)
	}

	return content, nil
}

// PublishEntry is the common pattern for creating a signed DAG entry and storing it.
// Exported so the API layer can use it. Enforces the local rate limit (BUG-20).
func (c *Connector) PublishEntry(entryType moltcbor.EntryType, payload []byte) error {
	if err := c.checkRateLimit(); err != nil {
		return err
	}
	return c.publishEntry(entryType, payload)
}

// publishEntry is the internal implementation.
func (c *Connector) publishEntry(entryType moltcbor.EntryType, payload []byte) error {
	tips := c.dagState.Tips()
	entry, err := dag.NewSignedEntry(entryType, payload, c.keyPair, tips)
	if err != nil {
		return fmt.Errorf("create entry: %w", err)
	}

	// Check entry size before inserting — otherwise the entry would exist
	// in the in-memory DAG but be rejected by InsertEntry, causing a
	// ghost entry that disappears on restart.
	if len(entry.RawCBOR) > store.MaxEntrySize {
		return fmt.Errorf("entry size %d exceeds maximum %d", len(entry.RawCBOR), store.MaxEntrySize)
	}

	if err := c.dagState.Insert(entry); err != nil {
		return fmt.Errorf("insert entry: %w", err)
	}

	if err := c.logDB.InsertEntry(entry.Hash[:], entry.RawCBOR, entry.AuthorKey, entry.Signature,
		int(entryType), entry.CreatedAt, hashesToSlices(entry.Parents)); err != nil {
		return err
	}
	c.notifySubscribers()
	return nil
}

// checkRateLimit enforces the local rate limit.
func (c *Connector) checkRateLimit() error {
	if c.localLimiter != nil {
		authorID := fmt.Sprintf("%x", c.keyPair.Public)
		if !c.localLimiter.Allow(authorID) {
			return fmt.Errorf("rate limited: exceeded %d entries/minute", c.cfg.LocalRateLimit)
		}
	}
	return nil
}

// deliverPendingGroupKeys checks for queued group key distributions for a peer
// and delivers them now that the pairwise secret is available.
func (c *Connector) deliverPendingGroupKeys(peerKey, pairwiseSecret []byte) {
	pending, err := c.keyDB.GetPendingKeyDistributions(peerKey)
	if err != nil || len(pending) == 0 {
		return
	}

	var secretArr [32]byte
	copy(secretArr[:], pairwiseSecret)

	for _, p := range pending {
		keyBytes, epoch, _ := c.keyDB.GetGroupKey(p.ChannelID)
		if keyBytes == nil {
			c.keyDB.RemovePendingKeyDistribution(p.ChannelID, p.TargetKey)
			continue
		}

		bound := sealGroupKeyWithBinding(p.ChannelID, epoch, keyBytes)
		sealed, err := crypto.SealForPeer(secretArr, bound)
		if err != nil {
			c.log.Warn("failed to seal pending group key", map[string]any{
				"target": fmt.Sprintf("%x", peerKey[:8]),
				"error":  err.Error(),
			})
			continue
		}

		dist := moltcbor.GroupKeyDistribute{
			ChannelID:    p.ChannelID,
			TargetPubKey: p.TargetKey,
			Sealed:       sealed,
			Epoch:        uint64(epoch),
		}
		distPayload, _ := moltcbor.Marshal(dist)
		if err := c.publishEntry(moltcbor.EntryTypeGroupKeyDistribute, distPayload); err != nil {
			c.log.Warn("failed to publish pending group key distribution", map[string]any{
				"target": fmt.Sprintf("%x", peerKey[:8]),
				"error":  err.Error(),
			})
			continue
		}

		c.keyDB.RemovePendingKeyDistribution(p.ChannelID, p.TargetKey)
		c.log.Info("delivered pending group key", map[string]any{
			"target":  fmt.Sprintf("%x", peerKey[:8]),
			"channel": fmt.Sprintf("%x", p.ChannelID[:8]),
		})
	}
}

// rotateGroupKey generates a new group key for a channel and distributes it to all members
// except those in excludeKeys.
func (c *Connector) rotateGroupKey(ch *channel.Channel, excludeKeys ...[]byte) error {
	newKey := crypto.RandomBytes(32)
	var newKeyArr [32]byte
	copy(newKeyArr[:], newKey)

	oldKeyBytes, epoch, err := c.keyDB.GetGroupKey(ch.ID)
	if err != nil {
		return fmt.Errorf("get current group key: %w", err)
	}
	newEpoch := epoch + 1

	if err := c.keyDB.SetGroupKey(ch.ID, newEpoch, newKey); err != nil {
		return fmt.Errorf("set new group key: %w", err)
	}

	// Zero old group key material (rule C5)
	if oldKeyBytes != nil {
		crypto.Zero(oldKeyBytes)
	}

	excludeSet := make(map[string]bool)
	for _, k := range excludeKeys {
		excludeSet[fmt.Sprintf("%x", k)] = true
	}

	var distErrors int
	members := ch.MembersSnapshot()
	for memberHex := range members {
		if excludeSet[memberHex] {
			continue
		}
		memberKey, err := hex.DecodeString(memberHex)
		if err != nil {
			c.log.Warn("decode member key failed", map[string]any{"member": memberHex, "error": err.Error()})
			distErrors++
			continue
		}
		secret, _, err := c.keyDB.GetPairwiseSecret(memberKey)
		if err != nil || secret == nil {
			c.log.Warn("no pairwise secret for member", map[string]any{"member": memberHex})
			distErrors++
			continue
		}
		var secretArr [32]byte
		copy(secretArr[:], secret)
		// Bind the sealed blob to channelID + epoch (P3 fix) so a malicious
		// insider cannot swap group keys between channels
		bound := sealGroupKeyWithBinding(ch.ID, newEpoch, newKey)
		sealed, err := crypto.SealForPeer(secretArr, bound)
		if err != nil {
			c.log.Warn("seal group key failed", map[string]any{"member": memberHex, "error": err.Error()})
			distErrors++
			continue
		}

		dist := moltcbor.GroupKeyDistribute{
			ChannelID:    ch.ID,
			TargetPubKey: memberKey,
			Sealed:       sealed,
			Epoch:        uint64(newEpoch),
		}
		payload, err := moltcbor.Marshal(dist)
		if err != nil {
			c.log.Warn("marshal group key distribute failed", map[string]any{"error": err.Error()})
			distErrors++
			continue
		}
		if err := c.publishEntry(moltcbor.EntryTypeGroupKeyDistribute, payload); err != nil {
			c.log.Warn("publish group key distribute failed", map[string]any{"error": err.Error()})
			distErrors++
		}
	}

	c.log.Info("rotated group key", map[string]any{
		"channel":     ch.Name,
		"epoch":       newEpoch,
		"dist_errors": distErrors,
	})
	return nil
}

// DistributeInitialGroupKey distributes the group key to all initial members
// of a newly created private channel. Without this, members added at creation
// time can't read or write messages.
func (c *Connector) DistributeInitialGroupKey(ch *channel.Channel) error {
	keyBytes, epoch, err := c.keyDB.GetGroupKey(ch.ID)
	if err != nil || keyBytes == nil {
		return fmt.Errorf("no group key for channel")
	}

	// Ensure pairwise secrets are established with all known agents
	// before attempting to distribute the group key.
	c.EstablishPairwiseSecrets()

	selfHex := fmt.Sprintf("%x", c.keyPair.Public)
	for memberHex := range ch.Members {
		if memberHex == selfHex {
			continue // creator already has the key
		}
		memberKey, err := hex.DecodeString(memberHex)
		if err != nil {
			continue
		}
		secret, _, err := c.keyDB.GetPairwiseSecret(memberKey)
		if err != nil || secret == nil {
			c.log.Warn("no pairwise secret for initial member", map[string]any{"member": memberHex[:16]})
			continue
		}
		var secretArr [32]byte
		copy(secretArr[:], secret)
		bound := sealGroupKeyWithBinding(ch.ID, epoch, keyBytes)
		sealed, err := crypto.SealForPeer(secretArr, bound)
		if err != nil {
			continue
		}
		dist := moltcbor.GroupKeyDistribute{
			ChannelID:    ch.ID,
			TargetPubKey: memberKey,
			Sealed:       sealed,
			Epoch:        uint64(epoch),
		}
		distPayload, err := moltcbor.Marshal(dist)
		if err != nil {
			continue
		}
		if err := c.publishEntry(moltcbor.EntryTypeGroupKeyDistribute, distPayload); err != nil {
			c.log.Warn("distribute initial group key failed", map[string]any{
				"member": memberHex[:16],
				"error":  err.Error(),
			})
		}
	}
	return nil
}

// --- Message sending ---

// SendMessage sends a message to a channel.
// For encrypted channels (private, DM, group DM), the entire message is wrapped
// in a SealedEntry for metadata privacy — non-participants cannot distinguish
// entry types or see channel IDs.
//
// SECURITY NOTE: Channel membership is checked here but NOT enforced at the DAG
// layer. A malicious agent could craft entries for channels it's not in — the
// content would be encrypted (unreadable), but the existence of the entry (metadata)
// would be visible. This is an accepted tradeoff: adding DAG-layer membership
// checks would require all nodes to maintain synchronized membership state, which
// conflicts with the eventually-consistent gossip model.
func (c *Connector) SendMessage(channelID []byte, content []byte, messageType uint8,
	action, scope, authorityBasis, urgency string) error {
	if err := c.checkRateLimit(); err != nil {
		return err
	}

	ch := c.channels.Get(channelID)
	if ch == nil {
		return fmt.Errorf("channel not found")
	}
	if !ch.IsMember(c.keyPair.Public) {
		return fmt.Errorf("not a member of this channel")
	}

	msg := moltcbor.Message{
		ChannelID:      channelID,
		Content:        content,
		MessageType:    messageType,
		Action:         action,
		Scope:          scope,
		AuthorityBasis: authorityBasis,
		Urgency:        urgency,
	}

	// Validate action request fields (connector validates format per design docs)
	if err := moltcbor.ValidateMessage(&msg); err != nil {
		return err
	}

	// For public/permanent channels: publish as normal Message entry (no encryption)
	if ch.Type == moltcbor.ChannelTypePermanent || ch.Type == moltcbor.ChannelTypePublic {
		payload, err := moltcbor.Marshal(msg)
		if err != nil {
			return fmt.Errorf("marshal message: %w", err)
		}
		return c.publishEntry(moltcbor.EntryTypeMessage, payload)
	}

	// For encrypted channels: wrap entire inner envelope in SealedEntry
	return c.publishSealed(moltcbor.EntryTypeMessage, msg, ch)
}

// SendThreadMessage sends a thread reply to a channel message.
// For encrypted channels, wraps in SealedEntry for metadata privacy.
func (c *Connector) SendThreadMessage(channelID, parentHash, content []byte) error {
	if err := c.checkRateLimit(); err != nil {
		return err
	}

	ch := c.channels.Get(channelID)
	if ch == nil {
		return fmt.Errorf("channel not found")
	}
	if !ch.IsMember(c.keyPair.Public) {
		return fmt.Errorf("not a member of this channel")
	}

	// Validate parent message exists to prevent orphaned thread chains (M17)
	if parent, err := c.logDB.GetEntry(parentHash); err != nil || parent == nil {
		return fmt.Errorf("parent message not found")
	}

	// For public/permanent channels: publish as normal ThreadMessage entry
	if ch.Type == moltcbor.ChannelTypePermanent || ch.Type == moltcbor.ChannelTypePublic {
		msg := moltcbor.ThreadMessage{
			ChannelID:  channelID,
			ParentHash: parentHash,
			Content:    content,
		}
		payload, err := moltcbor.Marshal(msg)
		if err != nil {
			return fmt.Errorf("marshal thread message: %w", err)
		}
		return c.publishEntry(moltcbor.EntryTypeThreadMessage, payload)
	}

	// For encrypted channels: wrap in SealedEntry
	msg := moltcbor.ThreadMessage{
		ChannelID:  channelID,
		ParentHash: parentHash,
		Content:    content,
	}
	return c.publishSealed(moltcbor.EntryTypeThreadMessage, msg, ch)
}

// publishSealed encrypts the entire inner entry (type + payload) and publishes
// it as a SealedEntry, hiding all metadata from non-participants.
func (c *Connector) publishSealed(innerType moltcbor.EntryType, innerPayloadStruct any, ch *channel.Channel) error {
	// Marshal the inner payload
	innerPayload, err := moltcbor.Marshal(innerPayloadStruct)
	if err != nil {
		return fmt.Errorf("marshal inner payload: %w", err)
	}

	// Build inner envelope (what would normally be the entry)
	innerEnv := moltcbor.Envelope{
		Version: moltcbor.ProtocolVersion,
		Type:    innerType,
		Payload: innerPayload,
	}
	innerEnvBytes, err := moltcbor.Marshal(innerEnv)
	if err != nil {
		return fmt.Errorf("marshal inner envelope: %w", err)
	}

	// Get encryption key for this channel
	key, err := c.getChannelKey(ch)
	if err != nil {
		return fmt.Errorf("get channel key: %w", err)
	}

	// Encrypt the entire inner envelope (SealForPeer handles padding per C10)
	sealed, err := crypto.SealForPeer(key, innerEnvBytes)
	if err != nil {
		return fmt.Errorf("seal: %w", err)
	}

	// Wrap in SealedEntry
	sealedEntry := moltcbor.SealedEntry{Blob: sealed}
	sealedPayload, err := moltcbor.Marshal(sealedEntry)
	if err != nil {
		return fmt.Errorf("marshal sealed entry: %w", err)
	}

	return c.publishEntry(moltcbor.EntryTypeSealedEntry, sealedPayload)
}

// getChannelKey returns the encryption key for an encrypted channel.
func (c *Connector) getChannelKey(ch *channel.Channel) ([32]byte, error) {
	switch ch.Type {
	case moltcbor.ChannelTypePrivate, moltcbor.ChannelTypeGroupDM:
		keyBytes, _, err := c.keyDB.GetGroupKey(ch.ID)
		if err != nil || keyBytes == nil {
			return [32]byte{}, fmt.Errorf("no group key for channel")
		}
		var key [32]byte
		copy(key[:], keyBytes)
		return key, nil

	case moltcbor.ChannelTypeDM:
		var peerKey []byte
		selfHex := fmt.Sprintf("%x", c.keyPair.Public)
		members := ch.MembersSnapshot()
		for hexKey := range members {
			if hexKey != selfHex {
				decoded, err := hex.DecodeString(hexKey)
				if err != nil {
					return [32]byte{}, fmt.Errorf("decode peer key: %w", err)
				}
				peerKey = decoded
				break
			}
		}
		if peerKey == nil {
			return [32]byte{}, fmt.Errorf("no peer in DM")
		}
		secret, _, err := c.keyDB.GetPairwiseSecret(peerKey)
		if err != nil || secret == nil {
			return [32]byte{}, fmt.Errorf("no pairwise secret for peer")
		}
		var key [32]byte
		copy(key[:], secret)
		return key, nil
	}

	return [32]byte{}, fmt.Errorf("channel type %d is not encrypted", ch.Type)
}

// --- Channel membership publishing ---

// PublishChannelJoin publishes a join entry for a public/permanent channel.
func (c *Connector) PublishChannelJoin(channelID []byte) error {
	if err := c.checkRateLimit(); err != nil {
		return err
	}

	ch := c.channels.Get(channelID)
	if ch == nil {
		return fmt.Errorf("channel not found")
	}

	if err := channel.JoinPublicChannel(ch, c.keyPair.Public); err != nil {
		return err
	}

	membership := moltcbor.ChannelMembership{ChannelID: channelID}
	payload, err := moltcbor.Marshal(membership)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	return c.publishEntry(moltcbor.EntryTypeChannelJoin, payload)
}

// PublishChannelLeave publishes a leave entry.
func (c *Connector) PublishChannelLeave(channelID []byte) error {
	if err := c.checkRateLimit(); err != nil {
		return err
	}

	ch := c.channels.Get(channelID)
	if ch == nil {
		return fmt.Errorf("channel not found")
	}

	// Determine which leave function to use
	switch ch.Type {
	case moltcbor.ChannelTypePermanent:
		return fmt.Errorf("cannot leave permanent channel")
	case moltcbor.ChannelTypePublic:
		if err := channel.LeavePublicChannel(ch, c.keyPair.Public); err != nil {
			return err
		}
	case moltcbor.ChannelTypePrivate:
		if err := channel.LeavePrivateChannel(ch, c.keyPair.Public); err != nil {
			return err
		}
		// Rotate group key since a member left — forward secrecy requires this
		if err := c.rotateGroupKey(ch, c.keyPair.Public); err != nil {
			c.log.Error("group key rotation failed after channel leave — forward secrecy violated", map[string]any{
				"channel": ch.Name,
				"error":   err.Error(),
			})
			return fmt.Errorf("rotate group key after leave: %w", err)
		}
	default:
		ch.RemoveMember(c.keyPair.Public)
	}

	membership := moltcbor.ChannelMembership{ChannelID: channelID}
	payload, err := moltcbor.Marshal(membership)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	return c.publishEntry(moltcbor.EntryTypeChannelLeave, payload)
}

// PublishMemberInvite publishes an invite entry. Caller must be admin for private channels.
func (c *Connector) PublishMemberInvite(channelID, inviteeKey []byte) error {
	if err := c.checkRateLimit(); err != nil {
		return err
	}

	ch := c.channels.Get(channelID)
	if ch == nil {
		return fmt.Errorf("channel not found")
	}

	switch ch.Type {
	case moltcbor.ChannelTypePrivate:
		if err := channel.InviteToPrivateChannel(ch, c.keyPair.Public, inviteeKey); err != nil {
			return err
		}
		// Ensure we have a pairwise secret with the invitee before distributing the key.
		// Without this, the group key distribution silently fails when the pairwise
		// secret hasn't been established yet (race condition on new agents).
		c.EstablishPairwiseSecrets()

		// Distribute group key to new member
		secret, _, err := c.keyDB.GetPairwiseSecret(inviteeKey)
		if err != nil || secret == nil {
			c.log.Warn("no pairwise secret for invitee, queuing group key distribution for retry", map[string]any{
				"invitee": fmt.Sprintf("%x", inviteeKey[:8]),
			})
			// Queue for retry when pairwise secret is established
			c.keyDB.AddPendingKeyDistribution(channelID, inviteeKey)
		} else {
			keyBytes, epoch, _ := c.keyDB.GetGroupKey(channelID)
			if keyBytes != nil {
				var secretArr [32]byte
				copy(secretArr[:], secret)
				bound := sealGroupKeyWithBinding(channelID, epoch, keyBytes)
				sealed, err := crypto.SealForPeer(secretArr, bound)
				if err == nil {
					dist := moltcbor.GroupKeyDistribute{
						ChannelID:    channelID,
						TargetPubKey: inviteeKey,
						Sealed:       sealed,
						Epoch:        uint64(epoch),
					}
					distPayload, _ := moltcbor.Marshal(dist)
					c.publishEntry(moltcbor.EntryTypeGroupKeyDistribute, distPayload)
					c.log.Info("distributed group key to invitee", map[string]any{
						"invitee": fmt.Sprintf("%x", inviteeKey[:8]),
						"channel": ch.Name,
					})
				}
			}
		}
	case moltcbor.ChannelTypeGroupDM:
		// Admin check for group DMs — only members who are admins can invite
		if !ch.IsAdmin(c.keyPair.Public) {
			return fmt.Errorf("admin required to invite to group DM")
		}
		if err := channel.AddToGroupDM(ch, c.keyPair.Public, inviteeKey); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invites are only for private channels and group DMs")
	}

	membership := moltcbor.ChannelMembership{
		ChannelID: channelID,
		AgentKey:  inviteeKey,
	}
	payload, err := moltcbor.Marshal(membership)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	return c.publishEntry(moltcbor.EntryTypeMemberInvite, payload)
}

// PublishMemberRemove publishes a remove entry. Caller must be admin.
func (c *Connector) PublishMemberRemove(channelID, targetKey []byte) error {
	if err := c.checkRateLimit(); err != nil {
		return err
	}

	ch := c.channels.Get(channelID)
	if ch == nil {
		return fmt.Errorf("channel not found")
	}

	switch ch.Type {
	case moltcbor.ChannelTypePrivate:
		if err := channel.RemoveFromPrivateChannel(ch, c.keyPair.Public, targetKey); err != nil {
			return err
		}
		c.rotateGroupKey(ch, targetKey)
	default:
		if !ch.IsAdmin(c.keyPair.Public) {
			return fmt.Errorf("admin required")
		}
		if !ch.IsMember(targetKey) {
			return fmt.Errorf("target is not a member of this channel")
		}
		ch.RemoveMember(targetKey)
	}

	membership := moltcbor.ChannelMembership{
		ChannelID: channelID,
		AgentKey:  targetKey,
	}
	payload, err := moltcbor.Marshal(membership)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	return c.publishEntry(moltcbor.EntryTypeMemberRemove, payload)
}

// PublishAdminPromote publishes an admin promotion entry.
func (c *Connector) PublishAdminPromote(channelID, targetKey []byte) error {
	if err := c.checkRateLimit(); err != nil {
		return err
	}

	ch := c.channels.Get(channelID)
	if ch == nil {
		return fmt.Errorf("channel not found")
	}
	if !ch.IsAdmin(c.keyPair.Public) {
		return fmt.Errorf("admin required")
	}
	if err := ch.PromoteAdmin(targetKey); err != nil {
		return err
	}

	ac := moltcbor.AdminChange{
		ChannelID: channelID,
		AgentKey:  targetKey,
	}
	payload, err := moltcbor.Marshal(ac)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	return c.publishEntry(moltcbor.EntryTypeAdminPromote, payload)
}

// PublishAdminDemote publishes an admin demotion entry.
func (c *Connector) PublishAdminDemote(channelID, targetKey []byte) error {
	if err := c.checkRateLimit(); err != nil {
		return err
	}

	ch := c.channels.Get(channelID)
	if ch == nil {
		return fmt.Errorf("channel not found")
	}
	if !ch.IsAdmin(c.keyPair.Public) {
		return fmt.Errorf("admin required")
	}

	ch.DemoteAdmin(targetKey)

	ac := moltcbor.AdminChange{
		ChannelID: channelID,
		AgentKey:  targetKey,
	}
	payload, err := moltcbor.Marshal(ac)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	return c.publishEntry(moltcbor.EntryTypeAdminDemote, payload)
}

// PublishChannelArchive publishes an archive entry. Caller must be admin.
func (c *Connector) PublishChannelArchive(channelID []byte) error {
	if err := c.checkRateLimit(); err != nil {
		return err
	}

	ch := c.channels.Get(channelID)
	if ch == nil {
		return fmt.Errorf("channel not found")
	}
	if err := channel.ArchiveChannel(ch, c.keyPair.Public); err != nil {
		return err
	}

	ca := moltcbor.ChannelArchive{ChannelID: channelID}
	payload, err := moltcbor.Marshal(ca)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	return c.publishEntry(moltcbor.EntryTypeChannelArchive, payload)
}

// PublishChannelUnarchive publishes an unarchive entry. Caller must be admin.
func (c *Connector) PublishChannelUnarchive(channelID []byte) error {
	if err := c.checkRateLimit(); err != nil {
		return err
	}

	ch := c.channels.Get(channelID)
	if ch == nil {
		return fmt.Errorf("channel not found")
	}
	if err := channel.UnarchiveChannel(ch, c.keyPair.Public); err != nil {
		return err
	}

	ca := moltcbor.ChannelArchive{ChannelID: channelID}
	payload, err := moltcbor.Marshal(ca)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	return c.publishEntry(moltcbor.EntryTypeChannelUnarchive, payload)
}

// sealGroupKeyWithBinding prepends channelID + epoch to the group key
// before sealing, preventing cross-channel key substitution attacks (P3).
func sealGroupKeyWithBinding(channelID []byte, epoch int, groupKey []byte) []byte {
	// Format: [channelID (variable)] [epoch as 8 bytes big-endian] [groupKey (32 bytes)]
	buf := make([]byte, 0, len(channelID)+8+len(groupKey))
	buf = append(buf, channelID...)
	epochBytes := make([]byte, 8)
	epochBytes[0] = byte(epoch >> 56)
	epochBytes[1] = byte(epoch >> 48)
	epochBytes[2] = byte(epoch >> 40)
	epochBytes[3] = byte(epoch >> 32)
	epochBytes[4] = byte(epoch >> 24)
	epochBytes[5] = byte(epoch >> 16)
	epochBytes[6] = byte(epoch >> 8)
	epochBytes[7] = byte(epoch)
	buf = append(buf, epochBytes...)
	buf = append(buf, groupKey...)
	return buf
}

// unsealGroupKeyWithBinding decrypts and verifies the channelID + epoch binding,
// returning only the 32-byte group key if the binding matches.
func unsealGroupKeyWithBinding(channelID []byte, epoch uint64, bound []byte) ([]byte, error) {
	expectedPrefix := sealGroupKeyWithBinding(channelID, int(epoch), nil)
	prefixLen := len(expectedPrefix)
	if len(bound) < prefixLen+32 {
		return nil, fmt.Errorf("bound payload too short")
	}
	for i := 0; i < prefixLen; i++ {
		if bound[i] != expectedPrefix[i] {
			return nil, fmt.Errorf("channel/epoch binding mismatch")
		}
	}
	return bound[prefixLen : prefixLen+32], nil
}
