package connector

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/channel"
	"moltwork/internal/crypto"
	"moltwork/internal/identity"
	"moltwork/internal/store"
)

// replayRevocations scans the log for revocation entries and marks agents as revoked.
// Called during Start() so that revocation state survives restarts.
func (c *Connector) replayRevocations() {
	entries, err := c.logDB.EntriesByType(int(moltcbor.EntryTypeRevocation))
	if err != nil {
		c.log.Warn("replay revocations: query failed", map[string]any{"error": err.Error()})
		return
	}

	// Build a hash→pubkey lookup for efficient matching
	hashToPubKey := make(map[string][]byte)
	for _, agent := range c.registry.All() {
		h := crypto.Hash(agent.PublicKey)
		hashToPubKey[fmt.Sprintf("%x", h[:])] = agent.PublicKey
	}

	revoked := 0
	for _, raw := range entries {
		rev := decodeRevocationEntry(raw)
		if rev == nil {
			continue
		}

		if err := identity.VerifyRevocation(rev); err != nil {
			continue
		}

		hashHex := fmt.Sprintf("%x", rev.RevokedKeyHash)
		pubKey, ok := hashToPubKey[hashHex]
		if !ok {
			continue
		}

		c.registry.MarkRevoked(pubKey)
		revoked++
	}

	if revoked > 0 {
		c.log.Info("replayed revocations", map[string]any{"count": revoked})
	}
}

// replayOrgRelationships scans the log for org relationship entries and loads them into the org map.
func (c *Connector) replayOrgRelationships() {
	entries, err := c.logDB.EntriesByType(int(moltcbor.EntryTypeOrgRelationship))
	if err != nil {
		c.log.Warn("replay org relationships: query failed", map[string]any{"error": err.Error()})
		return
	}

	loaded := 0
	for _, raw := range entries {
		rel := decodeOrgRelationshipEntry(raw)
		if rel == nil {
			continue
		}

		if err := c.orgMap.AddVerifiedRelationship(*rel); err != nil {
			continue
		}
		loaded++
	}

	if loaded > 0 {
		c.log.Info("replayed org relationships", map[string]any{"count": loaded})
	}
}

// replayChannelState scans the log for channel create and membership entries,
// replaying them in causal order to rebuild channel state.
func (c *Connector) replayChannelState() {
	// Gather all relevant entry types
	types := []int{
		int(moltcbor.EntryTypeChannelCreate),
		int(moltcbor.EntryTypeChannelJoin),
		int(moltcbor.EntryTypeChannelLeave),
		int(moltcbor.EntryTypeMemberInvite),
		int(moltcbor.EntryTypeMemberRemove),
		int(moltcbor.EntryTypeAdminPromote),
		int(moltcbor.EntryTypeAdminDemote),
		int(moltcbor.EntryTypeChannelArchive),
		int(moltcbor.EntryTypeChannelUnarchive),
	}

	var allEntries []*store.RawEntry
	for _, t := range types {
		entries, err := c.logDB.EntriesByType(t)
		if err != nil {
			c.log.Warn("replay channel state: query failed", map[string]any{
				"type":  t,
				"error": err.Error(),
			})
			continue
		}
		allEntries = append(allEntries, entries...)
	}

	// Sort by (created_at, then hash) to maintain causal order.
	// Two entries within the same second (e.g., ChannelCreate + ChannelJoin)
	// must be deterministically ordered to prevent silent membership drops.
	sort.Slice(allEntries, func(i, j int) bool {
		if allEntries[i].CreatedAt != allEntries[j].CreatedAt {
			return allEntries[i].CreatedAt < allEntries[j].CreatedAt
		}
		return bytes.Compare(allEntries[i].Hash, allEntries[j].Hash) < 0
	})

	channels, members := 0, 0
	for _, raw := range allEntries {
		switch moltcbor.EntryType(raw.EntryType) {
		case moltcbor.EntryTypeChannelCreate:
			if c.replayChannelCreate(raw) {
				channels++
			}
		case moltcbor.EntryTypeChannelJoin:
			if c.replayChannelMembership(raw, true) {
				members++
			}
		case moltcbor.EntryTypeChannelLeave:
			c.replayChannelMembership(raw, false)
		case moltcbor.EntryTypeMemberInvite:
			if c.replayMemberInviteRemove(raw, true) {
				members++
			}
		case moltcbor.EntryTypeMemberRemove:
			c.replayMemberInviteRemove(raw, false)
		case moltcbor.EntryTypeAdminPromote:
			c.replayAdminChange(raw, true)
		case moltcbor.EntryTypeAdminDemote:
			c.replayAdminChange(raw, false)
		case moltcbor.EntryTypeChannelArchive:
			c.replayArchive(raw, true)
		case moltcbor.EntryTypeChannelUnarchive:
			c.replayArchive(raw, false)
		}
	}

	// Second pass: retry membership entries that may have been dropped because
	// the channel didn't exist yet (same-second ChannelCreate + ChannelJoin).
	for _, raw := range allEntries {
		switch moltcbor.EntryType(raw.EntryType) {
		case moltcbor.EntryTypeChannelJoin:
			c.replayChannelMembership(raw, true)
		case moltcbor.EntryTypeMemberInvite:
			c.replayMemberInviteRemove(raw, true)
		}
	}

	// Permanent channels: all registered agents are members automatically
	allAgents := c.registry.All()
	for _, ch := range c.channels.All() {
		if ch.Type == moltcbor.ChannelTypePermanent {
			for _, agent := range allAgents {
				ch.AddMember(agent.PublicKey)
			}
		}
	}

	if channels > 0 || members > 0 {
		c.log.Info("replayed channel state", map[string]any{
			"channels": channels,
			"members":  members,
		})
	}
}

func (c *Connector) replayChannelCreate(raw *store.RawEntry) bool {
	payload := decodePayload(raw)
	if payload == nil {
		return false
	}

	var cc moltcbor.ChannelCreate
	if err := moltcbor.Unmarshal(payload, &cc); err != nil {
		return false
	}

	// Validate channel type
	switch cc.ChannelType {
	case moltcbor.ChannelTypePermanent, moltcbor.ChannelTypePublic, moltcbor.ChannelTypePrivate,
		moltcbor.ChannelTypeDM, moltcbor.ChannelTypeGroupDM:
		// valid
	default:
		return false
	}

	ch := &channel.Channel{
		ID:          cc.ChannelID,
		Name:        cc.Name,
		Description: cc.Description,
		Type:        cc.ChannelType,
		Members:     make(map[string]bool),
		Admins:      make(map[string]bool),
		Creator:     raw.AuthorKey,
	}

	// For channel types with initial members
	for _, member := range cc.Members {
		ch.AddMember(member)
	}

	// Creator is always a member and admin
	ch.AddMember(raw.AuthorKey)
	ch.Admins[fmt.Sprintf("%x", raw.AuthorKey)] = true

	// Permanent channels: all agents auto-join (handled by join entries)
	if err := c.channels.Create(ch); err != nil {
		// Channel may already exist (duplicate replay), skip silently
		return false
	}
	return true
}

func (c *Connector) replayChannelMembership(raw *store.RawEntry, isJoin bool) bool {
	payload := decodePayload(raw)
	if payload == nil {
		return false
	}

	var cm moltcbor.ChannelMembership
	if err := moltcbor.Unmarshal(payload, &cm); err != nil {
		return false
	}

	ch := c.channels.Get(cm.ChannelID)
	if ch == nil {
		return false
	}

	if isJoin {
		ch.AddMember(raw.AuthorKey) // signer is the joining agent
		return true
	}
	ch.RemoveMember(raw.AuthorKey) // signer is the leaving agent
	return false
}

func (c *Connector) replayMemberInviteRemove(raw *store.RawEntry, isInvite bool) bool {
	payload := decodePayload(raw)
	if payload == nil {
		return false
	}

	var cm moltcbor.ChannelMembership
	if err := moltcbor.Unmarshal(payload, &cm); err != nil {
		return false
	}

	ch := c.channels.Get(cm.ChannelID)
	if ch == nil {
		return false
	}

	if isInvite {
		ch.AddMember(cm.AgentKey) // AgentKey is the invitee
		return true
	}
	ch.RemoveMember(cm.AgentKey) // AgentKey is the removed agent
	return false
}

func (c *Connector) replayAdminChange(raw *store.RawEntry, isPromote bool) {
	payload := decodePayload(raw)
	if payload == nil {
		return
	}

	var ac moltcbor.AdminChange
	if err := moltcbor.Unmarshal(payload, &ac); err != nil {
		return
	}

	ch := c.channels.Get(ac.ChannelID)
	if ch == nil {
		return
	}

	if isPromote {
		ch.PromoteAdmin(ac.AgentKey)
	} else {
		ch.DemoteAdmin(ac.AgentKey)
	}
}

func (c *Connector) replayArchive(raw *store.RawEntry, isArchive bool) {
	payload := decodePayload(raw)
	if payload == nil {
		return
	}

	var ca moltcbor.ChannelArchive
	if err := moltcbor.Unmarshal(payload, &ca); err != nil {
		return
	}

	ch := c.channels.Get(ca.ChannelID)
	if ch == nil {
		return
	}

	ch.Archived = isArchive
}

// replayGroupKeyDistributes processes GroupKeyDistribute entries from the log,
// extracting and storing group keys for private channels targeted at this agent.
// Without this, private channel invites are broken — the agent receives the entry
// via gossip but never extracts the group key from the sealed payload.
func (c *Connector) replayGroupKeyDistributes() {
	entries, err := c.logDB.EntriesByType(int(moltcbor.EntryTypeGroupKeyDistribute))
	if err != nil {
		c.log.Warn("replay group key distributes: query failed", map[string]any{"error": err.Error()})
		return
	}

	stored := 0
	for _, raw := range entries {
		payload := decodePayload(raw)
		if payload == nil {
			continue
		}

		var dist moltcbor.GroupKeyDistribute
		if err := moltcbor.Unmarshal(payload, &dist); err != nil {
			continue
		}

		// Only process entries targeted at us
		if !crypto.ConstantTimeEqual(dist.TargetPubKey, c.keyPair.Public) {
			continue
		}

		// Check if we already have a key at this epoch or newer
		_, existingEpoch, _ := c.keyDB.GetGroupKey(dist.ChannelID)
		if existingEpoch >= int(dist.Epoch) {
			continue
		}

		// Decrypt the sealed group key using our pairwise secret with the sender
		secret, _, err := c.keyDB.GetPairwiseSecret(raw.AuthorKey)
		if err != nil || secret == nil {
			c.log.Warn("replay group key distribute: no pairwise secret for sender", map[string]any{
				"sender": fmt.Sprintf("%x", raw.AuthorKey[:8]),
			})
			continue
		}

		var secretArr [32]byte
		copy(secretArr[:], secret)
		decrypted, err := crypto.OpenFromPeer(secretArr, dist.Sealed)
		if err != nil {
			c.log.Warn("replay group key distribute: decrypt failed", map[string]any{
				"sender": fmt.Sprintf("%x", raw.AuthorKey[:8]),
				"error":  err.Error(),
			})
			continue
		}

		// Try to verify channel/epoch binding (P3 fix).
		// Fall back to raw 32-byte key for backward compatibility with
		// entries sealed before the binding was added.
		var groupKeyBytes []byte
		if bound, err := unsealGroupKeyWithBinding(dist.ChannelID, dist.Epoch, decrypted); err == nil {
			groupKeyBytes = bound
		} else if len(decrypted) == 32 {
			// Legacy format: just the raw group key
			groupKeyBytes = decrypted
		} else {
			c.log.Warn("replay group key distribute: invalid payload", map[string]any{
				"length": len(decrypted),
			})
			continue
		}

		if err := c.keyDB.SetGroupKey(dist.ChannelID, int(dist.Epoch), groupKeyBytes); err != nil {
			c.log.Warn("replay group key distribute: store failed", map[string]any{
				"error": err.Error(),
			})
			continue
		}
		stored++
	}

	if stored > 0 {
		c.log.Info("replayed group key distributes", map[string]any{"count": stored})
	}
}

// replayPairwiseKeyExchanges processes PairwiseKeyExchange entries from the log
// to handle key rotations that occurred while offline.
func (c *Connector) replayPairwiseKeyExchanges() {
	entries, err := c.logDB.EntriesByType(int(moltcbor.EntryTypePairwiseKeyExchange))
	if err != nil {
		c.log.Warn("replay pairwise exchanges: query failed", map[string]any{"error": err.Error()})
		return
	}

	processed := 0
	for _, raw := range entries {
		payload := decodePayload(raw)
		if payload == nil {
			continue
		}

		var exchange moltcbor.PairwiseKeyExchange
		if err := moltcbor.Unmarshal(payload, &exchange); err != nil {
			continue
		}

		c.processPairwiseKeyExchange(raw.AuthorKey, &exchange)
		processed++
	}

	if processed > 0 {
		c.log.Info("replayed pairwise key exchanges", map[string]any{"count": processed})
	}
}

// --- Decoding helpers ---

// decodePayload extracts the inner payload bytes from a raw log entry.
// Entry structure: SignableWrapper { Parents, Envelope bytes, Time }
// Envelope: { Version, Type, Payload bytes }
func decodePayload(raw *store.RawEntry) []byte {
	var sigData struct {
		Parents  [][]byte `cbor:"1,keyasint"`
		Envelope []byte   `cbor:"2,keyasint"`
		Time     int64    `cbor:"3,keyasint"`
	}
	if err := moltcbor.Unmarshal(raw.RawCBOR, &sigData); err != nil {
		return nil
	}

	var env moltcbor.Envelope
	if err := moltcbor.Unmarshal(sigData.Envelope, &env); err != nil {
		return nil
	}

	return env.Payload
}

func decodeRevocationEntry(raw *store.RawEntry) *moltcbor.Revocation {
	payload := decodePayload(raw)
	if payload == nil {
		return nil
	}

	var rev moltcbor.Revocation
	if err := moltcbor.Unmarshal(payload, &rev); err != nil {
		return nil
	}
	return &rev
}

func decodeOrgRelationshipEntry(raw *store.RawEntry) *moltcbor.OrgRelationship {
	payload := decodePayload(raw)
	if payload == nil {
		return nil
	}

	var rel moltcbor.OrgRelationship
	if err := moltcbor.Unmarshal(payload, &rel); err != nil {
		return nil
	}

	// Only load fully signed relationships (both sigs present)
	if len(rel.SubjectSig) == 0 || len(rel.ManagerSig) == 0 {
		return nil
	}

	return &rel
}

// FindAgentByKeyHash looks up an agent by the BLAKE3 hash of their public key.
func (c *Connector) FindAgentByKeyHash(keyHash []byte) *identity.Agent {
	hashHex := hex.EncodeToString(keyHash)
	for _, agent := range c.registry.All() {
		h := crypto.Hash(agent.PublicKey)
		if hex.EncodeToString(h[:]) == hashHex {
			return agent
		}
	}
	return nil
}
