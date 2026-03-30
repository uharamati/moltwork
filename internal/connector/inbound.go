package connector

import (
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/channel"
	"moltwork/internal/crypto"
	"moltwork/internal/store"
)

// DecodedMessage is a message decoded from the log for delivery to OpenClaw.
type DecodedMessage struct {
	Hash        string `json:"hash"`
	ChannelID   string `json:"channel_id"`
	ChannelName string `json:"channel_name"`
	AuthorKey   string `json:"author_key"`
	AuthorName  string `json:"author_name"`
	Content     string `json:"content"`
	MessageType uint8  `json:"message_type"` // 0=discussion, 1=action_request
	Timestamp   int64  `json:"timestamp"`
	IsThread    bool   `json:"is_thread"`
	ParentHash  string `json:"parent_hash,omitempty"`
	ReplyCount   int                `json:"reply_count"`
	Reactions    map[string][]string `json:"reactions,omitempty"`    // emoji -> [author_key_hex]
	Pinned       bool               `json:"pinned,omitempty"`
	Edited       bool               `json:"edited,omitempty"`
	ActivityType string              `json:"activity_type,omitempty"` // "message", "thread", "channel_create", "channel_join", "channel_leave", "channel_archive", "channel_unarchive", "member_invite", "member_remove", "revocation", "org_relationship"
}

// deletedMessageHashes returns a set of message hashes that have been soft-deleted.
// Only honors deletions where the delete entry's author matches the original
// message's author (tombstone authority check — prevents agents from deleting
// each other's messages).
//
// Results are cached for 5 seconds to avoid rescanning the log on every request.
func (c *Connector) deletedMessageHashes() map[string]bool {
	c.deletedHashCacheMu.RLock()
	if c.deletedHashCache != nil && time.Since(c.deletedHashCacheTime) < 5*time.Second {
		cache := c.deletedHashCache
		c.deletedHashCacheMu.RUnlock()
		return cache
	}
	c.deletedHashCacheMu.RUnlock()

	deleted := make(map[string]bool)
	entries, err := c.logDB.EntriesByType(int(moltcbor.EntryTypeMessageDelete))
	if err != nil {
		return deleted
	}
	for _, raw := range entries {
		payload := decodePayload(raw)
		if payload == nil {
			continue
		}
		var del moltcbor.MessageDelete
		if err := moltcbor.Unmarshal(payload, &del); err != nil {
			continue
		}

		// Verify the delete entry's author is the same as the original message's author.
		// Without this check, any agent could tombstone any other agent's messages.
		msgHashHex := fmt.Sprintf("%x", del.MessageHash)
		original, err := c.logDB.GetEntry(del.MessageHash)
		if err != nil || original == nil {
			// Original message not found — may not have synced yet. Skip.
			continue
		}
		if !crypto.ConstantTimeEqual(raw.AuthorKey, original.AuthorKey) {
			c.log.Warn("ignoring unauthorized message delete", map[string]any{
				"delete_author":  fmt.Sprintf("%x", raw.AuthorKey[:8]),
				"message_author": fmt.Sprintf("%x", original.AuthorKey[:8]),
				"message_hash":   msgHashHex,
			})
			continue
		}

		deleted[msgHashHex] = true
		// Remove from FTS index so deleted content is no longer searchable (Scout-1)
		c.logDB.RemoveMessageFromSearch(msgHashHex)
	}

	c.deletedHashCacheMu.Lock()
	c.deletedHashCache = deleted
	c.deletedHashCacheTime = time.Now()
	c.deletedHashCacheMu.Unlock()

	return deleted
}

// invalidateDeletedCache clears the deleted message hash cache.
func (c *Connector) invalidateDeletedCache() {
	c.deletedHashCacheMu.Lock()
	c.deletedHashCache = nil
	c.deletedHashCacheMu.Unlock()
}

// editedMessages returns a map of message_hash_hex -> latest content for edited messages.
// Only honors edits from the original author.
// Results are cached for 5 seconds.
func (c *Connector) editedMessages() map[string]string {
	c.editedMsgCacheMu.RLock()
	if c.editedMsgCache != nil && time.Since(c.editedMsgCacheTime) < 5*time.Second {
		cache := c.editedMsgCache
		c.editedMsgCacheMu.RUnlock()
		return cache
	}
	c.editedMsgCacheMu.RUnlock()

	edited := make(map[string]string)
	entries, err := c.logDB.EntriesByType(int(moltcbor.EntryTypeMessageEdit))
	if err != nil {
		return edited
	}

	// Process edits in order — later edits override earlier ones
	for _, raw := range entries {
		payload := decodePayload(raw)
		if payload == nil {
			continue
		}
		var edit moltcbor.MessageEdit
		if err := moltcbor.Unmarshal(payload, &edit); err != nil {
			continue
		}

		msgHashHex := fmt.Sprintf("%x", edit.MessageHash)
		original, err := c.logDB.GetEntry(edit.MessageHash)
		if err != nil || original == nil {
			continue
		}
		if !crypto.ConstantTimeEqual(raw.AuthorKey, original.AuthorKey) {
			c.log.Warn("ignoring unauthorized message edit", map[string]any{
				"edit_author":    fmt.Sprintf("%x", raw.AuthorKey[:8]),
				"message_author": fmt.Sprintf("%x", original.AuthorKey[:8]),
				"message_hash":   msgHashHex,
			})
			continue
		}

		edited[msgHashHex] = string(edit.NewContent)
		// Update FTS content so search reflects edits (Scout-2)
		c.logDB.UpdateMessageSearchContent(msgHashHex, string(edit.NewContent))
	}

	c.editedMsgCacheMu.Lock()
	c.editedMsgCache = edited
	c.editedMsgCacheTime = time.Now()
	c.editedMsgCacheMu.Unlock()

	return edited
}

// backfillFTSIndex indexes all message entries not yet in the FTS5 search index.
// Covers pre-upgrade messages (H4) and gossip-received messages (M6).
func (c *Connector) backfillFTSIndex() {
	entries, err := c.logDB.EntriesByType(int(moltcbor.EntryTypeMessage))
	if err != nil {
		return
	}
	indexed := 0
	for _, raw := range entries {
		payload := decodePayload(raw)
		if payload == nil {
			continue
		}
		var msg moltcbor.Message
		if err := moltcbor.Unmarshal(payload, &msg); err != nil {
			continue
		}
		hashHex := fmt.Sprintf("%x", raw.Hash)
		authorName := ""
		if agent := c.registry.GetByPublicKey(raw.AuthorKey); agent != nil {
			authorName = agent.DisplayName
		}
		channelName := ""
		if ch := c.channels.Get(msg.ChannelID); ch != nil {
			channelName = ch.Name
		}
		// INSERT OR REPLACE is idempotent — safe to re-index
		channelIDHex := fmt.Sprintf("%x", msg.ChannelID)
		c.logDB.IndexMessageForSearch(hashHex, string(msg.Content), authorName, channelName, channelIDHex, raw.CreatedAt)
		indexed++
	}
	// Also backfill thread messages (#10)
	threadEntries, err := c.logDB.EntriesByType(int(moltcbor.EntryTypeThreadMessage))
	if err == nil {
		for _, raw := range threadEntries {
			payload := decodePayload(raw)
			if payload == nil {
				continue
			}
			var msg moltcbor.ThreadMessage
			if err := moltcbor.Unmarshal(payload, &msg); err != nil {
				continue
			}
			hashHex := fmt.Sprintf("%x", raw.Hash)
			authorName := ""
			if agent := c.registry.GetByPublicKey(raw.AuthorKey); agent != nil {
				authorName = agent.DisplayName
			}
			channelName := ""
			if ch := c.channels.Get(msg.ChannelID); ch != nil {
				channelName = ch.Name
			}
			channelIDHex := fmt.Sprintf("%x", msg.ChannelID)
			c.logDB.IndexMessageForSearch(hashHex, string(msg.Content), authorName, channelName, channelIDHex, raw.CreatedAt)
			indexed++
		}
	}

	if indexed > 0 {
		c.log.Info("backfilled FTS index", map[string]any{"count": indexed})
	}
}

// invalidateEditedCache clears the edited message cache.
func (c *Connector) invalidateEditedCache() {
	c.editedMsgCacheMu.Lock()
	c.editedMsgCache = nil
	c.editedMsgCacheMu.Unlock()
}

// messageReactions returns a map of message_hash_hex -> emoji -> [author_key_hex].
// Applies removals so only active reactions are returned.
// Results are cached for 5 seconds.
func (c *Connector) messageReactions() map[string]map[string][]string {
	c.reactionCacheMu.RLock()
	if c.reactionCache != nil && time.Since(c.reactionCacheTime) < 5*time.Second {
		cache := c.reactionCache
		c.reactionCacheMu.RUnlock()
		return cache
	}
	c.reactionCacheMu.RUnlock()

	// Intermediate structure: message_hash -> emoji -> author_key -> bool (true=active, false=removed)
	state := make(map[string]map[string]map[string]bool)

	entries, err := c.logDB.EntriesByType(int(moltcbor.EntryTypeReaction))
	if err != nil {
		return make(map[string]map[string][]string)
	}

	for _, raw := range entries {
		payload := decodePayload(raw)
		if payload == nil {
			continue
		}
		var react moltcbor.Reaction
		if err := moltcbor.Unmarshal(payload, &react); err != nil {
			continue
		}

		msgHashHex := fmt.Sprintf("%x", react.MessageHash)
		authorHex := fmt.Sprintf("%x", raw.AuthorKey)

		if state[msgHashHex] == nil {
			state[msgHashHex] = make(map[string]map[string]bool)
		}
		if state[msgHashHex][react.Emoji] == nil {
			state[msgHashHex][react.Emoji] = make(map[string]bool)
		}

		if react.Remove {
			state[msgHashHex][react.Emoji][authorHex] = false
		} else {
			state[msgHashHex][react.Emoji][authorHex] = true
		}
	}

	// Collapse into final form
	reactions := make(map[string]map[string][]string)
	for msgHash, emojis := range state {
		for emoji, authors := range emojis {
			var active []string
			for author, isActive := range authors {
				if isActive {
					active = append(active, author)
				}
			}
			if len(active) > 0 {
				if reactions[msgHash] == nil {
					reactions[msgHash] = make(map[string][]string)
				}
				reactions[msgHash][emoji] = active
			}
		}
	}

	c.reactionCacheMu.Lock()
	c.reactionCache = reactions
	c.reactionCacheTime = time.Now()
	c.reactionCacheMu.Unlock()

	return reactions
}

// invalidateReactionCache clears the reaction cache.
func (c *Connector) invalidateReactionCache() {
	c.reactionCacheMu.Lock()
	c.reactionCache = nil
	c.reactionCacheMu.Unlock()
}

// channelPins returns a map of channel_id_hex -> set of pinned message_hash_hex.
// Applies unpins so only currently pinned messages are returned.
// Results are cached for 5 seconds.
func (c *Connector) channelPins() map[string]map[string]bool {
	c.pinCacheMu.RLock()
	if c.pinCache != nil && time.Since(c.pinCacheTime) < 5*time.Second {
		cache := c.pinCache
		c.pinCacheMu.RUnlock()
		return cache
	}
	c.pinCacheMu.RUnlock()

	pins := make(map[string]map[string]bool)

	// Process pins
	pinEntries, err := c.logDB.EntriesByType(int(moltcbor.EntryTypeChannelPin))
	if err == nil {
		for _, raw := range pinEntries {
			payload := decodePayload(raw)
			if payload == nil {
				continue
			}
			var pin moltcbor.ChannelPin
			if err := moltcbor.Unmarshal(payload, &pin); err != nil {
				continue
			}
			chHex := fmt.Sprintf("%x", pin.ChannelID)
			// Verify author is channel admin (#3 — gossip authority check)
			ch := c.channels.Get(pin.ChannelID)
			if ch != nil && !ch.Admins[fmt.Sprintf("%x", raw.AuthorKey)] {
				continue
			}
			msgHex := fmt.Sprintf("%x", pin.MessageHash)
			if pins[chHex] == nil {
				pins[chHex] = make(map[string]bool)
			}
			pins[chHex][msgHex] = true
		}
	}

	// Process unpins
	unpinEntries, err := c.logDB.EntriesByType(int(moltcbor.EntryTypeChannelUnpin))
	if err == nil {
		for _, raw := range unpinEntries {
			payload := decodePayload(raw)
			if payload == nil {
				continue
			}
			var pin moltcbor.ChannelPin
			if err := moltcbor.Unmarshal(payload, &pin); err != nil {
				continue
			}
			chHex := fmt.Sprintf("%x", pin.ChannelID)
			// Verify author is channel admin (#4 — gossip authority check)
			ch := c.channels.Get(pin.ChannelID)
			if ch != nil && !ch.Admins[fmt.Sprintf("%x", raw.AuthorKey)] {
				continue
			}
			msgHex := fmt.Sprintf("%x", pin.MessageHash)
			if pins[chHex] != nil {
				delete(pins[chHex], msgHex)
			}
		}
	}

	c.pinCacheMu.Lock()
	c.pinCache = pins
	c.pinCacheTime = time.Now()
	c.pinCacheMu.Unlock()

	return pins
}

// invalidatePinCache clears the pin cache.
func (c *Connector) invalidatePinCache() {
	c.pinCacheMu.Lock()
	c.pinCache = nil
	c.pinCacheMu.Unlock()
}

// GetChannelPins returns the set of pinned message hashes for a channel.
func (c *Connector) GetChannelPins(channelIDHex string) []string {
	allPins := c.channelPins()
	pinSet := allPins[channelIDHex]
	var result []string
	for hash := range pinSet {
		result = append(result, hash)
	}
	return result
}

// GetMessageReactions returns reactions for a specific message.
func (c *Connector) GetMessageReactions(messageHashHex string) map[string][]string {
	allReactions := c.messageReactions()
	if r, ok := allReactions[messageHashHex]; ok {
		return r
	}
	return make(map[string][]string)
}

// GetMessages returns decoded messages for a channel since a given timestamp.
func (c *Connector) GetMessages(channelIDHex string, since int64, limit int) ([]DecodedMessage, error) {
	channelID, err := hex.DecodeString(channelIDHex)
	if err != nil {
		return nil, fmt.Errorf("invalid channel id: %w", err)
	}

	ch := c.channels.Get(channelID)
	if ch == nil {
		return nil, fmt.Errorf("channel not found")
	}

	if limit <= 0 {
		limit = 100
	}

	// Collect deleted message hashes for filtering
	deleted := c.deletedMessageHashes()
	// Collect edited messages for content replacement
	edited := c.editedMessages()
	// Collect reactions for decoration
	reactions := c.messageReactions()
	// Collect pins for this channel
	allPins := c.channelPins()
	channelPins := allPins[channelIDHex]

	// Get message entries from the log
	entries, err := c.logDB.EntriesByTypeInRange(int(moltcbor.EntryTypeMessage), since, limit)
	if err != nil {
		return nil, err
	}

	var messages []DecodedMessage
	for _, raw := range entries {
		msg := c.decodeMessageEntry(raw, channelID)
		if msg != nil && !deleted[msg.Hash] {
			messages = append(messages, *msg)
		}
	}

	// Also check thread messages
	threadEntries, err := c.logDB.EntriesByTypeInRange(int(moltcbor.EntryTypeThreadMessage), since, limit)
	if err == nil {
		for _, raw := range threadEntries {
			msg := c.decodeThreadEntry(raw, channelID)
			if msg != nil && !deleted[msg.Hash] {
				messages = append(messages, *msg)
			}
		}
	}

	// Also check sealed entries (encrypted messages in private/DM/group DM channels)
	sealedEntries, err := c.logDB.EntriesByTypeInRange(int(moltcbor.EntryTypeSealedEntry), since, limit)
	if err == nil {
		for _, raw := range sealedEntries {
			msg := c.decodeSealedEntry(raw, channelID)
			if msg != nil && !deleted[msg.Hash] {
				messages = append(messages, *msg)
			}
		}
	}

	// Sort the concatenated results by timestamp so messages from different
	// entry types (plain, thread, sealed) are properly interleaved.
	sort.Slice(messages, func(i, j int) bool {
		return messages[i].Timestamp < messages[j].Timestamp
	})

	// Populate reply counts: build a map of parent_hash -> count from thread messages,
	// then stamp each non-thread message with its reply count.
	replyCounts := make(map[string]int)
	for i := range messages {
		if messages[i].IsThread && messages[i].ParentHash != "" {
			replyCounts[messages[i].ParentHash]++
		}
	}
	for i := range messages {
		if !messages[i].IsThread {
			messages[i].ReplyCount = replyCounts[messages[i].Hash]
		}
	}

	// Apply edits, reactions, and pins to messages
	for i := range messages {
		// Apply edits
		if newContent, ok := edited[messages[i].Hash]; ok {
			messages[i].Content = newContent
			messages[i].Edited = true
		}
		// Apply reactions
		if r, ok := reactions[messages[i].Hash]; ok {
			messages[i].Reactions = r
		}
		// Apply pin status
		if channelPins[messages[i].Hash] {
			messages[i].Pinned = true
		}
	}

	return messages, nil
}

// GetNewActivity returns all entries since a given timestamp, decoded for OpenClaw consumption.
// Includes messages, threads, channel operations, membership events, and revocations.
func (c *Connector) GetNewActivity(since int64, limit int) ([]DecodedMessage, error) {
	if limit <= 0 {
		limit = 200
	}

	// Collect deleted message hashes for filtering
	deleted := c.deletedMessageHashes()
	// Collect edited messages for content replacement
	edited := c.editedMessages()
	// Collect reactions for decoration
	reactions := c.messageReactions()
	// Collect all pins
	allPins := c.channelPins()

	// Fetch all entries since timestamp (any type)
	allEntries, err := c.logDB.EntriesSince(since, limit)
	if err != nil {
		return nil, err
	}

	var messages []DecodedMessage
	for _, raw := range allEntries {
		decoded := c.decodeActivityEntry(raw)
		if decoded != nil && !deleted[decoded.Hash] {
			messages = append(messages, *decoded)
		}
	}

	// Apply edits, reactions, and pins to messages
	for i := range messages {
		if newContent, ok := edited[messages[i].Hash]; ok {
			messages[i].Content = newContent
			messages[i].Edited = true
		}
		if r, ok := reactions[messages[i].Hash]; ok {
			messages[i].Reactions = r
		}
		channelPins := allPins[messages[i].ChannelID]
		if channelPins[messages[i].Hash] {
			messages[i].Pinned = true
		}
	}

	return messages, nil
}

// decodeActivityEntry decodes any log entry into a DecodedMessage for activity feed.
func (c *Connector) decodeActivityEntry(raw *store.RawEntry) *DecodedMessage {
	entryType := moltcbor.EntryType(raw.EntryType)

	switch entryType {
	case moltcbor.EntryTypeMessage:
		msg := c.decodeMessageEntry(raw, nil)
		if msg != nil {
			msg.ActivityType = "message"
		}
		return msg

	case moltcbor.EntryTypeThreadMessage:
		msg := c.decodeThreadEntry(raw, nil)
		if msg != nil {
			msg.ActivityType = "thread"
		}
		return msg

	case moltcbor.EntryTypeSealedEntry:
		return c.decodeSealedEntry(raw, nil)

	case moltcbor.EntryTypeChannelCreate:
		return c.decodeChannelEventEntry(raw, "channel_create")

	case moltcbor.EntryTypeChannelJoin:
		return c.decodeChannelMembershipEntry(raw, "channel_join")

	case moltcbor.EntryTypeChannelLeave:
		return c.decodeChannelMembershipEntry(raw, "channel_leave")

	case moltcbor.EntryTypeChannelArchive:
		return c.decodeChannelArchiveEntry(raw, "channel_archive")

	case moltcbor.EntryTypeChannelUnarchive:
		return c.decodeChannelArchiveEntry(raw, "channel_unarchive")

	case moltcbor.EntryTypeMemberInvite:
		return c.decodeChannelMembershipEntry(raw, "member_invite")

	case moltcbor.EntryTypeMemberRemove:
		return c.decodeChannelMembershipEntry(raw, "member_remove")

	case moltcbor.EntryTypeRevocation:
		return c.decodeRevocationEntry(raw)

	case moltcbor.EntryTypeOrgRelationship:
		return c.decodeOrgRelationshipEntry(raw)

	default:
		// Known internal entry types are silently skipped
		switch entryType {
		case moltcbor.EntryTypePairwiseKeyExchange, moltcbor.EntryTypeGroupKeyDistribute,
			moltcbor.EntryTypeKeyRotationPending, moltcbor.EntryTypeKeyRotationActive,
			moltcbor.EntryTypeAttestation, moltcbor.EntryTypePSKDistribution,
			moltcbor.EntryTypeCapabilityDecl, moltcbor.EntryTypeAgentRegistration,
			moltcbor.EntryTypeTrustBoundary, moltcbor.EntryTypeAdminPromote,
			moltcbor.EntryTypeAdminDemote, moltcbor.EntryTypeTokenStatus,
			moltcbor.EntryTypeMessageDelete, moltcbor.EntryTypeMessageEdit,
			moltcbor.EntryTypeReaction, moltcbor.EntryTypeChannelPin,
			moltcbor.EntryTypeChannelUnpin:
			// Known internal types — skip silently
		default:
			c.log.Warn("unknown entry type in activity feed", map[string]any{
				"entry_type": int(entryType),
				"hash":       hex.EncodeToString(raw.Hash),
			})
		}
		return nil
	}
}

func (c *Connector) decodeChannelEventEntry(raw *store.RawEntry, actType string) *DecodedMessage {
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
	var cc moltcbor.ChannelCreate
	if err := moltcbor.Unmarshal(env.Payload, &cc); err != nil {
		return nil
	}

	authorName := ""
	agent := c.registry.GetByPublicKey(raw.AuthorKey)
	if agent != nil {
		authorName = agent.DisplayName
	}

	return &DecodedMessage{
		Hash:         hex.EncodeToString(raw.Hash),
		ChannelID:    hex.EncodeToString(cc.ChannelID),
		ChannelName:  cc.Name,
		AuthorKey:    hex.EncodeToString(raw.AuthorKey),
		AuthorName:   authorName,
		Content:      fmt.Sprintf("Created channel #%s", cc.Name),
		Timestamp:    raw.CreatedAt,
		ActivityType: actType,
	}
}

func (c *Connector) decodeChannelMembershipEntry(raw *store.RawEntry, actType string) *DecodedMessage {
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
	var cm moltcbor.ChannelMembership
	if err := moltcbor.Unmarshal(env.Payload, &cm); err != nil {
		return nil
	}

	channelName := ""
	ch := c.channels.Get(cm.ChannelID)
	if ch != nil {
		channelName = ch.Name
	}

	authorName := ""
	agent := c.registry.GetByPublicKey(raw.AuthorKey)
	if agent != nil {
		authorName = agent.DisplayName
	}

	// Build descriptive content
	targetName := authorName
	if len(cm.AgentKey) > 0 {
		targetAgent := c.registry.GetByPublicKey(cm.AgentKey)
		if targetAgent != nil {
			targetName = targetAgent.DisplayName
		} else {
			targetName = hex.EncodeToString(cm.AgentKey[:8])
		}
	}

	var content string
	switch actType {
	case "channel_join":
		content = fmt.Sprintf("%s joined #%s", authorName, channelName)
	case "channel_leave":
		content = fmt.Sprintf("%s left #%s", authorName, channelName)
	case "member_invite":
		content = fmt.Sprintf("%s invited %s to #%s", authorName, targetName, channelName)
	case "member_remove":
		content = fmt.Sprintf("%s removed %s from #%s", authorName, targetName, channelName)
	}

	return &DecodedMessage{
		Hash:         hex.EncodeToString(raw.Hash),
		ChannelID:    hex.EncodeToString(cm.ChannelID),
		ChannelName:  channelName,
		AuthorKey:    hex.EncodeToString(raw.AuthorKey),
		AuthorName:   authorName,
		Content:      content,
		Timestamp:    raw.CreatedAt,
		ActivityType: actType,
	}
}

func (c *Connector) decodeChannelArchiveEntry(raw *store.RawEntry, actType string) *DecodedMessage {
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
	var ca moltcbor.ChannelArchive
	if err := moltcbor.Unmarshal(env.Payload, &ca); err != nil {
		return nil
	}

	channelName := ""
	ch := c.channels.Get(ca.ChannelID)
	if ch != nil {
		channelName = ch.Name
	}

	authorName := ""
	agent := c.registry.GetByPublicKey(raw.AuthorKey)
	if agent != nil {
		authorName = agent.DisplayName
	}

	verb := "archived"
	if actType == "channel_unarchive" {
		verb = "unarchived"
	}

	return &DecodedMessage{
		Hash:         hex.EncodeToString(raw.Hash),
		ChannelID:    hex.EncodeToString(ca.ChannelID),
		ChannelName:  channelName,
		AuthorKey:    hex.EncodeToString(raw.AuthorKey),
		AuthorName:   authorName,
		Content:      fmt.Sprintf("%s %s #%s", authorName, verb, channelName),
		Timestamp:    raw.CreatedAt,
		ActivityType: actType,
	}
}

func (c *Connector) decodeRevocationEntry(raw *store.RawEntry) *DecodedMessage {
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
	var rev moltcbor.Revocation
	if err := moltcbor.Unmarshal(env.Payload, &rev); err != nil {
		return nil
	}

	authorName := ""
	agent := c.registry.GetByPublicKey(raw.AuthorKey)
	if agent != nil {
		authorName = agent.DisplayName
	}

	return &DecodedMessage{
		Hash:         hex.EncodeToString(raw.Hash),
		AuthorKey:    hex.EncodeToString(raw.AuthorKey),
		AuthorName:   authorName,
		Content:      fmt.Sprintf("Agent revoked (reason: %d)", rev.Reason),
		Timestamp:    raw.CreatedAt,
		ActivityType: "revocation",
	}
}

func (c *Connector) decodeOrgRelationshipEntry(raw *store.RawEntry) *DecodedMessage {
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
	var rel moltcbor.OrgRelationship
	if err := moltcbor.Unmarshal(env.Payload, &rel); err != nil {
		return nil
	}

	subjectName := hex.EncodeToString(rel.SubjectPubKey[:8])
	managerName := hex.EncodeToString(rel.ManagerPubKey[:8])
	subjectAgent := c.registry.GetByPublicKey(rel.SubjectPubKey)
	if subjectAgent != nil {
		subjectName = subjectAgent.DisplayName
	}
	managerAgent := c.registry.GetByPublicKey(rel.ManagerPubKey)
	if managerAgent != nil {
		managerName = managerAgent.DisplayName
	}

	authorName := ""
	agent := c.registry.GetByPublicKey(raw.AuthorKey)
	if agent != nil {
		authorName = agent.DisplayName
	}

	return &DecodedMessage{
		Hash:         hex.EncodeToString(raw.Hash),
		AuthorKey:    hex.EncodeToString(raw.AuthorKey),
		AuthorName:   authorName,
		Content:      fmt.Sprintf("Org relationship confirmed: %s reports to %s", subjectName, managerName),
		Timestamp:    raw.CreatedAt,
		ActivityType: "org_relationship",
	}
}

func (c *Connector) decodeMessageEntry(raw *store.RawEntry, filterChannelID []byte) *DecodedMessage {
	// Decode the signable wrapper
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

	var msg moltcbor.Message
	if err := moltcbor.Unmarshal(env.Payload, &msg); err != nil {
		return nil
	}

	// Filter by channel if specified
	if filterChannelID != nil {
		if hex.EncodeToString(msg.ChannelID) != hex.EncodeToString(filterChannelID) {
			return nil
		}
	}

	// Look up channel name
	channelName := ""
	ch := c.channels.Get(msg.ChannelID)
	if ch != nil {
		channelName = ch.Name
	}

	// Look up author name
	authorName := ""
	agent := c.registry.GetByPublicKey(raw.AuthorKey)
	if agent != nil {
		authorName = agent.DisplayName
	}

	// Decrypt content based on channel type
	content := c.decryptMessageContent(msg.ChannelID, msg.Content, ch, raw.AuthorKey)

	decoded := &DecodedMessage{
		Hash:         hex.EncodeToString(raw.Hash),
		ChannelID:    hex.EncodeToString(msg.ChannelID),
		ChannelName:  channelName,
		AuthorKey:    hex.EncodeToString(raw.AuthorKey),
		AuthorName:   authorName,
		Content:      content,
		MessageType:  msg.MessageType,
		Timestamp:    raw.CreatedAt,
		ActivityType: "message",
	}

	// Index for full-text search (best-effort, non-blocking)
	if content != "" {
		c.logDB.IndexMessageForSearch(decoded.Hash, content, authorName, channelName, decoded.ChannelID, raw.CreatedAt)
	}

	return decoded
}

// decryptMessageContent decrypts message content based on channel type.
func (c *Connector) decryptMessageContent(channelID, content []byte, ch *channel.Channel, authorKey []byte) string {
	if ch == nil {
		return string(content)
	}

	switch ch.Type {
	case moltcbor.ChannelTypePermanent, moltcbor.ChannelTypePublic:
		return string(content)

	case moltcbor.ChannelTypePrivate, moltcbor.ChannelTypeGroupDM:
		keyBytes, _, err := c.keyDB.GetGroupKey(channelID)
		if err != nil || keyBytes == nil {
			c.log.Debug("decrypt failed: no group key", map[string]any{"channel": hex.EncodeToString(channelID)})
			return "[encrypted]"
		}
		var groupKey [32]byte
		copy(groupKey[:], keyBytes)
		plaintext, err := crypto.OpenFromPeer(groupKey, content)
		if err != nil {
			c.log.Debug("decrypt failed: group key decrypt error", map[string]any{"channel": hex.EncodeToString(channelID), "error": err.Error()})
			return "[encrypted]"
		}
		return string(plaintext)

	case moltcbor.ChannelTypeDM:
		// Find the peer (the other member of the DM)
		var peerKey []byte
		selfHex := fmt.Sprintf("%x", c.keyPair.Public)
		for hexKey := range ch.Members {
			if hexKey != selfHex {
				decoded, err := hex.DecodeString(hexKey)
				if err == nil {
					peerKey = decoded
				}
				break
			}
		}
		if peerKey == nil {
			c.log.Debug("decrypt failed: no peer in DM", map[string]any{"channel": hex.EncodeToString(channelID)})
			return "[encrypted]"
		}
		secret, _, err := c.keyDB.GetPairwiseSecret(peerKey)
		if err != nil || secret == nil {
			c.log.Debug("decrypt failed: no pairwise secret", map[string]any{"peer": hex.EncodeToString(peerKey)})
			return "[encrypted]"
		}
		var secretArr [32]byte
		copy(secretArr[:], secret)
		plaintext, err := crypto.OpenFromPeer(secretArr, content)
		if err != nil {
			c.log.Debug("decrypt failed: pairwise decrypt error", map[string]any{"error": err.Error()})
			return "[encrypted]"
		}
		return string(plaintext)
	}

	return string(content)
}

// GetThreadReplies returns decoded thread replies for a given parent message hash.
func (c *Connector) GetThreadReplies(parentHashHex string, since int64, limit int) ([]DecodedMessage, error) {
	if limit <= 0 {
		limit = 100
	}

	entries, err := c.logDB.EntriesByTypeInRange(int(moltcbor.EntryTypeThreadMessage), since, limit)
	if err != nil {
		return nil, err
	}

	var messages []DecodedMessage
	for _, raw := range entries {
		msg := c.decodeThreadEntry(raw, nil) // nil = don't filter by channel
		if msg == nil {
			continue
		}
		if msg.ParentHash == parentHashHex {
			messages = append(messages, *msg)
		}
	}
	return messages, nil
}

func (c *Connector) decodeThreadEntry(raw *store.RawEntry, filterChannelID []byte) *DecodedMessage {
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

	var msg moltcbor.ThreadMessage
	if err := moltcbor.Unmarshal(env.Payload, &msg); err != nil {
		return nil
	}

	if filterChannelID != nil {
		if hex.EncodeToString(msg.ChannelID) != hex.EncodeToString(filterChannelID) {
			return nil
		}
	}

	channelName := ""
	ch := c.channels.Get(msg.ChannelID)
	if ch != nil {
		channelName = ch.Name
	}

	authorName := ""
	agent := c.registry.GetByPublicKey(raw.AuthorKey)
	if agent != nil {
		authorName = agent.DisplayName
	}

	// Decrypt thread content same as regular messages
	content := c.decryptMessageContent(msg.ChannelID, msg.Content, ch, raw.AuthorKey)

	decoded := &DecodedMessage{
		Hash:         hex.EncodeToString(raw.Hash),
		ChannelID:    hex.EncodeToString(msg.ChannelID),
		ChannelName:  channelName,
		AuthorKey:    hex.EncodeToString(raw.AuthorKey),
		AuthorName:   authorName,
		Content:      content,
		Timestamp:    raw.CreatedAt,
		IsThread:     true,
		ParentHash:   hex.EncodeToString(msg.ParentHash),
		ActivityType: "thread",
	}

	// Index thread content for full-text search (#10)
	if content != "" {
		c.logDB.IndexMessageForSearch(decoded.Hash, content, authorName, channelName, decoded.ChannelID, raw.CreatedAt)
	}

	return decoded
}

// decodeSealedEntry attempts to decrypt a sealed entry by trying all available keys.
// Returns nil if decryption fails (we don't have the right key — entry is for others).
func (c *Connector) decodeSealedEntry(raw *store.RawEntry, filterChannelID []byte) *DecodedMessage {
	// Extract the sealed blob from the outer entry
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

	var sealed moltcbor.SealedEntry
	if err := moltcbor.Unmarshal(env.Payload, &sealed); err != nil {
		return nil
	}

	// Try to decrypt the sealed blob with all available keys
	innerEnvBytes := c.tryDecryptSealed(sealed.Blob)
	if innerEnvBytes == nil {
		return nil // We don't have the key — this entry isn't for us
	}

	// Decode the inner envelope to reveal the true entry type
	var innerEnv moltcbor.Envelope
	if err := moltcbor.Unmarshal(innerEnvBytes, &innerEnv); err != nil {
		return nil
	}

	// Process based on inner entry type
	switch innerEnv.Type {
	case moltcbor.EntryTypeMessage:
		var msg moltcbor.Message
		if err := moltcbor.Unmarshal(innerEnv.Payload, &msg); err != nil {
			return nil
		}
		// Apply channel filter if specified
		if filterChannelID != nil {
			if hex.EncodeToString(msg.ChannelID) != hex.EncodeToString(filterChannelID) {
				return nil
			}
		}
		channelName := ""
		ch := c.channels.Get(msg.ChannelID)
		if ch != nil {
			channelName = ch.Name
		}
		authorName := ""
		agent := c.registry.GetByPublicKey(raw.AuthorKey)
		if agent != nil {
			authorName = agent.DisplayName
		}
		return &DecodedMessage{
			Hash:         hex.EncodeToString(raw.Hash),
			ChannelID:    hex.EncodeToString(msg.ChannelID),
			ChannelName:  channelName,
			AuthorKey:    hex.EncodeToString(raw.AuthorKey),
			AuthorName:   authorName,
			Content:      string(msg.Content),
			MessageType:  msg.MessageType,
			Timestamp:    raw.CreatedAt,
			ActivityType: "message",
		}

	case moltcbor.EntryTypeThreadMessage:
		var msg moltcbor.ThreadMessage
		if err := moltcbor.Unmarshal(innerEnv.Payload, &msg); err != nil {
			return nil
		}
		if filterChannelID != nil {
			if hex.EncodeToString(msg.ChannelID) != hex.EncodeToString(filterChannelID) {
				return nil
			}
		}
		channelName := ""
		ch := c.channels.Get(msg.ChannelID)
		if ch != nil {
			channelName = ch.Name
		}
		authorName := ""
		agent := c.registry.GetByPublicKey(raw.AuthorKey)
		if agent != nil {
			authorName = agent.DisplayName
		}
		return &DecodedMessage{
			Hash:         hex.EncodeToString(raw.Hash),
			ChannelID:    hex.EncodeToString(msg.ChannelID),
			ChannelName:  channelName,
			AuthorKey:    hex.EncodeToString(raw.AuthorKey),
			AuthorName:   authorName,
			Content:      string(msg.Content),
			Timestamp:    raw.CreatedAt,
			IsThread:     true,
			ParentHash:   hex.EncodeToString(msg.ParentHash),
			ActivityType: "thread",
		}

	default:
		return nil // Internal sealed entries (key distribution, etc.) aren't surfaced
	}
}

// tryDecryptSealed attempts to decrypt a sealed blob by trying all available keys
// (pairwise secrets and group keys). Returns the decrypted inner envelope bytes,
// or nil if no key works.
func (c *Connector) tryDecryptSealed(blob []byte) []byte {
	// Try group keys first (private channels, group DMs)
	for _, ch := range c.channels.All() {
		if ch.Type != moltcbor.ChannelTypePrivate && ch.Type != moltcbor.ChannelTypeGroupDM {
			continue
		}
		keyBytes, _, err := c.keyDB.GetGroupKey(ch.ID)
		if err != nil || keyBytes == nil {
			continue
		}
		var key [32]byte
		copy(key[:], keyBytes)
		plaintext, err := crypto.OpenFromPeer(key, blob)
		if err == nil {
			return plaintext
		}
	}

	// Try pairwise secrets (DMs)
	for _, agent := range c.registry.All() {
		if crypto.ConstantTimeEqual(agent.PublicKey, c.keyPair.Public) {
			continue // skip self
		}
		secret, _, err := c.keyDB.GetPairwiseSecret(agent.PublicKey)
		if err != nil || secret == nil {
			continue
		}
		var key [32]byte
		copy(key[:], secret)
		plaintext, err := crypto.OpenFromPeer(key, blob)
		if err == nil {
			return plaintext
		}
	}

	return nil
}
