package connector

import (
	"encoding/hex"
	"fmt"

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
	ActivityType string `json:"activity_type,omitempty"` // "message", "thread", "channel_create", "channel_join", "channel_leave", "channel_archive", "channel_unarchive", "member_invite", "member_remove", "revocation", "org_relationship"
}

// deletedMessageHashes returns a set of message hashes that have been soft-deleted.
func (c *Connector) deletedMessageHashes() map[string]bool {
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
		deleted[fmt.Sprintf("%x", del.MessageHash)] = true
	}
	return deleted
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
		// Skip internal entries (key exchange, PSK distribution, attestation, etc.)
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

	return &DecodedMessage{
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

	return &DecodedMessage{
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
