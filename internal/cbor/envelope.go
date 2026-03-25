package cbor

import "fmt"

// Protocol version. Checked first on decode (rule B4).
const ProtocolVersion = 1

// EntryType identifies the kind of log entry.
type EntryType uint8

const (
	EntryTypeAgentRegistration  EntryType = 1
	EntryTypeTrustBoundary      EntryType = 2
	EntryTypeChannelCreate      EntryType = 3
	EntryTypeMessage            EntryType = 4
	EntryTypeThreadMessage      EntryType = 5
	EntryTypePairwiseKeyExchange EntryType = 6
	EntryTypeGroupKeyDistribute EntryType = 7
	EntryTypeKeyRotationPending EntryType = 8
	EntryTypeKeyRotationActive  EntryType = 9
	EntryTypeRevocation         EntryType = 10
	EntryTypeAttestation        EntryType = 11
	EntryTypeOrgRelationship    EntryType = 12
	EntryTypeCapabilityDecl     EntryType = 13
	EntryTypePSKDistribution    EntryType = 14
	EntryTypeSealedEntry        EntryType = 15 // opaque encrypted blob
	EntryTypeChannelJoin        EntryType = 16
	EntryTypeChannelLeave       EntryType = 17
	EntryTypeChannelArchive     EntryType = 18
	EntryTypeChannelUnarchive   EntryType = 19
	EntryTypeAdminPromote       EntryType = 20
	EntryTypeAdminDemote        EntryType = 21
	EntryTypeMemberInvite       EntryType = 22
	EntryTypeMemberRemove       EntryType = 23
	EntryTypeTokenStatus        EntryType = 24
)

// Envelope wraps every log entry. Version is checked first (rule B4).
type Envelope struct {
	Version  uint8     `cbor:"1,keyasint"`
	Type     EntryType `cbor:"2,keyasint"`
	Payload  []byte    `cbor:"3,keyasint"` // CBOR-encoded type-specific payload
}

// --- Payload types ---

// AgentRegistration is published when an agent joins the workspace.
type AgentRegistration struct {
	PublicKey      []byte `cbor:"1,keyasint"` // Ed25519 public key
	PlatformUserID string `cbor:"2,keyasint"` // e.g., Slack user ID
	Platform       string `cbor:"3,keyasint"` // "slack", "teams", "discord"
	DisplayName    string `cbor:"4,keyasint"`
	Title          string `cbor:"5,keyasint,omitempty"`
	Team           string `cbor:"6,keyasint,omitempty"`
	ExchangePubKey []byte `cbor:"7,keyasint,omitempty"` // X25519 public key for pairwise secret derivation
}

// TrustBoundary sets the workspace identity anchor.
type TrustBoundary struct {
	Platform        string `cbor:"1,keyasint"` // "slack", "teams", "discord"
	WorkspaceDomain string `cbor:"2,keyasint"` // e.g., "toriihq.slack.com"
}

// ChannelType identifies channel behavior.
type ChannelType uint8

const (
	ChannelTypePermanent ChannelType = 1
	ChannelTypePublic    ChannelType = 2
	ChannelTypePrivate   ChannelType = 3
	ChannelTypeDM        ChannelType = 4
	ChannelTypeGroupDM   ChannelType = 5
)

// ChannelCreate announces a new channel.
type ChannelCreate struct {
	ChannelID   []byte      `cbor:"1,keyasint"` // content-addressed or random ID
	Name        string      `cbor:"2,keyasint,omitempty"`
	Description string      `cbor:"3,keyasint,omitempty"`
	ChannelType ChannelType `cbor:"4,keyasint"`
	Members     [][]byte    `cbor:"5,keyasint,omitempty"` // initial member public keys (for private/DM/group DM)
}

// Message is a channel or DM message.
type Message struct {
	ChannelID   []byte `cbor:"1,keyasint"`
	Content     []byte `cbor:"2,keyasint"` // plaintext for public, encrypted for private
	MessageType uint8  `cbor:"3,keyasint"` // 0 = discussion, 1 = action request

	// Action request fields (required when MessageType == 1)
	Action         string `cbor:"4,keyasint,omitempty"` // what action is being requested
	Scope          string `cbor:"5,keyasint,omitempty"` // scope of the request
	AuthorityBasis string `cbor:"6,keyasint,omitempty"` // why requestor believes they can ask
	Urgency        string `cbor:"7,keyasint,omitempty"` // urgency/deadline
}

// ThreadMessage is a reply to another message.
type ThreadMessage struct {
	ChannelID  []byte `cbor:"1,keyasint"`
	ParentHash []byte `cbor:"2,keyasint"` // content-addressed hash of parent message
	Content    []byte `cbor:"3,keyasint"`
}

// PairwiseKeyExchange contains X25519 ephemeral public key for one peer.
type PairwiseKeyExchange struct {
	TargetPubKey []byte `cbor:"1,keyasint"` // who this is encrypted for
	Sealed       []byte `cbor:"2,keyasint"` // encrypted key exchange material
}

// GroupKeyDistribute distributes a group key to a channel member.
type GroupKeyDistribute struct {
	ChannelID    []byte `cbor:"1,keyasint"`
	TargetPubKey []byte `cbor:"2,keyasint"` // member receiving the key
	Sealed       []byte `cbor:"3,keyasint"` // group key encrypted with pairwise secret
	Epoch        uint64 `cbor:"4,keyasint"` // key epoch (increments on rotation)
}

// KeyRotationPending signals group key rotation is starting (rule C7).
type KeyRotationPending struct {
	ChannelID []byte `cbor:"1,keyasint"`
	NewEpoch  uint64 `cbor:"2,keyasint"`
}

// KeyRotationActive signals all members have received the new key.
type KeyRotationActive struct {
	ChannelID []byte `cbor:"1,keyasint"`
	Epoch     uint64 `cbor:"2,keyasint"`
}

// RevocationReason describes why an agent was revoked.
type RevocationReason uint8

const (
	RevocationByManager RevocationReason = 1
	RevocationBySelf    RevocationReason = 2
	RevocationByQuorum  RevocationReason = 3
)

// Revocation announces agent removal from workspace.
type Revocation struct {
	RevokedKeyHash []byte           `cbor:"1,keyasint"` // BLAKE3 hash of revoked agent's public key
	Reason         RevocationReason `cbor:"2,keyasint"`
	Timestamp      int64            `cbor:"3,keyasint"` // Unix timestamp
	Signatures     [][]byte         `cbor:"4,keyasint"` // revoker signature(s)
	Revokers       [][]byte         `cbor:"5,keyasint"` // revoker public key(s)
}

// Attestation is a periodic platform token re-verification.
type Attestation struct {
	Platform        string `cbor:"1,keyasint"`
	WorkspaceDomain string `cbor:"2,keyasint"`
	PlatformUserID  string `cbor:"3,keyasint"`
	Timestamp       int64  `cbor:"4,keyasint"`
}

// OrgRelationship is a verified mutual handshake.
type OrgRelationship struct {
	SubjectPubKey  []byte `cbor:"1,keyasint"` // "reports to"
	ManagerPubKey  []byte `cbor:"2,keyasint"`
	SubjectSig     []byte `cbor:"3,keyasint"` // subject's signature
	ManagerSig     []byte `cbor:"4,keyasint"` // manager's signature
	Timestamp      int64  `cbor:"5,keyasint"`
	Supersedes     []byte `cbor:"6,keyasint,omitempty"` // hash of previous relationship entry
}

// CapabilityDeclaration announces what an agent can/cannot do.
type CapabilityDeclaration struct {
	Capabilities []string `cbor:"1,keyasint"` // what agent can do
	Restrictions []string `cbor:"2,keyasint"` // what agent cannot do
}

// PSKDistribution distributes a new pre-shared key to a specific agent.
type PSKDistribution struct {
	TargetPubKey []byte `cbor:"1,keyasint"`
	Sealed       []byte `cbor:"2,keyasint"` // PSK encrypted with pairwise secret
}

// SealedEntry is an opaque encrypted blob — metadata-private entry.
type SealedEntry struct {
	Blob []byte `cbor:"1,keyasint"` // padded, encrypted content
}

// ChannelMembership entries for join/leave/invite/remove.
type ChannelMembership struct {
	ChannelID []byte `cbor:"1,keyasint"`
	AgentKey  []byte `cbor:"2,keyasint,omitempty"` // target agent (for invite/remove)
}

// AdminChange for promote/demote.
type AdminChange struct {
	ChannelID []byte `cbor:"1,keyasint"`
	AgentKey  []byte `cbor:"2,keyasint"` // agent being promoted/demoted
}

// ChannelArchive for archive/unarchive.
type ChannelArchive struct {
	ChannelID []byte `cbor:"1,keyasint"`
}

// TokenStatus published when platform token verification changes.
type TokenStatus struct {
	Valid     bool   `cbor:"1,keyasint"`
	Platform string `cbor:"2,keyasint"`
	Message  string `cbor:"3,keyasint,omitempty"`
}

// --- Field Validation (rule B3) ---

// ValidateAgentRegistration checks required fields and value ranges.
func ValidateAgentRegistration(reg *AgentRegistration) error {
	if len(reg.PublicKey) != 32 {
		return fmt.Errorf("public key must be 32 bytes, got %d", len(reg.PublicKey))
	}
	if reg.Platform == "" {
		return fmt.Errorf("platform required")
	}
	if reg.Platform != "slack" && reg.Platform != "teams" && reg.Platform != "discord" {
		return fmt.Errorf("unsupported platform: %s", reg.Platform)
	}
	if len(reg.DisplayName) == 0 || len(reg.DisplayName) > 200 {
		return fmt.Errorf("display name must be 1-200 characters")
	}
	if len(reg.ExchangePubKey) > 0 && len(reg.ExchangePubKey) != 32 {
		return fmt.Errorf("exchange public key must be 32 bytes, got %d", len(reg.ExchangePubKey))
	}
	return nil
}

// ValidateTrustBoundary checks required fields.
func ValidateTrustBoundary(tb *TrustBoundary) error {
	if tb.Platform == "" {
		return fmt.Errorf("platform required")
	}
	if tb.WorkspaceDomain == "" {
		return fmt.Errorf("workspace domain required")
	}
	return nil
}

// ValidateMessage checks required fields.
// Action requests (type=1) must include structured action fields.
func ValidateMessage(msg *Message) error {
	if len(msg.ChannelID) == 0 {
		return fmt.Errorf("channel ID required")
	}
	if len(msg.Content) == 0 {
		return fmt.Errorf("content required")
	}
	if msg.MessageType > 1 {
		return fmt.Errorf("invalid message type: %d", msg.MessageType)
	}
	// Action requests must declare what action is being requested
	if msg.MessageType == 1 && msg.Action == "" {
		return fmt.Errorf("action requests must include the 'action' field describing what is being requested")
	}
	return nil
}

// ValidateChannelCreate checks required fields.
func ValidateChannelCreate(cc *ChannelCreate) error {
	if len(cc.ChannelID) == 0 {
		return fmt.Errorf("channel ID required")
	}
	if cc.ChannelType < ChannelTypePermanent || cc.ChannelType > ChannelTypeGroupDM {
		return fmt.Errorf("invalid channel type: %d", cc.ChannelType)
	}
	return nil
}

// ValidateChannelMembership checks required fields.
func ValidateChannelMembership(cm *ChannelMembership) error {
	if len(cm.ChannelID) == 0 {
		return fmt.Errorf("channel ID required")
	}
	return nil
}

// ValidateAdminChange checks required fields.
func ValidateAdminChange(ac *AdminChange) error {
	if len(ac.ChannelID) == 0 {
		return fmt.Errorf("channel ID required")
	}
	if len(ac.AgentKey) == 0 {
		return fmt.Errorf("agent key required")
	}
	return nil
}

// ValidateChannelArchive checks required fields.
func ValidateChannelArchive(ca *ChannelArchive) error {
	if len(ca.ChannelID) == 0 {
		return fmt.Errorf("channel ID required")
	}
	return nil
}

// ValidateThreadMessage checks required fields.
func ValidateThreadMessage(tm *ThreadMessage) error {
	if len(tm.ChannelID) == 0 {
		return fmt.Errorf("channel ID required")
	}
	if len(tm.ParentHash) == 0 {
		return fmt.Errorf("parent hash required")
	}
	if len(tm.Content) == 0 {
		return fmt.Errorf("content required")
	}
	return nil
}

// ValidateRevocation checks required fields.
func ValidateRevocation(rev *Revocation) error {
	if len(rev.RevokedKeyHash) == 0 {
		return fmt.Errorf("revoked key hash required")
	}
	if rev.Reason < RevocationByManager || rev.Reason > RevocationByQuorum {
		return fmt.Errorf("invalid revocation reason: %d", rev.Reason)
	}
	if rev.Timestamp == 0 {
		return fmt.Errorf("timestamp required")
	}
	if len(rev.Signatures) == 0 {
		return fmt.Errorf("at least one signature required")
	}
	if len(rev.Revokers) != len(rev.Signatures) {
		return fmt.Errorf("revokers and signatures count mismatch")
	}
	return nil
}
