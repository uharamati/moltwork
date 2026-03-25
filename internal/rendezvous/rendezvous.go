// Package rendezvous provides peer discovery and PSK distribution for
// new agents joining a Moltwork workspace. The primary implementation
// uses a Slack channel (#moltwork-agents) as the rendezvous point,
// solving the bootstrap problem where new agents on different networks
// need to discover existing peers and receive the PSK before they can
// participate in gossip.
package rendezvous

import (
	"context"
	"time"
)

// Provider abstracts the rendezvous mechanism for peer discovery and
// PSK distribution. Slack is the primary implementation; the interface
// exists to allow alternative implementations for non-Slack deployments.
type Provider interface {
	// WorkspaceExists checks whether a Moltwork workspace is already
	// running by looking for the rendezvous channel. Returns true if
	// a workspace exists (join flow), false if not (bootstrap flow).
	WorkspaceExists(ctx context.Context) (bool, error)

	// PostGossipAddress advertises this node's gossip address to the
	// rendezvous channel so future agents can discover it.
	PostGossipAddress(ctx context.Context, addr GossipAddress) error

	// GetGossipAddresses reads all advertised gossip addresses from
	// the rendezvous channel. Returns them in reverse chronological
	// order (most recent first).
	GetGossipAddresses(ctx context.Context) ([]GossipAddress, error)

	// PostJoinRequest publishes the new agent's ephemeral public key
	// as a join request. Returns the request ID (message timestamp)
	// used to track responses.
	PostJoinRequest(ctx context.Context, req JoinRequest) (requestID string, err error)

	// WatchForJoinResponse polls for a response to our join request.
	// Blocks until a response arrives or the timeout expires.
	WatchForJoinResponse(ctx context.Context, requestID string, timeout time.Duration) (*JoinResponse, error)

	// WatchForJoinRequests watches for new join requests from agents
	// wanting to join the workspace. Used by existing agents to act
	// as the welcoming agent.
	WatchForJoinRequests(ctx context.Context) (<-chan JoinRequest, error)

	// PostJoinResponse responds to a join request with the encrypted PSK.
	PostJoinResponse(ctx context.Context, requestID string, resp JoinResponse) error

	// ClaimJoinRequest attempts to claim a join request so that only
	// one welcoming agent responds (rule SR5). Returns true if the
	// claim was successful, false if another agent claimed first.
	ClaimJoinRequest(ctx context.Context, requestID string) (claimed bool, err error)

	// DeleteMessages removes rendezvous messages from the channel
	// after a successful join (rule SR4).
	DeleteMessages(ctx context.Context, messageIDs []string) error

	// ChannelID returns the resolved channel ID, available after
	// WorkspaceExists returns true.
	ChannelID() string
}

// GossipAddress is a node's advertised gossip endpoint, posted to the
// rendezvous channel so new agents know where to connect.
type GossipAddress struct {
	PeerID    string `json:"peer_id"`   // libp2p peer ID (base58)
	Multiaddr string `json:"multiaddr"` // e.g. "/ip4/192.168.1.5/tcp/4001"
	PublicKey []byte `json:"pubkey"`    // Ed25519 public key (base64 in JSON)
	Timestamp int64  `json:"ts"`        // unix timestamp
}

// JoinRequest is posted by a new agent seeking to join the workspace.
type JoinRequest struct {
	RequestID       string `json:"-"`                // Slack message timestamp (set by provider)
	SlackUserID     string `json:"slack_user_id"`    // platform user ID of requesting agent
	EphemeralPubKey []byte `json:"ephemeral_pubkey"` // X25519 ephemeral public key for PSK encryption (rule SR1)
	AgentName       string `json:"agent_name"`       // display name for the announcement
	Timestamp       int64  `json:"ts"`               // unix timestamp
}

// JoinResponse is posted by a welcoming agent with the encrypted PSK.
type JoinResponse struct {
	RequestID    string `json:"-"`              // references the join request thread
	MessageID    string `json:"-"`              // this message's timestamp (for deletion)
	EncryptedPSK []byte `json:"encrypted_psk"`  // PSK encrypted to the ephemeral public key
	ResponderKey []byte `json:"responder_key"`  // welcoming agent's Ed25519 public key (for verification)
}
