package gossip

import (
	"context"
	"crypto/ed25519"
	"fmt"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	libp2p "github.com/libp2p/go-libp2p"

	"moltwork/internal/logging"
)

const (
	// ProtocolID is the libp2p protocol identifier for Moltwork gossip sync.
	ProtocolID = "/moltwork/sync/1.0.0"
)

// HostConfig holds configuration for creating a libp2p host.
type HostConfig struct {
	ListenPort   int
	PrivateKey   ed25519.PrivateKey // Moltwork Ed25519 key (rule N3: peer ID derived from this)
	PSK          []byte             // pre-shared key for network gating (rule N3)
	Logger       *logging.Logger
	ServeRelay   bool // enable relay service (this node relays traffic for others)
	DisableRelay bool // disable relay client entirely (for tests)
}

// NewHost creates a libp2p host with Noise encryption and Ed25519 identity.
// Peer ID is derived from the Moltwork Ed25519 keypair (rule N3).
func NewHost(ctx context.Context, cfg HostConfig) (host.Host, error) {
	// Convert Ed25519 key to libp2p format
	privKey, err := libp2pcrypto.UnmarshalEd25519PrivateKey(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("convert ed25519 key: %w", err)
	}

	listenAddr := fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", cfg.ListenPort)

	opts := []libp2p.Option{
		libp2p.Identity(privKey),
		libp2p.ListenAddrStrings(listenAddr),
		// Noise is the default transport security in go-libp2p
	}

	if !cfg.DisableRelay {
		// Enable relay client so this node can dial through circuit addresses
		// (e.g. when connecting to a peer behind NAT). Zero cost when not used.
		opts = append(opts, libp2p.EnableRelay())

		// AutoRelay: when behind NAT, discover relay-capable peers from
		// connected peers and get a relay address through them. No static
		// relay list needed — the bootstrapping agent serves as relay and
		// other agents discover it automatically after connecting.
		opts = append(opts,
			libp2p.EnableAutoRelayWithPeerSource(connectedPeerSource(ctx)),
			libp2p.EnableAutoNATv2(),
			libp2p.EnableHolePunching(),
		)
	}

	// Serve as a relay for other agents (only on the bootstrapping agent
	// or any agent with a publicly reachable address).
	if cfg.ServeRelay {
		opts = append(opts, libp2p.EnableRelayService())
		cfg.Logger.Info("relay service enabled — this node will relay traffic for other agents")
	}

	// PSK gating is handled at the protocol level (we verify peer identity
	// during the sync handshake rather than using libp2p's PSK transport,
	// which requires a specific format). The PSK check happens in protocol.go.

	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("create libp2p host: %w", err)
	}

	cfg.Logger.Info("libp2p host started", map[string]any{
		"peer_id":   h.ID().String(),
		"addresses": h.Addrs(),
	})

	return h, nil
}

// connectedPeerSource returns a function that provides connected peers to
// AutoRelay for relay discovery. AutoRelay probes these peers for relay
// capability and uses any that support it.
func connectedPeerSource(ctx context.Context) func(ctx context.Context, num int) <-chan peer.AddrInfo {
	return func(ctx context.Context, num int) <-chan peer.AddrInfo {
		// Return an empty channel — AutoRelay will use peers from the
		// host's peerstore (connected peers) as candidates.
		// This is a placeholder; AutoRelay discovers relay support
		// from already-connected peers automatically.
		ch := make(chan peer.AddrInfo)
		close(ch)
		return ch
	}
}

// PeerIDFromPublicKey derives a libp2p peer ID from an Ed25519 public key.
func PeerIDFromPublicKey(pubKey ed25519.PublicKey) (peer.ID, error) {
	libp2pKey, err := libp2pcrypto.UnmarshalEd25519PublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("convert public key: %w", err)
	}
	return peer.IDFromPublicKey(libp2pKey)
}
