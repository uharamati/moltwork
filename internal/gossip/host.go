package gossip

import (
	"context"
	"crypto/ed25519"
	"fmt"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	multiaddr "github.com/multiformats/go-multiaddr"

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
	EnableRelay  bool   // enable AutoRelay + AutoNAT + hole punching for NAT traversal
	RelayAddr    string // multiaddr of relay node (required when EnableRelay is true)
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

	// Enable relay support for NAT traversal when configured.
	// The agent connects outbound to the relay node, which provides a
	// publicly reachable address. Other agents connect through the relay.
	if cfg.EnableRelay && cfg.RelayAddr != "" {
		ma, err := multiaddr.NewMultiaddr(cfg.RelayAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid relay address %q: %w", cfg.RelayAddr, err)
		}
		pi, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			return nil, fmt.Errorf("parse relay address %q: %w", cfg.RelayAddr, err)
		}

		opts = append(opts,
			libp2p.EnableRelay(),
			libp2p.EnableAutoRelayWithStaticRelays([]peer.AddrInfo{*pi}),
			libp2p.EnableAutoNATv2(),
			libp2p.EnableHolePunching(),
		)
		cfg.Logger.Info("relay and NAT traversal enabled", map[string]any{
			"relay": cfg.RelayAddr,
		})
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

// PeerIDFromPublicKey derives a libp2p peer ID from an Ed25519 public key.
func PeerIDFromPublicKey(pubKey ed25519.PublicKey) (peer.ID, error) {
	libp2pKey, err := libp2pcrypto.UnmarshalEd25519PublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("convert public key: %w", err)
	}
	return peer.IDFromPublicKey(libp2pKey)
}

// NewRelayHost starts a lightweight libp2p host that runs the Circuit Relay v2
// service. Other agents connect to this relay to traverse NAT.
// Run on a machine with a public IP: `moltwork relay --port 4002`
func NewRelayHost(ctx context.Context, port int) (host.Host, error) {
	listenAddr := fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port)

	h, err := libp2p.New(
		libp2p.ListenAddrStrings(listenAddr),
		libp2p.EnableRelayService(), // serve as a relay for other peers
	)
	if err != nil {
		return nil, fmt.Errorf("create relay host: %w", err)
	}

	return h, nil
}
