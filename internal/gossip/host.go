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
	ServeRelay   bool     // enable relay service (this node relays traffic for others)
	DisableRelay bool     // disable relay client entirely (for tests)
	StaticRelays []string // explicit relay peer multiaddrs (bypass AutoNAT detection)
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

	// hostRef is set after host creation so the peer source can access
	// connected peers. This is safe because AutoRelay doesn't call the
	// peer source until after the host is fully initialized.
	var hostRef host.Host

	if !cfg.DisableRelay {
		// Enable relay client so this node can dial through circuit addresses
		// (e.g. when connecting to a peer behind NAT). Zero cost when not used.
		opts = append(opts, libp2p.EnableRelay())

		if len(cfg.StaticRelays) > 0 {
			// Static relays: use explicitly configured relay peers instead of
			// waiting for AutoNAT to detect NAT status. This is needed when
			// the agent is behind NAT and AutoNAT detection is too slow.
			var relayInfos []peer.AddrInfo
			for _, addr := range cfg.StaticRelays {
				ma, err := multiaddr.NewMultiaddr(addr)
				if err != nil {
					cfg.Logger.Warn("invalid static relay address", map[string]any{"addr": addr, "error": err.Error()})
					continue
				}
				info, err := peer.AddrInfoFromP2pAddr(ma)
				if err != nil {
					cfg.Logger.Warn("cannot parse relay peer info", map[string]any{"addr": addr, "error": err.Error()})
					continue
				}
				relayInfos = append(relayInfos, *info)
				cfg.Logger.Info("using static relay", map[string]any{"peer": info.ID.String()})
			}
			if len(relayInfos) > 0 {
				opts = append(opts,
					libp2p.EnableAutoRelayWithStaticRelays(relayInfos),
					libp2p.EnableAutoNATv2(),
					libp2p.EnableHolePunching(),
				)
			}
		} else {
			// AutoRelay: when behind NAT, discover relay-capable peers from
			// connected peers and get a relay address through them.
			opts = append(opts,
				libp2p.EnableAutoRelayWithPeerSource(
					func(ctx context.Context, num int) <-chan peer.AddrInfo {
						ch := make(chan peer.AddrInfo)
						go func() {
							defer close(ch)
							if hostRef == nil {
								return
							}
							for _, p := range hostRef.Network().Peers() {
								select {
								case ch <- peer.AddrInfo{
									ID:    p,
									Addrs: hostRef.Network().Peerstore().Addrs(p),
								}:
								case <-ctx.Done():
									return
								}
							}
						}()
						return ch
					},
				),
				libp2p.EnableAutoNATv2(),
				libp2p.EnableHolePunching(),
			)
		}
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
	hostRef = h

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
