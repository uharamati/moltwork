package gossip

import (
	"context"
	"crypto/ed25519"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	multiaddr "github.com/multiformats/go-multiaddr"

	"moltwork/internal/logging"
	"moltwork/internal/store"
)

// Node is a gossip participant that syncs with peers.
type Node struct {
	host      host.Host
	logDB     *store.LogDB
	psk       []byte
	log       *logging.Logger
	tracker   *PeerTracker
	limiter   *RateLimiter
	validator AgentValidator

	lastSyncTime time.Time
	syncMu       sync.RWMutex

	// Per-peer sync locks to prevent concurrent syncs with the same peer
	peerSyncMu sync.Mutex
	activePeers map[peer.ID]bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NodeConfig configures a gossip node.
type NodeConfig struct {
	PrivateKey      ed25519.PrivateKey
	PSK             []byte
	ListenPort      int
	LogDB           *store.LogDB
	Logger          *logging.Logger
	GossipRateLimit int            // per-author entries/minute (default 100)
	SyncInterval    time.Duration
	Validator       AgentValidator // validates agent registration and revocation status
	MinPeers        int            // minimum desired peer connections (default 3)
	BootstrapPeers  []string       // multiaddr strings for bootstrap peers
	RelayAddr       string         // multiaddr of relay node for AutoRelay (optional)
	DisableRelay    bool           // disable relay client (for tests)
}

// NewNode creates and starts a gossip node.
func NewNode(parentCtx context.Context, cfg NodeConfig) (*Node, error) {
	ctx, cancel := context.WithCancel(parentCtx)

	h, err := NewHost(ctx, HostConfig{
		ListenPort:   cfg.ListenPort,
		PrivateKey:   cfg.PrivateKey,
		Logger:       cfg.Logger,
		RelayAddr:    cfg.RelayAddr,
		DisableRelay: cfg.DisableRelay,
	})
	if err != nil {
		cancel()
		return nil, err
	}

	rateLimit := cfg.GossipRateLimit
	if rateLimit == 0 {
		rateLimit = 100
	}

	syncInterval := cfg.SyncInterval
	if syncInterval == 0 {
		syncInterval = 10 * time.Second
	}

	tracker := NewPeerTracker(cfg.Logger)

	n := &Node{
		host:        h,
		logDB:       cfg.LogDB,
		psk:         cfg.PSK,
		log:         cfg.Logger,
		tracker:     tracker,
		limiter:     NewRateLimiter(rateLimit, time.Minute),
		validator:   cfg.Validator,
		activePeers: make(map[peer.ID]bool),
		ctx:         ctx,
		cancel:      cancel,
	}

	// Register sync protocol handler
	h.SetStreamHandler(protocol.ID(ProtocolID), func(s network.Stream) {
		HandleIncomingSync(s, cfg.LogDB, cfg.PSK, n.validator, cfg.Logger)
	})

	// Start mDNS discovery
	if err := StartMDNS(ctx, h, tracker); err != nil {
		cfg.Logger.Warn("mDNS start failed", map[string]any{"error": err.Error()})
	}

	// Connect to bootstrap peers (rule N8)
	for _, addr := range cfg.BootstrapPeers {
		ma, err := multiaddr.NewMultiaddr(addr)
		if err != nil {
			cfg.Logger.Warn("invalid bootstrap peer address", map[string]any{"addr": addr, "error": err.Error()})
			continue
		}
		pi, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			cfg.Logger.Warn("parse bootstrap peer", map[string]any{"addr": addr, "error": err.Error()})
			continue
		}
		tracker.HandlePeerFound(*pi)
		cfg.Logger.Info("added bootstrap peer", map[string]any{"peer": pi.ID.String()})
	}

	// Start periodic sync loop
	n.wg.Add(1)
	go n.syncLoop(syncInterval)

	return n, nil
}

// syncLoop periodically syncs with discovered peers.
func (n *Node) syncLoop(interval time.Duration) {
	defer n.wg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			n.syncWithPeers()
		}
	}
}

// syncWithPeers initiates sync with all known peers.
// Warns if peer count is below minimum (rule N7).
func (n *Node) syncWithPeers() {
	peers := n.tracker.Peers()

	// Check minimum peer count (rule N7)
	activePeers := 0
	for _, pi := range peers {
		if pi.ID != n.host.ID() && n.host.Network().Connectedness(pi.ID) == network.Connected {
			activePeers++
		}
	}
	minPeers := 3 // default
	if activePeers < minPeers {
		n.log.Warn("below minimum peer count", map[string]any{
			"active":  activePeers,
			"minimum": minPeers,
		})
	}
	for _, pi := range peers {
		if pi.ID == n.host.ID() {
			continue
		}

		// Deterministic sync direction: only initiate if our ID < peer ID
		// This prevents both sides from simultaneously opening sync streams
		if n.host.ID() > pi.ID {
			continue
		}

		// Check if already syncing with this peer
		n.peerSyncMu.Lock()
		if n.activePeers[pi.ID] {
			n.peerSyncMu.Unlock()
			continue
		}
		n.activePeers[pi.ID] = true
		n.peerSyncMu.Unlock()

		func() {
			defer func() {
				n.peerSyncMu.Lock()
				delete(n.activePeers, pi.ID)
				n.peerSyncMu.Unlock()
			}()

			// Connect if not already connected
			if n.host.Network().Connectedness(pi.ID) != network.Connected {
				if err := n.host.Connect(n.ctx, pi); err != nil {
					n.log.Debug("connect failed", map[string]any{"peer": pi.ID.String(), "error": err.Error()})
					return
				}
			}

			// Open sync stream
			s, err := n.host.NewStream(n.ctx, pi.ID, protocol.ID(ProtocolID))
			if err != nil {
				n.log.Debug("open stream failed", map[string]any{"peer": pi.ID.String(), "error": err.Error()})
				return
			}

			if err := InitiateSync(s, n.logDB, n.psk, n.validator, n.log); err != nil {
				n.log.Debug("sync failed", map[string]any{"peer": pi.ID.String(), "error": err.Error()})
			} else {
				n.log.Debug("sync completed", map[string]any{"peer": pi.ID.String()})
			}
		}()
	}

	n.syncMu.Lock()
	n.lastSyncTime = time.Now()
	n.syncMu.Unlock()
}

// Host returns the underlying libp2p host.
func (n *Node) Host() host.Host {
	return n.host
}

// Tracker returns the peer tracker.
func (n *Node) Tracker() *PeerTracker {
	return n.tracker
}

// LastSyncTime returns the time of the last completed sync cycle.
func (n *Node) LastSyncTime() time.Time {
	n.syncMu.RLock()
	defer n.syncMu.RUnlock()
	return n.lastSyncTime
}

// UpdatePSK atomically swaps the PSK used for gossip authentication.
// Called when PSK is rotated (e.g., after agent revocation).
func (n *Node) UpdatePSK(newPSK []byte) {
	n.psk = newPSK
}

// RelayAddrs returns any relay (circuit) addresses the host has acquired.
// These are addresses like /p2p/RELAY/p2p-circuit/p2p/SELF that allow
// peers on other networks to connect through the relay.
func (n *Node) RelayAddrs() []multiaddr.Multiaddr {
	var relayAddrs []multiaddr.Multiaddr
	for _, addr := range n.host.Addrs() {
		if isRelayAddr(addr) {
			relayAddrs = append(relayAddrs, addr)
		}
	}
	return relayAddrs
}

// WaitForRelayAddr waits up to timeout for the host to acquire a relay
// address (indicating AutoRelay has connected to a public relay because
// AutoNAT detected we're behind NAT). Returns immediately if relay addrs
// are already available or if the node is publicly reachable.
func (n *Node) WaitForRelayAddr(timeout time.Duration) []multiaddr.Multiaddr {
	// Check if we already have relay addresses
	if addrs := n.RelayAddrs(); len(addrs) > 0 {
		return addrs
	}

	deadline := time.After(timeout)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			n.log.Info("relay address wait timed out, using available addresses")
			return n.RelayAddrs()
		case <-n.ctx.Done():
			return nil
		case <-ticker.C:
			if addrs := n.RelayAddrs(); len(addrs) > 0 {
				n.log.Info("relay address acquired", map[string]any{
					"addrs": addrs,
				})
				return addrs
			}
		}
	}
}

// isRelayAddr checks if a multiaddr contains /p2p-circuit/ (indicating a relay address).
func isRelayAddr(addr multiaddr.Multiaddr) bool {
	for _, p := range addr.Protocols() {
		if p.Code == multiaddr.P_CIRCUIT {
			return true
		}
	}
	return false
}

// Close shuts down the gossip node.
func (n *Node) Close() error {
	n.cancel()
	n.wg.Wait()
	return n.host.Close()
}
