package gossip

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
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

	pskMu sync.RWMutex // protects psk field

	lastSyncTime time.Time
	syncMu       sync.RWMutex

	// Per-peer sync locks to prevent concurrent syncs with the same peer
	peerSyncMu sync.Mutex
	activePeers map[peer.ID]bool

	minPeers int // minimum peer count before warning

	// Rate-limit peer count warnings
	peerWarnMu  sync.Mutex
	lastPeerWarn time.Time

	onSyncComplete func() // called after entries are received via gossip

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
	ServeRelay      bool           // enable relay service for other agents
	DisableRelay    bool           // disable relay client (for tests)
	StaticRelays    []string       // multiaddrs of explicit relay peers (bypass AutoNAT)
}

// NewNode creates and starts a gossip node.
func NewNode(parentCtx context.Context, cfg NodeConfig) (*Node, error) {
	ctx, cancel := context.WithCancel(parentCtx)

	h, err := NewHost(ctx, HostConfig{
		ListenPort:   cfg.ListenPort,
		PrivateKey:   cfg.PrivateKey,
		Logger:       cfg.Logger,
		ServeRelay:   cfg.ServeRelay,
		DisableRelay: cfg.DisableRelay,
		StaticRelays: cfg.StaticRelays,
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

	minPeers := cfg.MinPeers
	if minPeers == 0 {
		minPeers = 3
	}

	n := &Node{
		host:        h,
		logDB:       cfg.LogDB,
		psk:         cfg.PSK,
		log:         cfg.Logger,
		tracker:     tracker,
		limiter:     NewRateLimiter(rateLimit, time.Minute),
		validator:   cfg.Validator,
		minPeers:    minPeers,
		activePeers: make(map[peer.ID]bool),
		ctx:         ctx,
		cancel:      cancel,
	}

	// Register sync protocol handler
	h.SetStreamHandler(protocol.ID(ProtocolID), func(s network.Stream) {
		defer func() {
			if r := recover(); r != nil {
				cfg.Logger.Error("panic in incoming sync handler", map[string]any{
					"peer":  s.Conn().RemotePeer().String(),
					"panic": fmt.Sprintf("%v", r),
				})
			}
		}()

		// Add the connecting peer to our tracker so we can sync back to them.
		// Without this, incoming connections are handled but we never learn
		// the peer's address for reverse sync (asymmetric gossip bug).
		remotePeer := s.Conn().RemotePeer()
		remoteAddr := s.Conn().RemoteMultiaddr()
		tracker.HandlePeerFound(peer.AddrInfo{
			ID:    remotePeer,
			Addrs: []multiaddr.Multiaddr{remoteAddr},
		})

		HandleIncomingSync(s, cfg.LogDB, n.getPSK(), n.validator, cfg.Logger)
		if n.onSyncComplete != nil {
			n.onSyncComplete()
		}
	})

	// Start mDNS discovery
	if err := StartMDNS(ctx, h, tracker); err != nil {
		cfg.Logger.Warn("mDNS start failed", map[string]any{"error": err.Error()})
	}

	// Connect to bootstrap peers (rule N8)
	validPeers := 0
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
		validPeers++
	}
	if len(cfg.BootstrapPeers) > 0 && validPeers == 0 {
		cfg.Logger.Warn("all bootstrap peers were invalid — node has no initial peers and may not discover the network")
	}

	// Start periodic sync loop
	n.wg.Add(1)
	go n.syncLoop(syncInterval)

	return n, nil
}

// syncLoop periodically syncs with discovered peers.
func (n *Node) syncLoop(interval time.Duration) {
	defer n.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			n.log.Error("panic in sync loop", map[string]any{
				"panic": fmt.Sprintf("%v", r),
			})
		}
	}()
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
// Each peer sync runs in a goroutine so one stalled peer can't block others.
func (n *Node) syncWithPeers() {
	peers := n.tracker.Peers()

	// Check minimum peer count — rate-limit to once per minute (bug 14)
	activePeers := 0
	for _, pi := range peers {
		if pi.ID != n.host.ID() && n.host.Network().Connectedness(pi.ID) == network.Connected {
			activePeers++
		}
	}
	if activePeers < n.minPeers {
		n.peerWarnMu.Lock()
		now := time.Now()
		if now.Sub(n.lastPeerWarn) > time.Minute {
			n.log.Warn("below minimum peer count", map[string]any{
				"active":  activePeers,
				"minimum": n.minPeers,
			})
			n.lastPeerWarn = now
		}
		n.peerWarnMu.Unlock()
	}

	for _, pi := range peers {
		if pi.ID == n.host.ID() {
			continue
		}

		// Check if already syncing with this peer (prevents duplicate concurrent syncs)
		n.peerSyncMu.Lock()
		if n.activePeers[pi.ID] {
			n.peerSyncMu.Unlock()
			continue
		}
		n.activePeers[pi.ID] = true
		n.peerSyncMu.Unlock()

		// Run in background — don't block the sync loop waiting for completion.
		// Each goroutine cleans up activePeers and calls onSyncComplete on success.
		go func(pi peer.AddrInfo) {
			defer func() {
				// Recover from panics (e.g., malformed CBOR from a peer) so one
				// bad peer can't crash the entire process.
				if r := recover(); r != nil {
					n.log.Error("panic in peer sync goroutine", map[string]any{
						"peer":  pi.ID.String(),
						"panic": fmt.Sprintf("%v", r),
					})
				}
				n.peerSyncMu.Lock()
				delete(n.activePeers, pi.ID)
				n.peerSyncMu.Unlock()
			}()

			// Connect if not already connected
			if n.host.Network().Connectedness(pi.ID) != network.Connected {
				connectCtx, connectCancel := context.WithTimeout(n.ctx, 10*time.Second)
				defer connectCancel()
				if err := n.host.Connect(connectCtx, pi); err != nil {
					n.log.Debug("connect failed", map[string]any{"peer": pi.ID.String(), "error": err.Error()})
					return
				}
			}

			// Open sync stream with timeout
			streamCtx, streamCancel := context.WithTimeout(n.ctx, 15*time.Second)
			defer streamCancel()
			s, err := n.host.NewStream(streamCtx, pi.ID, protocol.ID(ProtocolID))
			if err != nil {
				n.log.Debug("open stream failed", map[string]any{"peer": pi.ID.String(), "error": err.Error()})
				return
			}

			if err := InitiateSync(s, n.logDB, n.getPSK(), n.validator, n.log); err != nil {
				if errors.Is(err, ErrNoNewEntries) {
					// Sync completed but no new data — skip expensive rebuild
					n.log.Debug("sync completed (no new entries)", map[string]any{"peer": pi.ID.String()})
				} else {
					n.log.Debug("sync failed", map[string]any{"peer": pi.ID.String(), "error": err.Error()})
				}
			} else {
				n.log.Debug("sync completed", map[string]any{"peer": pi.ID.String()})
				n.syncMu.Lock()
				n.lastSyncTime = time.Now()
				n.syncMu.Unlock()
				if n.onSyncComplete != nil {
					n.onSyncComplete()
				}
			}
		}(pi)
	}
}

// Host returns the underlying libp2p host.
func (n *Node) Host() host.Host {
	return n.host
}

// Tracker returns the peer tracker.
func (n *Node) Tracker() *PeerTracker {
	return n.tracker
}

// MinPeers returns the configured minimum peer count.
func (n *Node) MinPeers() int {
	return n.minPeers
}

// LastSyncTime returns the time of the last completed sync cycle.
func (n *Node) LastSyncTime() time.Time {
	n.syncMu.RLock()
	defer n.syncMu.RUnlock()
	return n.lastSyncTime
}

// SetOnSyncComplete sets a callback invoked after entries are received via gossip.
// The connector uses this to rebuild in-memory state (registry, channels, etc.)
func (n *Node) SetOnSyncComplete(fn func()) {
	n.onSyncComplete = fn
}

// getPSK returns the current PSK, protected by the read lock.
func (n *Node) getPSK() []byte {
	n.pskMu.RLock()
	defer n.pskMu.RUnlock()
	psk := make([]byte, len(n.psk))
	copy(psk, n.psk)
	return psk
}

// UpdatePSK atomically swaps the PSK used for gossip authentication.
// Called when PSK is rotated (e.g., after agent revocation per rule R6).
//
// PSK ROTATION CEREMONY:
// 1. ProcessRevocation() generates a new PSK and calls UpdatePSK() locally
// 2. The new PSK is distributed to all non-revoked agents via DistributePSKTo()
//    which publishes PSKDistribution entries sealed to each agent's pairwise secret
// 3. Each agent decrypts the new PSK from the PSKDistribution entry during replay
// 4. There is a brief window where old and new PSK coexist — peers using the old
//    PSK will fail auth and retry on the next sync cycle after receiving the new PSK
//
// This is safe because: (a) the revoked agent never receives the new PSK, and
// (b) existing agents will sync the PSKDistribution entry within 1-2 gossip cycles.
func (n *Node) UpdatePSK(newPSK []byte) {
	n.pskMu.Lock()
	defer n.pskMu.Unlock()
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
