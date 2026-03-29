package gossip

import (
	"context"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"

	"moltwork/internal/logging"
)

const mDNSServiceTag = "moltwork-gossip"

// peerTrackerTTL is how long a peer stays in the tracker without being rediscovered.
const peerTrackerTTL = 2 * time.Hour

// PeerTracker tracks discovered peers.
type PeerTracker struct {
	mu           sync.Mutex
	peers        map[peer.ID]peer.AddrInfo
	peerLastSeen map[peer.ID]time.Time
	log          *logging.Logger
}

// NewPeerTracker creates a new peer tracker.
func NewPeerTracker(log *logging.Logger) *PeerTracker {
	return &PeerTracker{
		peers:        make(map[peer.ID]peer.AddrInfo),
		peerLastSeen: make(map[peer.ID]time.Time),
		log:          log,
	}
}

// HandlePeerFound is called by mDNS when a peer is discovered.
func (pt *PeerTracker) HandlePeerFound(pi peer.AddrInfo) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	_, exists := pt.peers[pi.ID]
	pt.peers[pi.ID] = pi
	pt.peerLastSeen[pi.ID] = time.Now()
	if !exists {
		pt.log.Info("peer discovered", map[string]any{"peer": pi.ID.String()})
	} else {
		pt.log.Debug("peer rediscovered", map[string]any{"peer": pi.ID.String()})
	}
}

// Peers returns all known peers, evicting stale entries first (L1).
func (pt *PeerTracker) Peers() []peer.AddrInfo {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	now := time.Now()
	for id, lastSeen := range pt.peerLastSeen {
		if now.Sub(lastSeen) > peerTrackerTTL {
			delete(pt.peers, id)
			delete(pt.peerLastSeen, id)
		}
	}
	result := make([]peer.AddrInfo, 0, len(pt.peers))
	for _, p := range pt.peers {
		result = append(result, p)
	}
	return result
}

// RemovePeer removes a peer from tracking.
func (pt *PeerTracker) RemovePeer(id peer.ID) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	delete(pt.peers, id)
	delete(pt.peerLastSeen, id)
}

// StartMDNS starts mDNS peer discovery.
func StartMDNS(ctx context.Context, h host.Host, tracker *PeerTracker) error {
	svc := mdns.NewMdnsService(h, mDNSServiceTag, tracker)
	return svc.Start()
}
