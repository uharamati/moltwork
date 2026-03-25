package gossip

import (
	"context"
	"sync"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"

	"moltwork/internal/logging"
)

const mDNSServiceTag = "moltwork-gossip"

// PeerTracker tracks discovered peers.
type PeerTracker struct {
	mu    sync.Mutex
	peers map[peer.ID]peer.AddrInfo
	log   *logging.Logger
}

// NewPeerTracker creates a new peer tracker.
func NewPeerTracker(log *logging.Logger) *PeerTracker {
	return &PeerTracker{
		peers: make(map[peer.ID]peer.AddrInfo),
		log:   log,
	}
}

// HandlePeerFound is called by mDNS when a peer is discovered.
func (pt *PeerTracker) HandlePeerFound(pi peer.AddrInfo) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.peers[pi.ID] = pi
	pt.log.Info("peer discovered", map[string]any{"peer": pi.ID.String()})
}

// Peers returns all known peers.
func (pt *PeerTracker) Peers() []peer.AddrInfo {
	pt.mu.Lock()
	defer pt.mu.Unlock()
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
}

// StartMDNS starts mDNS peer discovery.
func StartMDNS(ctx context.Context, h host.Host, tracker *PeerTracker) error {
	svc := mdns.NewMdnsService(h, mDNSServiceTag, tracker)
	return svc.Start()
}
