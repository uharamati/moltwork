package connector

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"moltwork/internal/crypto"
	"moltwork/internal/rendezvous"

	"github.com/libp2p/go-libp2p/core/peer"
	multiaddr "github.com/multiformats/go-multiaddr"
)

const joinTimeout = 5 * time.Minute

// Join checks whether a workspace exists and routes to Bootstrap or JoinExisting.
func (c *Connector) Join(ctx context.Context, platform, workspaceDomain, botToken string) error {
	rv := rendezvous.NewSlackProvider(botToken, c.log)

	exists, err := rv.WorkspaceExists(ctx)
	if err != nil {
		return fmt.Errorf("check workspace existence: %w", err)
	}

	if !exists {
		c.log.Info("no existing workspace found, bootstrapping")
		if err := c.Bootstrap(platform, workspaceDomain); err != nil {
			return err
		}
		// After bootstrap, post rendezvous message
		return c.PostRendezvousAddress(ctx, rv)
	}

	c.log.Info("existing workspace found, joining")
	return c.JoinExisting(ctx, rv, platform, workspaceDomain)
}

// JoinExisting handles the join flow for an agent joining an existing workspace.
// It discovers peers via Slack, receives the PSK via the Slack-mediated exchange,
// connects to gossip, and completes onboarding.
func (c *Connector) JoinExisting(ctx context.Context, rv rendezvous.Provider, platform, workspaceDomain string) error {
	// Step 1: Generate ephemeral X25519 keypair for PSK exchange (rule SR1)
	ephemeral, err := crypto.GenerateExchangeKeyPair()
	if err != nil {
		return fmt.Errorf("generate ephemeral key: %w", err)
	}
	defer ephemeral.Zero()

	// Step 2: Post join request to Slack
	req := rendezvous.JoinRequest{
		SlackUserID:     "", // will be set from platform verification
		EphemeralPubKey: ephemeral.Public[:],
		AgentName:       "New Agent", // will be updated from Slack profile
		Timestamp:       time.Now().Unix(),
	}

	// Get platform user ID from the stored token verification
	token, plat, _, err := c.keyDB.GetPlatformToken()
	if err == nil && token != nil && plat == platform {
		// Use the Slack user ID we verified during auth.test
		// The connector should have stored this during Start()
		req.SlackUserID = c.getPlatformUserID()
	}

	requestID, err := rv.PostJoinRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("post join request: %w", err)
	}
	c.log.Info("posted join request, waiting for PSK", map[string]any{
		"request_id": requestID,
	})

	// Step 3: Wait for a welcoming agent to respond
	resp, err := rv.WatchForJoinResponse(ctx, requestID, joinTimeout)
	if err != nil {
		return fmt.Errorf("wait for PSK: %w", err)
	}
	c.log.Info("received PSK response")

	// Step 4: Decrypt PSK from response
	psk, err := crypto.OpenFromPublicKey(ephemeral.Private, resp.EncryptedPSK)
	if err != nil {
		return fmt.Errorf("decrypt PSK: %w", err)
	}

	// Step 5: Store PSK and update gossip node
	if err := c.keyDB.SetPSK(psk); err != nil {
		return fmt.Errorf("store PSK: %w", err)
	}
	if c.node != nil {
		c.node.UpdatePSK(psk)
	}
	c.log.Info("PSK received and stored")

	// Step 6: Read gossip addresses from Slack
	addrs, err := rv.GetGossipAddresses(ctx)
	if err != nil {
		return fmt.Errorf("read gossip addresses: %w", err)
	}

	if len(addrs) == 0 {
		return fmt.Errorf("no gossip addresses found in rendezvous channel")
	}

	// Step 6.5: Attempt HTTP chain sync from any peer with a sync_url.
	// This is like a blockchain initial block download — pull the full log
	// over HTTP before starting gossip, so we have all data immediately.
	synced := false
	for _, addr := range addrs {
		if addr.SyncURL == "" {
			continue
		}
		c.log.Info("attempting HTTP chain sync", map[string]any{"url": addr.SyncURL})
		if err := c.httpChainSync(addr.SyncURL, psk); err != nil {
			c.log.Warn("HTTP chain sync failed, will try next peer or fall back to gossip", map[string]any{
				"url":   addr.SyncURL,
				"error": err.Error(),
			})
			continue
		}
		synced = true
		c.log.Info("HTTP chain sync completed successfully", map[string]any{"url": addr.SyncURL})
		break // one successful sync is enough — every peer has the full log
	}

	// Also try any sync peers from config (e.g., --sync-peers CLI flag)
	if !synced {
		for _, peer := range c.cfg.SyncPeers {
			c.log.Info("attempting HTTP chain sync from configured peer", map[string]any{"url": peer})
			if err := c.httpChainSync(peer, psk); err != nil {
				c.log.Warn("HTTP chain sync from configured peer failed", map[string]any{
					"url":   peer,
					"error": err.Error(),
				})
				continue
			}
			synced = true
			c.log.Info("HTTP chain sync from configured peer succeeded", map[string]any{"url": peer})
			break
		}
	}

	// Step 7: Inject peers into tracker (rule SR6: validate before connecting)
	for _, addr := range addrs {
		if addr.Multiaddr == "" || addr.PeerID == "" {
			c.log.Warn("skipping invalid gossip address", map[string]any{
				"peer_id":   addr.PeerID,
				"multiaddr": addr.Multiaddr,
			})
			continue
		}

		// Parse multiaddr and create peer.AddrInfo
		fullAddr := fmt.Sprintf("%s/p2p/%s", addr.Multiaddr, addr.PeerID)
		ma, err := multiaddr.NewMultiaddr(fullAddr)
		if err != nil {
			c.log.Warn("invalid multiaddr from rendezvous", map[string]any{
				"addr":  fullAddr,
				"error": err.Error(),
			})
			continue
		}

		pi, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			c.log.Warn("parse peer addr failed", map[string]any{
				"addr":  fullAddr,
				"error": err.Error(),
			})
			continue
		}

		c.node.Tracker().HandlePeerFound(*pi)
		c.log.Info("added rendezvous peer", map[string]any{
			"peer": pi.ID.String(),
		})
	}

	// Step 8: Clean up Slack messages (rule SR4)
	messagesToDelete := []string{requestID}
	if resp.MessageID != "" {
		messagesToDelete = append(messagesToDelete, resp.MessageID)
	}
	if err := rv.DeleteMessages(ctx, messagesToDelete); err != nil {
		c.log.Warn("cleanup rendezvous messages failed", map[string]any{
			"error": err.Error(),
		})
		// Non-fatal — the PSK is encrypted and the ephemeral key is zeroed
	}

	c.log.Info("join flow completed, gossip sync will begin")
	return nil
}

// PostRendezvousAddress posts this node's gossip address to the rendezvous channel.
// Called after bootstrap and on address changes.
func (c *Connector) PostRendezvousAddress(ctx context.Context, rv rendezvous.Provider) error {
	if c.node == nil {
		return fmt.Errorf("gossip node not started")
	}

	advertiseAddr := c.determineAdvertiseAddr()
	if advertiseAddr == "" {
		c.log.Warn("could not determine advertise address, skipping rendezvous post")
		return nil
	}

	// Derive sync URL: explicit config > auto-detect from advertise IP + web UI port
	syncURL := c.cfg.SyncURL
	if syncURL == "" {
		syncURL = c.determineSyncURL(advertiseAddr)
	}

	addr := rendezvous.GossipAddress{
		PeerID:    c.node.Host().ID().String(),
		Multiaddr: advertiseAddr,
		SyncURL:   syncURL,
		PublicKey:  c.keyPair.Public,
		Timestamp: time.Now().Unix(),
	}

	if err := rv.PostGossipAddress(ctx, addr); err != nil {
		return fmt.Errorf("post gossip address: %w", err)
	}

	c.log.Info("posted rendezvous address", map[string]any{
		"multiaddr": advertiseAddr,
		"peer_id":   addr.PeerID,
	})
	return nil
}

// determineAdvertiseAddr resolves the gossip address to advertise.
// Priority: explicit config > first non-loopback IPv4 > empty.
func (c *Connector) determineAdvertiseAddr() string {
	// 1. Explicit config
	if c.cfg.AdvertiseAddr != "" {
		return c.cfg.AdvertiseAddr
	}

	// 2. First non-loopback, non-link-local IPv4
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				// Build multiaddr from the IP and the gossip listen port
				port := c.cfg.ListenPort
				if port == 0 && c.node != nil {
					// Get the actual port from the libp2p host
					hostAddrs := c.node.Host().Addrs()
					for _, ma := range hostAddrs {
						if p, err := ma.ValueForProtocol(multiaddr.P_TCP); err == nil {
							fmt.Sscanf(p, "%d", &port)
							break
						}
					}
				}
				if port > 0 {
					return fmt.Sprintf("/ip4/%s/tcp/%d", ip4.String(), port)
				}
				return fmt.Sprintf("/ip4/%s/tcp/0", ip4.String())
			}
		}
	}

	return ""
}

// determineSyncURL derives the HTTP sync URL from the advertise multiaddr and port config.
// Uses PublicPort if set (the port bound on 0.0.0.0), otherwise falls back to WebUIPort.
func (c *Connector) determineSyncURL(advertiseAddr string) string {
	port := c.cfg.WebUIPort
	if c.cfg.PublicPort > 0 {
		port = c.cfg.PublicPort
	}

	// Extract the IP from the multiaddr (format: /ip4/X.X.X.X/tcp/XXXXX)
	parts := strings.Split(advertiseAddr, "/")
	for i, p := range parts {
		if p == "ip4" && i+1 < len(parts) {
			ip := parts[i+1]
			return fmt.Sprintf("http://%s:%d", ip, port)
		}
	}
	return ""
}

// getPlatformUserID returns the platform user ID if available.
// This is set during platform verification.
func (c *Connector) getPlatformUserID() string {
	// Check registry for our own agent
	for _, agent := range c.registry.All() {
		if crypto.ConstantTimeEqual(agent.PublicKey, c.keyPair.Public) {
			return agent.PlatformUserID
		}
	}
	return ""
}

// watchJoinRequests runs as a background goroutine on existing agents,
// watching for new agents requesting to join via the Slack rendezvous.
func (c *Connector) watchJoinRequests(ctx context.Context, rv rendezvous.Provider) {
	requests, err := rv.WatchForJoinRequests(ctx)
	if err != nil {
		c.log.Warn("watch join requests failed", map[string]any{"error": err.Error()})
		return
	}

	for req := range requests {
		c.handleJoinRequest(ctx, rv, req)
	}
}

// handleJoinRequest processes a single join request from a new agent.
func (c *Connector) handleJoinRequest(ctx context.Context, rv rendezvous.Provider, req rendezvous.JoinRequest) {
	// SR2: Verify the Slack user ID is not already registered
	if req.SlackUserID != "" {
		for _, agent := range c.registry.All() {
			if agent.PlatformUserID == req.SlackUserID {
				c.log.Info("ignoring join request from already-registered user", map[string]any{
					"slack_user_id": req.SlackUserID,
				})
				return
			}
		}
	}

	// SR5: Try to claim the request
	claimed, err := rv.ClaimJoinRequest(ctx, req.RequestID)
	if err != nil {
		c.log.Warn("claim join request failed", map[string]any{"error": err.Error()})
		return
	}
	if !claimed {
		c.log.Info("join request already claimed by another agent")
		return
	}

	// Get PSK
	psk, err := c.keyDB.GetPSK()
	if err != nil || psk == nil {
		c.log.Warn("cannot distribute PSK: not available")
		return
	}

	// Encrypt PSK to the ephemeral public key
	if len(req.EphemeralPubKey) != 32 {
		c.log.Warn("invalid ephemeral public key length in join request")
		return
	}
	var ephPub [32]byte
	copy(ephPub[:], req.EphemeralPubKey)

	encryptedPSK, err := crypto.SealToPublicKey(ephPub, psk)
	if err != nil {
		c.log.Warn("encrypt PSK failed", map[string]any{"error": err.Error()})
		return
	}

	// Post response
	resp := rendezvous.JoinResponse{
		EncryptedPSK: encryptedPSK,
		ResponderKey: c.keyPair.Public,
	}
	if err := rv.PostJoinResponse(ctx, req.RequestID, resp); err != nil {
		c.log.Warn("post join response failed", map[string]any{"error": err.Error()})
		return
	}

	c.log.Info("distributed PSK to new agent", map[string]any{
		"agent_name":  req.AgentName,
		"request_id":  req.RequestID,
	})

	// Post join announcement via Slack
	c.RelayJoinToSlack(req.AgentName, "", "")
}
