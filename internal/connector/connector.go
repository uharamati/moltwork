package connector

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	multiaddr "github.com/multiformats/go-multiaddr"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/channel"
	"moltwork/internal/config"
	"moltwork/internal/crypto"
	"moltwork/internal/dag"
	"moltwork/internal/gossip"
	"moltwork/internal/identity"
	"moltwork/internal/logging"
	"moltwork/internal/rendezvous"
	"moltwork/internal/store"
)

// Connector is the main orchestrator for a Moltwork agent.
type Connector struct {
	cfg      config.Config
	log      *logging.Logger
	logDB    *store.LogDB
	keyDB    *store.KeyDB
	dagState *dag.DAG
	node     *gossip.Node
	registry     *identity.Registry
	orgMap       *identity.OrgMap
	channels     *channel.Manager
	keyPair      *crypto.SigningKeyPair
	exchangeKey  *crypto.ExchangeKeyPair
	localLimiter *gossip.RateLimiter

	startedAt  time.Time
	suspended  bool
	attestLoop *identity.AttestationLoop
	diagDB     *store.DiagDB

	rebuildMu    sync.RWMutex // protects state rebuild (registry, channels, org) from concurrent API reads
	pairwiseMu   sync.Mutex   // protects EstablishPairwiseSecrets
	syncPeerURLs       []string // HTTP sync peer URLs (from config + rendezvous)
	httpSyncWatermark  int64    // watermark for HTTP sync fallback (reduces hash set size)
	syncRebuild  chan struct{} // debounce channel for onSyncComplete rebuilds
	displayName          string // agent's display name, set during join
	cachedPlatformUserID string // cached to avoid O(n) scan every call

	// Deleted message hash cache (TTL-based, rebuilt every 5s)
	deletedHashCache     map[string]bool
	deletedHashCacheTime time.Time
	deletedHashCacheMu   sync.RWMutex

	// Edited message cache (TTL-based, rebuilt every 5s)
	editedMsgCache     map[string]string // message_hash_hex -> latest content
	editedMsgCacheTime time.Time
	editedMsgCacheMu   sync.RWMutex

	// Reaction cache (TTL-based, rebuilt every 5s)
	reactionCache     map[string]map[string][]string // message_hash_hex -> emoji -> [author_key_hex]
	reactionCacheTime time.Time
	reactionCacheMu   sync.RWMutex

	// Pin cache (TTL-based, rebuilt every 5s)
	pinCache     map[string]map[string]bool // channel_id_hex -> set of message_hash_hex
	pinCacheTime time.Time
	pinCacheMu   sync.RWMutex

	// Workspace norms state
	normsState NormsState

	// Integrity check cache — per-instance instead of package-level (M9)
	logDBIntegrityResult string
	logDBIntegrityTime   time.Time
	logDBIntegrityMu     sync.Mutex
	keyDBIntegrityResult string
	keyDBIntegrityTime   time.Time
	keyDBIntegrityMu     sync.Mutex

	// Subscriber notification: broadcast when new entries arrive via gossip or local publish.
	// API handlers (SSE, long-polling) subscribe to get notified of new data.
	subMu       sync.Mutex
	subscribers map[chan struct{}]struct{}

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Subscribe returns a channel that receives a signal when new entries are available.
// Call Unsubscribe when done to avoid leaks.
func (c *Connector) Subscribe() chan struct{} {
	ch := make(chan struct{}, 1)
	c.subMu.Lock()
	if c.subscribers == nil {
		c.subscribers = make(map[chan struct{}]struct{})
	}
	c.subscribers[ch] = struct{}{}
	c.subMu.Unlock()
	return ch
}

// Unsubscribe removes a subscriber channel.
func (c *Connector) Unsubscribe(ch chan struct{}) {
	c.subMu.Lock()
	delete(c.subscribers, ch)
	c.subMu.Unlock()
}

// RebuildRLock acquires a read lock on the state rebuild mutex.
// API handlers should call this before reading registry/channel/org state
// to avoid reading partially-rebuilt state during gossip sync.
func (c *Connector) RebuildRLock()   { c.rebuildMu.RLock() }
func (c *Connector) RebuildRUnlock() { c.rebuildMu.RUnlock() }

// notifySubscribers sends a non-blocking signal to all subscribers.
func (c *Connector) notifySubscribers() {
	c.invalidateDeletedCache()
	c.subMu.Lock()
	for ch := range c.subscribers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	c.subMu.Unlock()
}

// New creates a new Connector but does not start it.
func New(cfg config.Config) *Connector {
	return &Connector{
		cfg:      cfg,
		log:      logging.New("connector"),
		dagState: dag.New(),
		registry: identity.NewRegistry(),
		orgMap:   identity.NewOrgMap(),
		channels: channel.NewManager(),
	}
}

// Start initializes and starts all subsystems.
func (c *Connector) Start(ctx context.Context) error {
	c.ctx, c.cancel = context.WithCancel(ctx)

	// Ensure data directory exists
	if err := os.MkdirAll(c.cfg.DataDir, 0755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	// Open databases (rules S1, S2, S4)
	var err error
	c.logDB, err = store.OpenLogDB(c.cfg.LogDBPath())
	if err != nil {
		return fmt.Errorf("open log db: %w", err)
	}

	c.keyDB, err = store.OpenKeyDB(c.cfg.KeyDBPath())
	if err != nil {
		c.logDB.Close()
		return fmt.Errorf("open key db: %w", err)
	}

	// Load or generate identity
	if err := c.loadOrCreateIdentity(); err != nil {
		c.Close()
		return fmt.Errorf("identity: %w", err)
	}

	// Load registry from existing log entries
	c.registry.LoadFromDB(c.logDB)

	// Replay revocations so revoked agents are marked before pairwise secrets
	c.replayRevocations()

	// Replay org relationships from the log
	c.replayOrgRelationships()

	// Replay channel state (creates + membership events)
	c.replayChannelState()

	// Replay workspace norms from the log
	c.replayNormsUpdates()

	// Replay pairwise key exchange entries (for rotation handling)
	c.replayPairwiseKeyExchanges()

	// Establish pairwise secrets with all known agents
	c.EstablishPairwiseSecrets()

	// Replay group key distributes (must run after pairwise secrets are established)
	c.replayGroupKeyDistributes()

	// Backfill FTS index for any messages not yet indexed (H4, M6)
	c.backfillFTSIndex()

	// Initialize local rate limiter (rule N6)
	localRate := c.cfg.LocalRateLimit
	if localRate == 0 {
		localRate = 30
	}
	c.localLimiter = gossip.NewRateLimiter(localRate, time.Minute)

	// Load PSK — only the bootstrap agent generates it (via Bootstrap()).
	// Joining agents receive it via pairwise secret exchange.
	psk, err := c.keyDB.GetPSK()
	if err != nil {
		c.Close()
		return fmt.Errorf("get PSK: %w", err)
	}

	if psk == nil {
		// No PSK yet — gossip cannot start until we receive one (via join flow)
		// or generate one (via bootstrap). We'll start gossip with a nil PSK
		// and the node will reject all connections until PSK is set.
		c.log.Info("no PSK available, gossip will wait for PSK distribution or bootstrap")
		// Use an empty placeholder — gossip auth will reject all peers,
		// which is correct until we bootstrap or receive PSK
		psk = make([]byte, 32)
	}

	// Start gossip node
	c.node, err = gossip.NewNode(c.ctx, gossip.NodeConfig{
		PrivateKey:      c.keyPair.Private,
		PSK:             psk,
		ListenPort:      c.cfg.ListenPort,
		LogDB:           c.logDB,
		KeyDB:           c.keyDB,
		Logger:          logging.New("gossip"),
		GossipRateLimit: c.cfg.GossipRateLimit,
		SyncInterval:    10 * time.Second,
		Validator:       c.registry,
		BootstrapPeers:  c.cfg.BootstrapPeers,
		ServeRelay:      c.cfg.ServeRelay,
		StaticRelays:    c.cfg.StaticRelays,
	})
	if err != nil {
		c.Close()
		return fmt.Errorf("start gossip: %w", err)
	}

	// Debounced rebuild: collapses N rapid-fire sync completions into one rebuild.
	// Without this, 10 peers syncing simultaneously would trigger 10 full DB scans.
	c.syncRebuild = make(chan struct{}, 1)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-c.syncRebuild:
				// Wait 500ms for more sync completions to coalesce
				timer := time.NewTimer(500 * time.Millisecond)
				select {
				case <-c.ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
				// Drain any additional signals that arrived
				for {
					select {
					case <-c.syncRebuild:
					default:
						goto rebuild
					}
				}
			rebuild:
				c.rebuildMu.Lock()
				c.registry.LoadFromDB(c.logDB)
				c.replayChannelState()
				c.replayOrgRelationships()
				c.replayNormsUpdates()
				c.EstablishPairwiseSecrets()
				c.replayGroupKeyDistributes()
				c.rebuildMu.Unlock()
				c.notifySubscribers()
			}
		}
	}()

	c.node.SetOnSyncComplete(func() {
		select {
		case c.syncRebuild <- struct{}{}:
		default:
			// rebuild already pending
		}
	})

	c.startedAt = time.Now()

	c.log.Info("connector started", map[string]any{
		"peer_id":   c.node.Host().ID().String(),
		"data_dir":  c.cfg.DataDir,
		"agent_key": fmt.Sprintf("%x", c.keyPair.Public[:8]),
	})

	// Start pairwise key rotation loop (rule C9)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.startPairwiseRotation(c.ctx)
	}()

	// Start watching for join requests from new agents (welcoming agent role)
	c.startJoinRequestWatcher()

	// Re-discover peers from Slack on restart (bug 12)
	c.rediscoverPeersFromSlack()

	// Initialize sync peer URLs from config and start background HTTP sync
	c.syncPeerURLs = append(c.syncPeerURLs, c.cfg.SyncPeers...)
	c.startHTTPSyncLoop(c.ctx)

	// Start attestation loop if platform token exists (rule P3)
	token, platform, _, _ := c.keyDB.GetPlatformToken()
	if token != nil && platform != "" {
		var verifier identity.PlatformVerifier
		switch platform {
		case "slack":
			verifier = identity.NewSlackVerifier()
		}
		if verifier != nil {
			interval := time.Duration(c.cfg.AttestationInterval) * time.Second
			if interval == 0 {
				interval = time.Hour
			}
			c.attestLoop = identity.NewAttestationLoop(verifier, string(token), c.keyPair, c.logDB, c.dagState, logging.New("attestation"), interval)
			c.wg.Add(1)
			go func() {
				defer c.wg.Done()
				c.attestLoop.Run(c.ctx)
			}()
			c.log.Info("attestation loop started", map[string]any{"interval": interval.String()})
		}
	}

	return nil
}

// loadOrCreateIdentity loads the agent's keypair from the key DB, or generates a new one.
// Also loads or creates the X25519 exchange keypair for pairwise secret derivation.
func (c *Connector) loadOrCreateIdentity() error {
	pub, priv, err := c.keyDB.GetIdentity()
	if err != nil {
		return err
	}

	if pub != nil && priv != nil {
		c.keyPair = &crypto.SigningKeyPair{
			Public:  ed25519.PublicKey(pub),
			Private: ed25519.PrivateKey(priv),
		}
		c.log.Info("loaded existing identity")
	} else {
		// Generate new signing keypair
		kp, err := crypto.GenerateSigningKeyPair()
		if err != nil {
			return err
		}
		c.keyPair = kp

		if err := c.keyDB.SetIdentity(kp.Public, kp.Private); err != nil {
			return err
		}
		c.log.Info("generated new identity")
	}

	// Load or create X25519 exchange keypair
	exchPub, exchPriv, err := c.keyDB.GetExchangeKeys()
	if err != nil {
		return err
	}

	if exchPub != nil && exchPriv != nil {
		var pubArr, privArr [32]byte
		copy(pubArr[:], exchPub)
		copy(privArr[:], exchPriv)
		c.exchangeKey = &crypto.ExchangeKeyPair{
			Public:  pubArr,
			Private: privArr,
		}
		c.log.Info("loaded existing exchange key")
	} else {
		ekp, err := crypto.GenerateExchangeKeyPair()
		if err != nil {
			return err
		}
		c.exchangeKey = ekp

		if err := c.keyDB.SetExchangeKeys(ekp.Public[:], ekp.Private[:]); err != nil {
			return err
		}
		c.log.Info("generated new exchange key")
	}

	return nil
}

// ExchangeKey returns the agent's X25519 exchange keypair.
func (c *Connector) ExchangeKey() *crypto.ExchangeKeyPair {
	return c.exchangeKey
}

// EstablishPairwiseSecrets derives pairwise secrets with all known agents.
func (c *Connector) EstablishPairwiseSecrets() {
	c.pairwiseMu.Lock()
	defer c.pairwiseMu.Unlock()

	for _, agent := range c.registry.All() {
		// Skip self
		if crypto.ConstantTimeEqual(agent.PublicKey, c.keyPair.Public) {
			continue
		}

		// Skip agents without exchange keys
		if len(agent.ExchangePubKey) != 32 {
			continue
		}

		// Skip if already have a pairwise secret for this agent
		existing, _, _ := c.keyDB.GetPairwiseSecret(agent.PublicKey)
		if existing != nil {
			continue
		}

		// Derive pairwise secret via X25519 DH
		var peerExchPub [32]byte
		copy(peerExchPub[:], agent.ExchangePubKey)
		secret, err := crypto.DerivePairwiseSecret(c.exchangeKey, peerExchPub)
		if err != nil {
			c.log.Warn("derive pairwise secret failed", map[string]any{"error": err.Error()})
			continue
		}

		if err := c.keyDB.SetPairwiseSecret(agent.PublicKey, secret[:], 0); err != nil {
			c.log.Warn("store pairwise secret failed", map[string]any{"error": err.Error()})
			continue
		}

		c.log.Info("established pairwise secret", map[string]any{
			"peer": fmt.Sprintf("%x", agent.PublicKey[:8]),
		})

		// Deliver any pending group key distributions now that we have the secret
		c.deliverPendingGroupKeys(agent.PublicKey, secret[:])
	}
}

// Bootstrap initializes a new workspace. Only called by the first agent.
func (c *Connector) Bootstrap(platform, workspaceDomain string) error {
	return bootstrap(c, platform, workspaceDomain)
}

// KeyPair returns the agent's signing keypair.
func (c *Connector) KeyPair() *crypto.SigningKeyPair {
	return c.keyPair
}

// Context returns the connector's lifecycle context, cancelled on shutdown.
func (c *Connector) Context() context.Context {
	return c.ctx
}

// Registry returns the agent registry.
func (c *Connector) Registry() *identity.Registry {
	return c.registry
}

// OrgMap returns the org map.
func (c *Connector) OrgMap() *identity.OrgMap {
	return c.orgMap
}

// Channels returns the channel manager.
func (c *Connector) Channels() *channel.Manager {
	return c.channels
}

// DAG returns the DAG state.
func (c *Connector) DAG() *dag.DAG {
	return c.dagState
}

// LogDB returns the log database.
func (c *Connector) LogDB() *store.LogDB {
	return c.logDB
}

// KeyDB returns the key database.
func (c *Connector) KeyDB() *store.KeyDB {
	return c.keyDB
}

// Log returns the connector's logger.
func (c *Connector) Log() *logging.Logger {
	return c.log
}

// GossipNode returns the gossip node.
func (c *Connector) GossipNode() *gossip.Node {
	return c.node
}

// DiagDB returns the diagnostics database (may be nil if unavailable).
func (c *Connector) DiagDB() *store.DiagDB {
	return c.diagDB
}

// SetDiagDB sets the diagnostics database.
func (c *Connector) SetDiagDB(db *store.DiagDB) {
	c.diagDB = db
}

// GetPSK returns the workspace PSK, or nil if not yet set.
func (c *Connector) GetPSK() []byte {
	psk, err := c.keyDB.GetPSK()
	if err != nil || psk == nil {
		return nil
	}
	return psk
}

// SetDisplayName sets the agent's display name (used in join requests).
func (c *Connector) SetDisplayName(name string) {
	c.displayName = name
}

// WebUITokenPath returns the path to the web UI bearer token file.
func (c *Connector) WebUITokenPath() string {
	return filepath.Join(c.cfg.DataDir, "webui.token")
}

// ProcessRevocation handles an agent revocation: marks as revoked, retroactively rejects
// post-revocation entries, rotates group keys and PSK (rules R1-R6).
func (c *Connector) ProcessRevocation(revokedPubKey []byte, revocationTimestamp int64) error {
	// Mark agent as revoked in registry
	c.registry.MarkRevoked(revokedPubKey)

	// Clear pairwise secret with revoked agent to prevent post-revocation use
	if err := c.keyDB.DeletePairwiseSecret(revokedPubKey); err != nil {
		c.log.Warn("delete pairwise secret failed", map[string]any{"error": err.Error()})
	}

	c.log.Info("agent revoked", map[string]any{
		"agent": fmt.Sprintf("%x", revokedPubKey[:8]),
	})

	// Retroactive rejection of post-revocation entries (rule R2)
	postEntries, err := c.logDB.GetEntriesByAuthor(revokedPubKey, revocationTimestamp)
	if err != nil {
		c.log.Warn("retroactive scan failed", map[string]any{"error": err.Error()})
	} else {
		for _, e := range postEntries {
			c.logDB.MarkEntryRejected(e.Hash, "post-revocation")
		}
		if len(postEntries) > 0 {
			c.log.Info("retroactively rejected entries", map[string]any{
				"count": len(postEntries),
			})
		}
	}

	// Rotate group keys for all channels the revoked agent was in (rule R4)
	for _, ch := range c.channels.List(c.keyPair.Public) {
		if ch.Type != moltcbor.ChannelTypePrivate && ch.Type != moltcbor.ChannelTypeGroupDM {
			continue
		}
		revokedHex := fmt.Sprintf("%x", revokedPubKey)
		if !ch.Members[revokedHex] {
			continue
		}
		c.rotateGroupKey(ch, revokedPubKey)
	}

	// Rotate PSK (rule R6)
	newPSK := crypto.RandomBytes(32)
	c.keyDB.SetPSK(newPSK)
	if c.node != nil {
		c.node.UpdatePSK(newPSK)
	}

	// Distribute new PSK to all non-revoked agents
	for _, agent := range c.registry.All() {
		if crypto.ConstantTimeEqual(agent.PublicKey, c.keyPair.Public) {
			continue
		}
		if c.registry.IsRevoked(agent.PublicKey) {
			continue
		}
		c.DistributePSKTo(agent.PublicKey)
	}

	c.log.Info("PSK rotated after revocation")
	return nil
}

// DistributePSKTo sends the current PSK to a new agent, encrypted with their pairwise secret.
func (c *Connector) DistributePSKTo(targetPubKey []byte) error {
	psk, err := c.keyDB.GetPSK()
	if err != nil || psk == nil {
		return fmt.Errorf("no PSK to distribute")
	}

	secret, _, err := c.keyDB.GetPairwiseSecret(targetPubKey)
	if err != nil || secret == nil {
		return fmt.Errorf("no pairwise secret for target agent")
	}

	var secretArr [32]byte
	copy(secretArr[:], secret)
	sealed, err := crypto.SealForPeer(secretArr, psk)
	if err != nil {
		return fmt.Errorf("seal PSK: %w", err)
	}

	dist := moltcbor.PSKDistribution{
		TargetPubKey: targetPubKey,
		Sealed:       sealed,
	}
	payload, err := moltcbor.Marshal(dist)
	if err != nil {
		return fmt.Errorf("marshal PSK distribution: %w", err)
	}

	tips := c.dagState.Tips()
	entry, err := dag.NewSignedEntry(moltcbor.EntryTypePSKDistribution, payload, c.keyPair, tips)
	if err != nil {
		return fmt.Errorf("create PSK distribution entry: %w", err)
	}

	if err := c.dagState.Insert(entry); err != nil {
		return fmt.Errorf("insert PSK distribution: %w", err)
	}

	return c.logDB.InsertEntry(entry.Hash[:], entry.RawCBOR, entry.AuthorKey, entry.Signature,
		int(moltcbor.EntryTypePSKDistribution), entry.CreatedAt, hashesToSlices(entry.Parents))
}

// GetTrustBoundary reads the trust boundary from the log.
func (c *Connector) GetTrustBoundary() (platform, domain string, err error) {
	entries, err := c.logDB.EntriesByType(int(moltcbor.EntryTypeTrustBoundary))
	if err != nil {
		return "", "", err
	}
	if len(entries) == 0 {
		return "", "", fmt.Errorf("no trust boundary set")
	}

	// Decode the first (and should be only) trust boundary entry
	raw := entries[0]
	var sigData struct {
		Parents  [][]byte `cbor:"1,keyasint"`
		Envelope []byte   `cbor:"2,keyasint"`
		Time     int64    `cbor:"3,keyasint"`
	}
	if err := moltcbor.Unmarshal(raw.RawCBOR, &sigData); err != nil {
		return "", "", err
	}

	var env moltcbor.Envelope
	if err := moltcbor.Unmarshal(sigData.Envelope, &env); err != nil {
		return "", "", err
	}

	var tb moltcbor.TrustBoundary
	if err := moltcbor.Unmarshal(env.Payload, &tb); err != nil {
		return "", "", err
	}

	return tb.Platform, tb.WorkspaceDomain, nil
}

// startJoinRequestWatcher launches a background goroutine that watches the
// #moltwork-agents Slack channel for join requests from new agents. When a
// request is found, this agent acts as the welcoming agent — distributing the
// PSK and posting the join announcement.
func (c *Connector) startJoinRequestWatcher() {
	token, platform, _, err := c.keyDB.GetPlatformToken()
	if err != nil || token == nil || platform != "slack" {
		c.log.Info("no slack token available, join request watcher not started")
		return
	}

	rv := rendezvous.NewSlackProvider(string(token), c.log)

	// Use cached channel ID to skip full Slack channel scan on restart
	if cachedID := c.keyDB.GetRendezvousChannelID(); cachedID != "" {
		rv.SetCachedChannelID(cachedID)
	}

	// Check if the channel exists before starting the watcher
	exists, err := rv.WorkspaceExists(c.ctx)
	if err != nil || !exists {
		c.log.Info("rendezvous channel not found, join request watcher not started")
		return
	}

	// Cache the resolved channel ID for fast startup next time
	if chID := rv.ChannelID(); chID != "" {
		c.keyDB.SetRendezvousChannelID(chID)
	}

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.watchJoinRequests(c.ctx, rv)
	}()
	c.log.Info("join request watcher started")

	// Post gossip address to Slack. If we have an explicit advertise address,
	// post immediately. Otherwise wait for AutoRelay to acquire a relay address.
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		if c.cfg.AdvertiseAddr == "" {
			c.log.Info("waiting for relay address before posting rendezvous...")
			c.node.WaitForRelayAddr(30 * time.Second)
		}
		if err := c.PostRendezvousAddress(c.ctx, rv); err != nil {
			c.log.Warn("could not post rendezvous address", map[string]any{"error": err.Error()})
		}
	}()
}

// rediscoverPeersFromSlack re-reads gossip addresses from #moltwork-agents
// to populate the peer tracker on restart (bug 12).
func (c *Connector) rediscoverPeersFromSlack() {
	token, platform, _, err := c.keyDB.GetPlatformToken()
	if err != nil || token == nil || platform != "slack" {
		return
	}
	psk := c.GetPSK()
	if psk == nil {
		return // not joined yet
	}

	rv := rendezvous.NewSlackProvider(string(token), c.log)
	if cachedID := c.keyDB.GetRendezvousChannelID(); cachedID != "" {
		rv.SetCachedChannelID(cachedID)
	}
	exists, err := rv.WorkspaceExists(c.ctx)
	if err != nil || !exists {
		return
	}

	addrs, err := rv.GetGossipAddresses(c.ctx)
	if err != nil || len(addrs) == 0 {
		return
	}

	for _, addr := range addrs {
		if addr.Multiaddr == "" || addr.PeerID == "" {
			continue
		}
		fullAddr := addr.Multiaddr
		if !strings.Contains(fullAddr, "/p2p/"+addr.PeerID) {
			fullAddr = fmt.Sprintf("%s/p2p/%s", fullAddr, addr.PeerID)
		}
		ma, err := multiaddr.NewMultiaddr(fullAddr)
		if err != nil {
			continue
		}
		pi, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			continue
		}
		c.node.Tracker().HandlePeerFound(*pi)
	}

	if len(addrs) > 0 {
		c.log.Info("rediscovered peers from Slack", map[string]any{"count": len(addrs)})
	}
}

// Close shuts down all subsystems.
func (c *Connector) Close() error {
	if c.cancel != nil {
		c.cancel()
	}
	c.wg.Wait()

	var firstErr error
	if c.node != nil {
		if err := c.node.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if c.logDB != nil {
		if err := c.logDB.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if c.keyDB != nil {
		if err := c.keyDB.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if c.diagDB != nil {
		if err := c.diagDB.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
