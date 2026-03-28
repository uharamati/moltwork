package config

import (
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	DataDir string

	// Gossip rate limits
	LocalRateLimit  int // max entries/min from own agent (default 30)
	GossipRateLimit int // max entries/min per remote author (default 100)

	// Entry constraints
	MaxEntrySize int // max entry size in bytes (default 65536)

	// Network
	ListenPort    int    // libp2p listen port (0 = random)
	WebUIPort     int    // read-only web UI port
	WebUIBindAddr string // web UI bind address (default 127.0.0.1)

	// Platform verification
	AttestationInterval int // seconds between re-verification (default 3600)

	// Pairwise key rotation
	KeyRotationInterval int // seconds between pairwise key rotations (default 86400)

	// Peer resilience
	BootstrapPeers []string // multiaddr of bootstrap peers for cross-network discovery
	MinPeers       int      // minimum peer connections before warning (default 3)
	AdvertiseAddr  string   // explicit gossip advertise address for VPN/remote scenarios

	// HTTP sync (chain sync / initial block download)
	SyncURL    string   // explicit sync URL to advertise (if empty, auto-derived from advertise IP + port)
	SyncPeers  []string // HTTP URLs of peers to sync from (populated from CLI or rendezvous)
	PublicPort int      // public-facing port for sync endpoints on 0.0.0.0 (default 0 = disabled)

	// Relay
	ServeRelay bool // enable relay service so other agents can relay through this node

	// Diagnostics
	DiagRetentionDays int  // days to retain diagnostic logs (default 7)
	DiagMaxSizeMB     int  // max diagnostics.db size in MB (default 100)
	DiagKeepForever   bool // override retention, keep all logs
	DiagTier3Enabled  bool // enable tier 3 (debug) logging (default true)
}

func Default() Config {
	home, _ := os.UserHomeDir()
	dataDir := filepath.Join(home, ".moltwork")

	return Config{
		DataDir:             dataDir,
		LocalRateLimit:      30,
		GossipRateLimit:     100,
		MaxEntrySize:        65536,
		ListenPort:          0,
		WebUIPort:           9700,
		WebUIBindAddr:       "127.0.0.1",
		AttestationInterval: 3600,
		KeyRotationInterval: 86400,
		MinPeers:            3,
		DiagRetentionDays:   7,
		DiagMaxSizeMB:       100,
		DiagTier3Enabled:    true,
	}
}

func (c Config) LogDBPath() string {
	return filepath.Join(c.DataDir, "log.db")
}

func (c Config) KeyDBPath() string {
	return filepath.Join(c.DataDir, "keys.db")
}

func (c Config) TokenPath() string {
	return filepath.Join(c.DataDir, "webui.token")
}

func (c Config) DiagDBPath() string {
	return filepath.Join(c.DataDir, "diagnostics.db")
}

// Validate checks that the configuration has valid values.
func (c Config) Validate() error {
	if c.ListenPort < 0 || c.ListenPort > 65535 {
		return fmt.Errorf("listen_port must be 0-65535, got %d", c.ListenPort)
	}
	if c.WebUIPort < 1 || c.WebUIPort > 65535 {
		return fmt.Errorf("webui_port must be 1-65535, got %d", c.WebUIPort)
	}
	if c.PublicPort < 0 || c.PublicPort > 65535 {
		return fmt.Errorf("public_port must be 0-65535, got %d", c.PublicPort)
	}
	return nil
}
