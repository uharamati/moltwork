package config

import (
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
