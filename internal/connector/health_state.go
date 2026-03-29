package connector

import (
	"fmt"
	"os"
	"sync"
	"time"

	moltcbor "moltwork/internal/cbor"
)

// Health state methods implement the health.ConnectorState interface.

func (c *Connector) GossipPeerCount() int {
	if c.node == nil {
		return 0
	}
	return len(c.node.Tracker().Peers())
}

func (c *Connector) LastSyncTime() time.Time {
	if c.node == nil {
		return time.Time{}
	}
	return c.node.LastSyncTime()
}

func (c *Connector) PlatformTokenLastVerified() time.Time {
	if c.attestLoop == nil {
		return c.startedAt // fall back to startup time
	}
	t, _ := c.attestLoop.LastVerified()
	return t
}

func (c *Connector) PlatformTokenValid() bool {
	if c.attestLoop == nil {
		return true // no attestation loop means no token to invalidate
	}
	_, valid := c.attestLoop.LastVerified()
	return valid
}

func (c *Connector) IsSuspended() bool {
	return c.suspended
}

func (c *Connector) HasPrivateKey() bool {
	return c.keyPair != nil
}

func (c *Connector) PairwiseEstablished() int {
	count := 0
	for _, agent := range c.registry.All() {
		if len(agent.PublicKey) == 0 {
			continue
		}
		secret, _, _ := c.keyDB.GetPairwiseSecret(agent.PublicKey)
		if secret != nil {
			count++
		}
	}
	return count
}

func (c *Connector) PairwiseExpected() int {
	count := 0
	for _, agent := range c.registry.All() {
		if agent.Revoked {
			continue
		}
		if c.keyPair != nil && string(agent.PublicKey) == string(c.keyPair.Public) {
			continue // skip self
		}
		count++
	}
	return count
}

func (c *Connector) OverdueRotations() int {
	interval := time.Duration(c.cfg.KeyRotationInterval) * time.Second
	if interval == 0 {
		interval = 24 * time.Hour
	}
	threshold := time.Now().Add(-interval).Unix()
	peers, err := c.keyDB.PeersNeedingRotation(threshold)
	if err != nil {
		return 0
	}
	return len(peers)
}

// Cached integrity check results — recomputed every 6 hours.
var (
	logDBIntegrityResult string
	logDBIntegrityTime   time.Time
	logDBIntegrityMu     sync.Mutex
	keyDBIntegrityResult string
	keyDBIntegrityTime   time.Time
	keyDBIntegrityMu     sync.Mutex
)

const integrityCheckInterval = 6 * time.Hour

func (c *Connector) LogDBIntegrity() string {
	if c.logDB == nil {
		return "failed"
	}
	logDBIntegrityMu.Lock()
	defer logDBIntegrityMu.Unlock()
	if time.Since(logDBIntegrityTime) < integrityCheckInterval && logDBIntegrityResult != "" {
		return logDBIntegrityResult
	}
	result, err := c.logDB.IntegrityCheck()
	if err != nil {
		logDBIntegrityResult = "failed"
	} else {
		logDBIntegrityResult = result
	}
	logDBIntegrityTime = time.Now()
	return logDBIntegrityResult
}

func (c *Connector) LogDBSizeBytes() int64 {
	info, err := os.Stat(c.cfg.LogDBPath())
	if err != nil {
		return 0
	}
	return info.Size()
}

func (c *Connector) LogDBLastWrite() time.Time {
	if c.logDB == nil {
		return time.Time{}
	}
	ts, err := c.logDB.LatestTimestamp()
	if err != nil || ts == 0 {
		return c.startedAt
	}
	return time.Unix(ts/1000, (ts%1000)*int64(time.Millisecond))
}

func (c *Connector) LogDBEntryCount() int {
	if c.logDB == nil {
		return 0
	}
	count, _ := c.logDB.EntryCount()
	return count
}

func (c *Connector) KeyDBIntegrity() string {
	if c.keyDB == nil {
		return "failed"
	}
	keyDBIntegrityMu.Lock()
	defer keyDBIntegrityMu.Unlock()
	if time.Since(keyDBIntegrityTime) < integrityCheckInterval && keyDBIntegrityResult != "" {
		return keyDBIntegrityResult
	}
	result, err := c.keyDB.IntegrityCheck()
	if err != nil {
		keyDBIntegrityResult = "failed"
	} else {
		keyDBIntegrityResult = result
	}
	keyDBIntegrityTime = time.Now()
	return keyDBIntegrityResult
}

func (c *Connector) KeyDBSizeBytes() int64 {
	info, err := os.Stat(c.cfg.KeyDBPath())
	if err != nil {
		return 0
	}
	return info.Size()
}

func (c *Connector) KeyDBPermissionsOK() bool {
	info, err := os.Stat(c.cfg.KeyDBPath())
	if err != nil {
		return false
	}
	return info.Mode().Perm() == 0600
}

func (c *Connector) AgentCount() int {
	return c.registry.Count()
}

func (c *Connector) RevokedAgentCount() int {
	count := 0
	for _, a := range c.registry.All() {
		if a.Revoked {
			count++
		}
	}
	return count
}

func (c *Connector) StaleAttestations() int {
	interval := c.AttestationInterval()
	threshold := time.Now().Add(-interval).Unix()
	stale := 0

	for _, agent := range c.registry.All() {
		if agent.Revoked {
			continue
		}
		if c.keyPair != nil && string(agent.PublicKey) == string(c.keyPair.Public) {
			continue // skip self
		}

		// Find latest attestation for this agent
		entries, err := c.logDB.GetEntriesByAuthor(agent.PublicKey, 0)
		if err != nil {
			stale++
			continue
		}

		latestAttestation := int64(0)
		for _, e := range entries {
			if e.EntryType == int(moltcbor.EntryTypeAttestation) && e.CreatedAt > latestAttestation {
				latestAttestation = e.CreatedAt
			}
		}

		if latestAttestation == 0 || latestAttestation < threshold {
			stale++
		}
	}

	return stale
}

func (c *Connector) SelfRegistered() bool {
	if c.keyPair == nil {
		return false
	}
	return c.registry.GetByPublicKey(c.keyPair.Public) != nil
}

func (c *Connector) Uptime() time.Duration {
	if c.startedAt.IsZero() {
		return 0
	}
	return time.Since(c.startedAt)
}

func (c *Connector) RateLimitRemaining() int {
	if c.localLimiter == nil || c.keyPair == nil {
		return c.cfg.LocalRateLimit
	}
	return c.localLimiter.Remaining(fmt.Sprintf("%x", c.keyPair.Public))
}

func (c *Connector) RateLimitMax() int {
	return c.cfg.LocalRateLimit
}

func (c *Connector) MinPeers() int {
	if c.cfg.MinPeers == 0 {
		return 3
	}
	return c.cfg.MinPeers
}

func (c *Connector) AttestationInterval() time.Duration {
	if c.cfg.AttestationInterval == 0 {
		return time.Hour
	}
	return time.Duration(c.cfg.AttestationInterval) * time.Second
}
