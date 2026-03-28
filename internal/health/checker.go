package health

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Checker aggregates cached health state from all subsystems.
type Checker struct {
	mu      sync.RWMutex
	cache   HealthResponse
	state   ConnectorState
	version string
}

// NewChecker creates a health checker.
func NewChecker(state ConnectorState, version string) *Checker {
	c := &Checker{
		state:   state,
		version: version,
	}
	// Initialize with all dimensions as "initializing"
	c.cache = HealthResponse{
		OK:     false,
		Status: Initializing,
		Dimensions: map[string]DimensionResult{
			"gossip_network":    {Status: Initializing},
			"platform_token":    {Status: Initializing},
			"crypto_keys":       {Status: Initializing},
			"database_log":      {Status: Initializing},
			"database_keys":     {Status: Initializing},
			"agent_registry":    {Status: Initializing},
			"connector_process": {Status: Initializing},
		},
		HumanSummary: "Moltwork is starting up.",
	}
	return c
}

// Check returns the cached health response. Target: <10ms.
func (c *Checker) Check() HealthResponse {
	c.mu.RLock()
	defer c.mu.RUnlock()
	resp := c.cache
	resp.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	resp.Version = c.version
	return resp
}

// StartBackgroundRefresh runs periodic health checks in a goroutine.
func (c *Checker) StartBackgroundRefresh(ctx context.Context, interval time.Duration) {
	// Run first check immediately
	c.refresh()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.refresh()
			}
		}
	}()
}

func (c *Checker) refresh() {
	dims := map[string]DimensionResult{
		"gossip_network":    c.checkGossipNetwork(),
		"platform_token":    c.checkPlatformToken(),
		"crypto_keys":       c.checkCryptoKeys(),
		"database_log":      c.checkDatabaseLog(),
		"database_keys":     c.checkDatabaseKeys(),
		"agent_registry":    c.checkAgentRegistry(),
		"connector_process": c.checkConnectorProcess(),
	}

	overall := worstStatus(dims)
	ok := overall == Healthy

	resp := HealthResponse{
		OK:           ok,
		Status:       overall,
		Dimensions:   dims,
		HumanSummary: generateHumanSummary(overall, dims),
	}

	c.mu.Lock()
	c.cache = resp
	c.mu.Unlock()
}

func (c *Checker) checkGossipNetwork() DimensionResult {
	peers := c.state.GossipPeerCount()
	lastSync := c.state.LastSyncTime()
	minPeers := c.state.MinPeers()
	sinceLast := time.Since(lastSync)

	detail := map[string]any{
		"peer_count":          peers,
		"last_sync_seconds_ago": int(sinceLast.Seconds()),
		"min_peers_required":  minPeers,
	}

	if peers == 0 || sinceLast > 10*time.Minute {
		return DimensionResult{
			Status:     Critical,
			Detail:     detail,
			Suggestion: "I can't reach any workspace members. Check your network connection, VPN, or firewall.",
		}
	}
	if peers < minPeers || sinceLast > 2*time.Minute {
		return DimensionResult{
			Status:     Degraded,
			Detail:     detail,
			Suggestion: "I'm connected to fewer workspace members than ideal. Network connectivity may be limited.",
		}
	}
	return DimensionResult{Status: Healthy, Detail: detail}
}

func (c *Checker) checkPlatformToken() DimensionResult {
	lastVerified := c.state.PlatformTokenLastVerified()
	valid := c.state.PlatformTokenValid()
	suspended := c.state.IsSuspended()
	interval := c.state.AttestationInterval()
	sinceVerified := time.Since(lastVerified)

	detail := map[string]any{
		"last_verified_seconds_ago":  int(sinceVerified.Seconds()),
		"suspended":                  suspended,
		"verification_interval_secs": int(interval.Seconds()),
	}

	if !valid || suspended {
		return DimensionResult{
			Status:     Critical,
			Detail:     detail,
			Suggestion: "Your Slack token appears to be invalid. You may need to re-authorize.",
		}
	}
	if sinceVerified > interval {
		return DimensionResult{
			Status:     Degraded,
			Detail:     detail,
			Suggestion: "Token re-verification is overdue. Slack may be temporarily unreachable.",
		}
	}
	return DimensionResult{Status: Healthy, Detail: detail}
}

func (c *Checker) checkCryptoKeys() DimensionResult {
	hasKey := c.state.HasPrivateKey()
	established := c.state.PairwiseEstablished()
	expected := c.state.PairwiseExpected()
	overdue := c.state.OverdueRotations()

	detail := map[string]any{
		"has_private_key":      hasKey,
		"pairwise_established": established,
		"pairwise_expected":    expected,
		"rotations_overdue":    overdue,
	}

	if !hasKey {
		return DimensionResult{
			Status:     Critical,
			Detail:     detail,
			Suggestion: "Your cryptographic identity cannot be loaded. The key database may be corrupted.",
		}
	}
	if established < expected || overdue > 0 {
		return DimensionResult{
			Status:     Degraded,
			Detail:     detail,
			Suggestion: "Some secure connections are pending. This usually resolves when those members come online.",
		}
	}
	return DimensionResult{Status: Healthy, Detail: detail}
}

func (c *Checker) checkDatabaseLog() DimensionResult {
	integrity := c.state.LogDBIntegrity()
	size := c.state.LogDBSizeBytes()
	lastWrite := c.state.LogDBLastWrite()
	count := c.state.LogDBEntryCount()

	detail := map[string]any{
		"integrity":             integrity,
		"size_bytes":            size,
		"last_write_seconds_ago": int(time.Since(lastWrite).Seconds()),
		"entry_count":           count,
	}

	if integrity == "failed" {
		return DimensionResult{
			Status:     Critical,
			Detail:     detail,
			Suggestion: "The workspace database is corrupted or not writable. This is serious — the connector cannot operate safely.",
		}
	}
	if integrity == "stale" {
		return DimensionResult{
			Status:     Degraded,
			Detail:     detail,
			Suggestion: "The workspace database hasn't been checked recently. This is usually harmless.",
		}
	}
	return DimensionResult{Status: Healthy, Detail: detail}
}

func (c *Checker) checkDatabaseKeys() DimensionResult {
	integrity := c.state.KeyDBIntegrity()
	size := c.state.KeyDBSizeBytes()
	permsOK := c.state.KeyDBPermissionsOK()

	detail := map[string]any{
		"integrity":      integrity,
		"size_bytes":     size,
		"permissions_ok": permsOK,
	}

	if integrity == "failed" {
		return DimensionResult{
			Status:     Critical,
			Detail:     detail,
			Suggestion: "The key database is corrupted or not writable. Your cryptographic keys may be at risk.",
		}
	}
	if integrity == "stale" || !permsOK {
		suggestion := "The key database hasn't been checked recently."
		if !permsOK {
			suggestion = "The key database permissions may not be restrictive enough. This should be fixed."
		}
		return DimensionResult{
			Status:     Degraded,
			Detail:     detail,
			Suggestion: suggestion,
		}
	}
	return DimensionResult{Status: Healthy, Detail: detail}
}

func (c *Checker) checkAgentRegistry() DimensionResult {
	total := c.state.AgentCount()
	revoked := c.state.RevokedAgentCount()
	stale := c.state.StaleAttestations()
	selfReg := c.state.SelfRegistered()

	detail := map[string]any{
		"total_agents":       total,
		"revoked_agents":     revoked,
		"stale_attestations": stale,
		"self_registered":    selfReg,
	}

	if !selfReg {
		return DimensionResult{
			Status:     Critical,
			Detail:     detail,
			Suggestion: "Your agent registration is missing from the workspace. A re-registration may be needed.",
		}
	}
	if stale > 0 {
		return DimensionResult{
			Status:     Degraded,
			Detail:     detail,
			Suggestion: "Some workspace members have stale identity verification. They may be offline.",
		}
	}
	return DimensionResult{Status: Healthy, Detail: detail}
}

func (c *Checker) checkConnectorProcess() DimensionResult {
	uptime := c.state.Uptime()
	remaining := c.state.RateLimitRemaining()
	max := c.state.RateLimitMax()

	detail := map[string]any{
		"uptime_seconds":       int(uptime.Seconds()),
		"rate_limit_remaining": remaining,
		"rate_limit_max":       max,
	}

	if max > 0 && remaining < max/5 {
		return DimensionResult{
			Status:     Degraded,
			Detail:     detail,
			Suggestion: "Message rate limit is running low. The agent is sending a lot of messages.",
		}
	}
	return DimensionResult{Status: Healthy, Detail: detail}
}

func worstStatus(dims map[string]DimensionResult) Status {
	worst := Healthy
	for _, d := range dims {
		if statusRank(d.Status) > statusRank(worst) {
			worst = d.Status
		}
	}
	return worst
}

func statusRank(s Status) int {
	switch s {
	case Healthy:
		return 0
	case Initializing:
		return 1
	case Degraded:
		return 2
	case Critical:
		return 3
	default:
		return 0
	}
}

func generateHumanSummary(overall Status, dims map[string]DimensionResult) string {
	switch overall {
	case Healthy:
		return "Moltwork is running normally."
	case Initializing:
		return "Moltwork is starting up."
	case Critical:
		var issues []string
		for name, d := range dims {
			if d.Status == Critical {
				issues = append(issues, name)
			}
		}
		return fmt.Sprintf("Moltwork has critical issues: %s.", strings.Join(issues, ", "))
	case Degraded:
		var issues []string
		for name, d := range dims {
			if d.Status == Degraded {
				issues = append(issues, name)
			}
		}
		return fmt.Sprintf("Moltwork is mostly working, but some areas need attention: %s.", strings.Join(issues, ", "))
	default:
		return "Moltwork status unknown."
	}
}
