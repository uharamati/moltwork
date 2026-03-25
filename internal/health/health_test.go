package health

import (
	"testing"
	"time"
)

// mockState implements ConnectorState for testing.
type mockState struct {
	gossipPeers         int
	lastSync            time.Time
	tokenLastVerified   time.Time
	tokenValid          bool
	suspended           bool
	hasKey              bool
	pairwiseEstablished int
	pairwiseExpected    int
	overdueRotations    int
	logIntegrity        string
	logSize             int64
	logLastWrite        time.Time
	logEntryCount       int
	keyIntegrity        string
	keySize             int64
	keyPermsOK          bool
	agentCount          int
	revokedCount        int
	staleAttestations   int
	selfRegistered      bool
	uptime              time.Duration
	rateLimitRemaining  int
	rateLimitMax        int
	minPeers            int
	attestInterval      time.Duration
}

func (m *mockState) GossipPeerCount() int                 { return m.gossipPeers }
func (m *mockState) LastSyncTime() time.Time              { return m.lastSync }
func (m *mockState) PlatformTokenLastVerified() time.Time { return m.tokenLastVerified }
func (m *mockState) PlatformTokenValid() bool             { return m.tokenValid }
func (m *mockState) IsSuspended() bool                    { return m.suspended }
func (m *mockState) HasPrivateKey() bool                  { return m.hasKey }
func (m *mockState) PairwiseEstablished() int             { return m.pairwiseEstablished }
func (m *mockState) PairwiseExpected() int                { return m.pairwiseExpected }
func (m *mockState) OverdueRotations() int                { return m.overdueRotations }
func (m *mockState) LogDBIntegrity() string               { return m.logIntegrity }
func (m *mockState) LogDBSizeBytes() int64                { return m.logSize }
func (m *mockState) LogDBLastWrite() time.Time            { return m.logLastWrite }
func (m *mockState) LogDBEntryCount() int                 { return m.logEntryCount }
func (m *mockState) KeyDBIntegrity() string               { return m.keyIntegrity }
func (m *mockState) KeyDBSizeBytes() int64                { return m.keySize }
func (m *mockState) KeyDBPermissionsOK() bool             { return m.keyPermsOK }
func (m *mockState) AgentCount() int                      { return m.agentCount }
func (m *mockState) RevokedAgentCount() int               { return m.revokedCount }
func (m *mockState) StaleAttestations() int               { return m.staleAttestations }
func (m *mockState) SelfRegistered() bool                 { return m.selfRegistered }
func (m *mockState) Uptime() time.Duration                { return m.uptime }
func (m *mockState) RateLimitRemaining() int              { return m.rateLimitRemaining }
func (m *mockState) RateLimitMax() int                    { return m.rateLimitMax }
func (m *mockState) MinPeers() int                        { return m.minPeers }
func (m *mockState) AttestationInterval() time.Duration   { return m.attestInterval }

func healthyState() *mockState {
	return &mockState{
		gossipPeers:         5,
		lastSync:            time.Now().Add(-30 * time.Second),
		tokenLastVerified:   time.Now().Add(-10 * time.Minute),
		tokenValid:          true,
		hasKey:              true,
		pairwiseEstablished: 4,
		pairwiseExpected:    4,
		logIntegrity:        "ok",
		logSize:             1024 * 1024,
		logLastWrite:        time.Now().Add(-5 * time.Second),
		logEntryCount:       100,
		keyIntegrity:        "ok",
		keySize:             4096,
		keyPermsOK:          true,
		agentCount:          5,
		selfRegistered:      true,
		uptime:              10 * time.Minute,
		rateLimitRemaining:  25,
		rateLimitMax:        30,
		minPeers:            3,
		attestInterval:      time.Hour,
	}
}

func TestAllHealthy(t *testing.T) {
	c := NewChecker(healthyState(), "test-v1")
	c.refresh()
	resp := c.Check()

	if resp.Status != Healthy {
		t.Errorf("expected healthy, got %s", resp.Status)
	}
	if !resp.OK {
		t.Error("ok should be true when healthy")
	}
	if resp.HumanSummary != "Moltwork is running normally." {
		t.Errorf("unexpected summary: %s", resp.HumanSummary)
	}
}

func TestGossipPeerThresholds(t *testing.T) {
	tests := []struct {
		peers    int
		lastSync time.Duration
		want     Status
	}{
		{5, 30 * time.Second, Healthy},
		{3, 30 * time.Second, Healthy},   // exactly min
		{2, 30 * time.Second, Degraded},  // below min
		{1, 30 * time.Second, Degraded},
		{0, 30 * time.Second, Critical},
		{5, 3 * time.Minute, Degraded},   // sync too old
		{5, 15 * time.Minute, Critical},  // sync way too old
	}

	for _, tt := range tests {
		s := healthyState()
		s.gossipPeers = tt.peers
		s.lastSync = time.Now().Add(-tt.lastSync)

		c := NewChecker(s, "test")
		c.refresh()
		dim := c.Check().Dimensions["gossip_network"]
		if dim.Status != tt.want {
			t.Errorf("peers=%d sync=%v: got %s, want %s", tt.peers, tt.lastSync, dim.Status, tt.want)
		}
	}
}

func TestPlatformTokenStates(t *testing.T) {
	// Valid and recent
	s := healthyState()
	c := NewChecker(s, "test")
	c.refresh()
	if c.Check().Dimensions["platform_token"].Status != Healthy {
		t.Error("valid recent token should be healthy")
	}

	// Suspended
	s = healthyState()
	s.suspended = true
	c = NewChecker(s, "test")
	c.refresh()
	if c.Check().Dimensions["platform_token"].Status != Critical {
		t.Error("suspended should be critical")
	}

	// Token invalid
	s = healthyState()
	s.tokenValid = false
	c = NewChecker(s, "test")
	c.refresh()
	if c.Check().Dimensions["platform_token"].Status != Critical {
		t.Error("invalid token should be critical")
	}

	// Overdue verification
	s = healthyState()
	s.tokenLastVerified = time.Now().Add(-2 * time.Hour) // way past 1hr interval
	c = NewChecker(s, "test")
	c.refresh()
	if c.Check().Dimensions["platform_token"].Status != Degraded {
		t.Error("overdue verification should be degraded")
	}
}

func TestCryptoKeysStates(t *testing.T) {
	// No private key
	s := healthyState()
	s.hasKey = false
	c := NewChecker(s, "test")
	c.refresh()
	if c.Check().Dimensions["crypto_keys"].Status != Critical {
		t.Error("missing key should be critical")
	}

	// Missing pairwise secrets
	s = healthyState()
	s.pairwiseEstablished = 2
	s.pairwiseExpected = 4
	c = NewChecker(s, "test")
	c.refresh()
	if c.Check().Dimensions["crypto_keys"].Status != Degraded {
		t.Error("incomplete pairwise should be degraded")
	}
}

func TestDatabaseStates(t *testing.T) {
	// Log corrupted
	s := healthyState()
	s.logIntegrity = "failed"
	c := NewChecker(s, "test")
	c.refresh()
	if c.Check().Dimensions["database_log"].Status != Critical {
		t.Error("corrupted log should be critical")
	}

	// Key perms wrong
	s = healthyState()
	s.keyPermsOK = false
	c = NewChecker(s, "test")
	c.refresh()
	if c.Check().Dimensions["database_keys"].Status != Degraded {
		t.Error("wrong key perms should be degraded")
	}
}

func TestAgentRegistryStates(t *testing.T) {
	// Not registered
	s := healthyState()
	s.selfRegistered = false
	c := NewChecker(s, "test")
	c.refresh()
	if c.Check().Dimensions["agent_registry"].Status != Critical {
		t.Error("unregistered should be critical")
	}

	// Stale attestations
	s = healthyState()
	s.staleAttestations = 2
	c = NewChecker(s, "test")
	c.refresh()
	if c.Check().Dimensions["agent_registry"].Status != Degraded {
		t.Error("stale attestations should be degraded")
	}
}

func TestRateLimitDegraded(t *testing.T) {
	s := healthyState()
	s.rateLimitRemaining = 3 // < 30/5 = 6
	c := NewChecker(s, "test")
	c.refresh()
	if c.Check().Dimensions["connector_process"].Status != Degraded {
		t.Error("low rate limit should be degraded")
	}
}

func TestWorstStatusAggregation(t *testing.T) {
	// One critical dimension makes overall critical
	s := healthyState()
	s.selfRegistered = false // makes agent_registry critical
	c := NewChecker(s, "test")
	c.refresh()
	resp := c.Check()
	if resp.Status != Critical {
		t.Errorf("one critical should make overall critical, got %s", resp.Status)
	}
	if resp.OK {
		t.Error("ok should be false when not healthy")
	}
}

func TestInitialState(t *testing.T) {
	c := NewChecker(healthyState(), "test")
	// Before refresh, everything should be initializing
	resp := c.Check()
	if resp.Status != Initializing {
		t.Errorf("initial status should be initializing, got %s", resp.Status)
	}
}

func TestVersionInResponse(t *testing.T) {
	c := NewChecker(healthyState(), "v0.1.0")
	c.refresh()
	resp := c.Check()
	if resp.Version != "v0.1.0" {
		t.Errorf("version: got %s, want v0.1.0", resp.Version)
	}
}
