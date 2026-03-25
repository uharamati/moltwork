package health

import "time"

// Status represents the health state of a dimension or the overall system.
type Status string

const (
	Healthy      Status = "healthy"
	Degraded     Status = "degraded"
	Critical     Status = "critical"
	Initializing Status = "initializing"
)

// DimensionResult is the health status of a single dimension.
type DimensionResult struct {
	Status     Status         `json:"status"`
	Detail     map[string]any `json:"detail"`
	Suggestion string         `json:"suggestion,omitempty"`
}

// HealthResponse is the full health check response.
type HealthResponse struct {
	OK           bool                       `json:"ok"`
	Status       Status                     `json:"status"`
	Timestamp    string                     `json:"timestamp"`
	Version      string                     `json:"version"`
	Dimensions   map[string]DimensionResult `json:"dimensions"`
	HumanSummary string                     `json:"human_summary"`
}

// ConnectorState is the interface the health checker needs from the connector.
type ConnectorState interface {
	GossipPeerCount() int
	LastSyncTime() time.Time
	PlatformTokenLastVerified() time.Time
	PlatformTokenValid() bool
	IsSuspended() bool
	HasPrivateKey() bool
	PairwiseEstablished() int
	PairwiseExpected() int
	OverdueRotations() int
	LogDBIntegrity() string // "ok", "failed", "stale"
	LogDBSizeBytes() int64
	LogDBLastWrite() time.Time
	LogDBEntryCount() int
	KeyDBIntegrity() string
	KeyDBSizeBytes() int64
	KeyDBPermissionsOK() bool
	AgentCount() int
	RevokedAgentCount() int
	StaleAttestations() int
	SelfRegistered() bool
	Uptime() time.Duration
	RateLimitRemaining() int
	RateLimitMax() int
	MinPeers() int
	AttestationInterval() time.Duration
}
