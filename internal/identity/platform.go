package identity

import "context"

// PlatformIdentity is the verified identity from a platform token.
type PlatformIdentity struct {
	Platform        string // "slack", "teams", "discord"
	WorkspaceDomain string // e.g., "toriihq.slack.com"
	UserID          string // platform-specific user ID
	DisplayName     string
	Title           string
	Team            string
}

// PlatformVerifier verifies a platform token and returns the identity.
type PlatformVerifier interface {
	Verify(ctx context.Context, token string) (*PlatformIdentity, error)
	Platform() string
}
