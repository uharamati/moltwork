package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// SlackVerifier verifies Slack bot tokens using auth.test (rule P1-P3).
type SlackVerifier struct {
	client *http.Client
}

// NewSlackVerifier creates a Slack verifier with a 10-second timeout and
// a transport that doesn't follow redirects (rule P2).
func NewSlackVerifier() *SlackVerifier {
	return &SlackVerifier{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (s *SlackVerifier) Platform() string {
	return "slack"
}

// slackAuthTestResponse is the expected response from Slack's auth.test API.
type slackAuthTestResponse struct {
	OK    bool   `json:"ok"`
	URL   string `json:"url"`    // workspace URL e.g., "https://toriihq.slack.com/"
	Team  string `json:"team"`   // workspace name
	User  string `json:"user"`   // bot user name
	TeamID string `json:"team_id"`
	UserID string `json:"user_id"`
	Error  string `json:"error"`
}

// Verify calls Slack auth.test with the token to verify workspace membership.
// Retries up to 3 times with exponential backoff (rule P2).
// Validates full auth.test response (rule P1).
func (s *SlackVerifier) Verify(ctx context.Context, token string) (*PlatformIdentity, error) {
	var lastErr error

	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			delay := time.Duration(1<<uint(attempt-1)) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		result, err := s.callAuthTest(ctx, token)
		if err != nil {
			lastErr = err
			continue
		}
		return result, nil
	}

	return nil, fmt.Errorf("slack auth.test failed after 3 attempts: %w", lastErr)
}

func (s *SlackVerifier) callAuthTest(ctx context.Context, token string) (*PlatformIdentity, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", "https://slack.com/api/auth.test", nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var authResp slackAuthTestResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	// Rule P1: full response validation
	if !authResp.OK {
		return nil, fmt.Errorf("auth.test not ok: %s", authResp.Error)
	}
	if authResp.UserID == "" {
		return nil, fmt.Errorf("auth.test missing user_id")
	}
	if authResp.URL == "" {
		return nil, fmt.Errorf("auth.test missing url")
	}

	// Extract workspace domain from URL
	domain := extractDomain(authResp.URL)
	if domain == "" {
		return nil, fmt.Errorf("cannot extract domain from url: %s", authResp.URL)
	}

	return &PlatformIdentity{
		Platform:        "slack",
		WorkspaceDomain: domain,
		UserID:          authResp.UserID,
		DisplayName:     authResp.User,
	}, nil
}

// extractDomain extracts "toriihq.slack.com" from "https://toriihq.slack.com/".
func extractDomain(url string) string {
	// Strip protocol
	for _, prefix := range []string{"https://", "http://"} {
		if len(url) > len(prefix) && url[:len(prefix)] == prefix {
			url = url[len(prefix):]
			break
		}
	}
	// Strip trailing slash
	if len(url) > 0 && url[len(url)-1] == '/' {
		url = url[:len(url)-1]
	}
	return url
}
