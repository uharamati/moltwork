package rendezvous

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"moltwork/internal/logging"
)

const (
	channelName    = "moltwork-agents"
	pollInterval   = 5 * time.Second
	apiTimeout     = 10 * time.Second
	claimWaitTime  = 30 * time.Second
)

// SlackProvider implements Provider using the #moltwork-agents Slack channel
// as the rendezvous point for peer discovery and PSK distribution.
type SlackProvider struct {
	token     string
	channelID string // resolved after WorkspaceExists or ensureChannel
	log       *logging.Logger
}

// NewSlackProvider creates a Slack-based rendezvous provider.
func NewSlackProvider(botToken string, log *logging.Logger) *SlackProvider {
	return &SlackProvider{
		token: botToken,
		log:   log,
	}
}

// ChannelID returns the resolved Slack channel ID.
func (s *SlackProvider) ChannelID() string {
	return s.channelID
}

// SetCachedChannelID pre-sets the channel ID from a cache, skipping findChannel.
// Call this before WorkspaceExists to avoid full channel scan on large workspaces.
func (s *SlackProvider) SetCachedChannelID(id string) {
	s.channelID = id
}

// WorkspaceExists checks if #moltwork-agents exists as a public channel.
// Uses conversations.list with types=public_channel (requires channels:read).
// If SetCachedChannelID was called, verifies the cached ID via conversations.info
// instead of scanning all channels.
func (s *SlackProvider) WorkspaceExists(ctx context.Context) (bool, error) {
	// Fast path: verify cached channel ID
	if s.channelID != "" {
		if s.verifyChannelID(ctx, s.channelID) {
			return true, nil
		}
		// Cache was stale, fall through to full scan
		s.channelID = ""
	}

	id, err := s.findChannel(ctx)
	if err != nil {
		return false, err
	}
	if id != "" {
		s.channelID = id
		return true, nil
	}
	return false, nil
}

// verifyChannelID checks if a cached channel ID is still valid via conversations.info.
func (s *SlackProvider) verifyChannelID(ctx context.Context, channelID string) bool {
	client := &http.Client{Timeout: apiTimeout}
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://slack.com/api/conversations.info?channel=%s", channelID), nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var result struct {
		OK      bool `json:"ok"`
		Channel struct {
			Name string `json:"name"`
		} `json:"channel"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return false
	}
	return result.OK && result.Channel.Name == channelName
}

// PostGossipAddress posts a rendezvous message with this node's gossip address.
func (s *SlackProvider) PostGossipAddress(ctx context.Context, addr GossipAddress) error {
	if s.channelID == "" {
		return fmt.Errorf("rendezvous channel not resolved")
	}

	// Need to join the channel first to post
	if err := s.joinChannel(ctx, s.channelID); err != nil {
		s.log.Warn("could not join rendezvous channel", map[string]any{"error": err.Error()})
		// Continue anyway — the bot may already be a member
	}

	text := FormatGossipAddress("Agent", addr)
	_, err := s.postMessage(ctx, s.channelID, text, "")
	return err
}

// GetGossipAddresses reads the channel history and parses all gossip
// address messages, returning them in reverse chronological order.
func (s *SlackProvider) GetGossipAddresses(ctx context.Context) ([]GossipAddress, error) {
	if s.channelID == "" {
		return nil, fmt.Errorf("rendezvous channel not resolved")
	}

	// Join the channel to read history
	if err := s.joinChannel(ctx, s.channelID); err != nil {
		s.log.Warn("could not join rendezvous channel for reading", map[string]any{"error": err.Error()})
	}

	messages, err := s.readHistory(ctx, s.channelID)
	if err != nil {
		return nil, err
	}

	var addrs []GossipAddress
	for _, msg := range messages {
		if addr := ParseGossipAddress(msg.Text); addr != nil {
			addrs = append(addrs, *addr)
		}
	}
	return addrs, nil
}

// PostJoinRequest posts a join request to the rendezvous channel.
func (s *SlackProvider) PostJoinRequest(ctx context.Context, req JoinRequest) (string, error) {
	if s.channelID == "" {
		return "", fmt.Errorf("rendezvous channel not resolved")
	}

	// Join the channel to post
	if err := s.joinChannel(ctx, s.channelID); err != nil {
		s.log.Warn("could not join rendezvous channel for join request", map[string]any{"error": err.Error()})
	}

	text := FormatJoinRequest(req)
	ts, err := s.postMessage(ctx, s.channelID, text, "")
	if err != nil {
		return "", err
	}
	return ts, nil
}

// WatchForJoinResponse polls for a response to our join request.
func (s *SlackProvider) WatchForJoinResponse(ctx context.Context, requestID string, timeout time.Duration) (*JoinResponse, error) {
	deadline := time.After(timeout)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline:
			return nil, fmt.Errorf("timeout waiting for PSK response after %v", timeout)
		case <-ticker.C:
			replies, err := s.readReplies(ctx, s.channelID, requestID)
			if err != nil {
				s.log.Warn("poll for join response failed", map[string]any{"error": err.Error()})
				continue
			}
			for _, reply := range replies {
				if resp := ParseJoinResponse(reply.Text); resp != nil {
					resp.RequestID = requestID
					resp.MessageID = reply.TS
					return resp, nil
				}
			}
		}
	}
}

// WatchForJoinRequests watches for new join requests from agents wanting
// to join. Returns a channel that emits join requests as they appear.
func (s *SlackProvider) WatchForJoinRequests(ctx context.Context) (<-chan JoinRequest, error) {
	if s.channelID == "" {
		return nil, fmt.Errorf("rendezvous channel not resolved")
	}

	ch := make(chan JoinRequest, 10)
	go func() {
		defer close(ch)
		// Track which messages we've already seen. Pruned periodically
		// to prevent unbounded memory growth in long-running agents.
		seen := make(map[string]bool)
		ticker := time.NewTicker(pollInterval)
		defer ticker.Stop()
		pruneCounter := 0

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				messages, err := s.readHistory(ctx, s.channelID)
				if err != nil {
					s.log.Warn("poll for join requests failed", map[string]any{"error": err.Error()})
					continue
				}

				// Build set of currently visible message TSs
				currentTSs := make(map[string]bool, len(messages))
				for _, msg := range messages {
					currentTSs[msg.TS] = true
					if seen[msg.TS] {
						continue
					}
					seen[msg.TS] = true
					if req := ParseJoinRequest(msg.Text); req != nil {
						req.RequestID = msg.TS
						select {
						case ch <- *req:
						case <-ctx.Done():
							return
						}
					}
				}

				// Prune seen entries no longer in history every 100 polls (~8 min)
				pruneCounter++
				if pruneCounter >= 100 {
					pruneCounter = 0
					for ts := range seen {
						if !currentTSs[ts] {
							delete(seen, ts)
						}
					}
				}
			}
		}
	}()
	return ch, nil
}

// PostJoinResponse posts the encrypted PSK as a threaded reply.
func (s *SlackProvider) PostJoinResponse(ctx context.Context, requestID string, resp JoinResponse) error {
	text := FormatJoinResponse("agent", resp)
	_, err := s.postMessage(ctx, s.channelID, text, requestID)
	return err
}

// ClaimJoinRequest posts a claim reply in the join request thread (rule SR5).
// Uses deterministic winner selection: all claimers include their Ed25519
// public key, and the lexicographically smallest key wins. This prevents
// duplicate PSK delivery which can cause cascading pairwise secret corruption.
func (s *SlackProvider) ClaimJoinRequest(ctx context.Context, requestID string, claimerKey []byte) (bool, error) {
	// Check if someone already claimed this request
	replies, err := s.readReplies(ctx, s.channelID, requestID)
	if err != nil {
		return false, err
	}
	for _, reply := range replies {
		if ParseClaim(reply.Text) != nil {
			return false, nil // Already claimed
		}
	}

	// Post our claim with our public key for deterministic winner selection
	claimText := FormatClaim(claimerKey)
	_, err = s.postMessage(ctx, s.channelID, claimText, requestID)
	if err != nil {
		return false, err
	}

	// Extended pause to allow concurrent claims to settle.
	// Slack API latency means claims posted "at the same time" may appear
	// with different timestamps. 4 seconds accounts for typical API jitter.
	time.Sleep(4 * time.Second)

	// Re-read replies and determine the deterministic winner
	replies, err = s.readReplies(ctx, s.channelID, requestID)
	if err != nil {
		return true, nil // Assume we won if we can't check
	}

	// Collect all claim public keys and find deterministic winner
	var smallestKey []byte
	for _, reply := range replies {
		claim := ParseClaim(reply.Text)
		if claim == nil || len(claim.ClaimerKey) == 0 {
			continue
		}
		if smallestKey == nil || comparePubKeys(claim.ClaimerKey, smallestKey) < 0 {
			smallestKey = claim.ClaimerKey
		}
	}

	// We win if our key is the lexicographically smallest
	if smallestKey == nil {
		return true, nil // no valid claims found, we proceed
	}
	return comparePubKeys(claimerKey, smallestKey) == 0, nil
}

// DeleteMessages deletes messages from the channel (rule SR4).
func (s *SlackProvider) DeleteMessages(ctx context.Context, messageIDs []string) error {
	var firstErr error
	for _, ts := range messageIDs {
		if err := s.deleteMessage(ctx, s.channelID, ts); err != nil {
			s.log.Warn("delete rendezvous message failed", map[string]any{
				"ts":    ts,
				"error": err.Error(),
			})
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// --- Slack API helpers ---

// slackMessage represents a message from conversations.history/replies.
type slackMessage struct {
	TS   string `json:"ts"`
	Text string `json:"text"`
	User string `json:"user"`
}

// findChannel searches for the #moltwork-agents channel, paginating through
// all public channels until found or all pages are exhausted.
func (s *SlackProvider) findChannel(ctx context.Context) (string, error) {
	client := &http.Client{Timeout: apiTimeout}
	cursor := ""

	for {
		url := "https://slack.com/api/conversations.list?types=public_channel&limit=200"
		if cursor != "" {
			url += "&cursor=" + cursor
		}

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "Bearer "+s.token)

		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("rendezvous.channel.check_failed: %w", err)
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()

		var result struct {
			OK       bool `json:"ok"`
			Channels []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"channels"`
			ResponseMetadata struct {
				NextCursor string `json:"next_cursor"`
			} `json:"response_metadata"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return "", err
		}
		if !result.OK {
			return "", fmt.Errorf("slack API returned not OK")
		}

		for _, ch := range result.Channels {
			if ch.Name == channelName {
				return ch.ID, nil
			}
		}

		cursor = result.ResponseMetadata.NextCursor
		if cursor == "" {
			break
		}
	}

	return "", nil
}

// joinChannel joins a public channel so the bot can read/post.
func (s *SlackProvider) joinChannel(ctx context.Context, channelID string) error {
	client := &http.Client{Timeout: apiTimeout}

	payload, _ := json.Marshal(map[string]string{"channel": channelID})
	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://slack.com/api/conversations.join", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("rendezvous.channel.join_failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return err
	}
	if !result.OK && result.Error != "already_in_channel" {
		return fmt.Errorf("rendezvous.channel.join_failed: %s", result.Error)
	}
	return nil
}

// readHistory reads recent messages from a channel.
func (s *SlackProvider) readHistory(ctx context.Context, channelID string) ([]slackMessage, error) {
	client := &http.Client{Timeout: apiTimeout}

	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://slack.com/api/conversations.history?channel=%s&limit=200", channelID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rendezvous.history.read_failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var result struct {
		OK       bool           `json:"ok"`
		Error    string         `json:"error"`
		Messages []slackMessage `json:"messages"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	if !result.OK {
		return nil, fmt.Errorf("rendezvous.history.read_failed: %s", result.Error)
	}
	return result.Messages, nil
}

// readReplies reads threaded replies to a message.
func (s *SlackProvider) readReplies(ctx context.Context, channelID, threadTS string) ([]slackMessage, error) {
	client := &http.Client{Timeout: apiTimeout}

	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://slack.com/api/conversations.replies?channel=%s&ts=%s", channelID, threadTS), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rendezvous.replies.read_failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var result struct {
		OK       bool           `json:"ok"`
		Error    string         `json:"error"`
		Messages []slackMessage `json:"messages"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	if !result.OK {
		return nil, fmt.Errorf("rendezvous.replies.read_failed: %s", result.Error)
	}

	// conversations.replies includes the parent message as the first item;
	// skip it to return only actual replies
	if len(result.Messages) > 1 {
		return result.Messages[1:], nil
	}
	return nil, nil
}

// postMessage posts a message to a channel, optionally as a threaded reply.
// Returns the message timestamp (ts).
func (s *SlackProvider) postMessage(ctx context.Context, channelID, text, threadTS string) (string, error) {
	client := &http.Client{Timeout: apiTimeout}

	payload := map[string]string{
		"channel": channelID,
		"text":    text,
	}
	if threadTS != "" {
		payload["thread_ts"] = threadTS
	}
	payloadBytes, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://slack.com/api/chat.postMessage", bytes.NewReader(payloadBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("rendezvous.post.failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		TS    string `json:"ts"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	if !result.OK {
		return "", fmt.Errorf("rendezvous.post.failed: %s", result.Error)
	}
	return result.TS, nil
}

// deleteMessage deletes a message from a channel.
func (s *SlackProvider) deleteMessage(ctx context.Context, channelID, ts string) error {
	client := &http.Client{Timeout: apiTimeout}

	payload, _ := json.Marshal(map[string]string{
		"channel": channelID,
		"ts":      ts,
	})
	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://slack.com/api/chat.delete", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("rendezvous.delete.failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return err
	}
	if !result.OK {
		return fmt.Errorf("rendezvous.delete.failed: %s", result.Error)
	}
	return nil
}

// comparePubKeys compares two public keys lexicographically.
func comparePubKeys(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}
