package connector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// slackChannelName is the Slack channel where join announcements are posted.
const slackChannelName = "moltwork-agents"

// AnnounceJoinToSlack posts a join announcement to the #moltwork-agents channel
// in the company's Slack workspace (onboarding steps 13-14).
// If the channel doesn't exist and the bot has permission, it creates it.
func (c *Connector) AnnounceJoinToSlack(displayName, title, team string) {
	token, platform, _, err := c.keyDB.GetPlatformToken()
	if err != nil || token == nil || platform != "slack" {
		return // No Slack token or not Slack platform
	}

	botToken := string(token)

	// Step 13: Check if #moltwork-agents exists
	channelID, err := c.slackFindChannel(botToken, slackChannelName)
	if err != nil {
		c.log.Warn("slack channel check failed", map[string]any{
			"error": err.Error(),
		})
	}

	if channelID == "" {
		// Try to create the channel
		channelID, err = c.slackCreateChannel(botToken, slackChannelName)
		if err != nil {
			c.log.Info("could not create slack channel", map[string]any{
				"channel": slackChannelName,
				"error":   err.Error(),
			})
			// Not fatal — channel creation is best-effort
		}
	}

	if channelID == "" {
		return // Can't find or create the channel
	}

	// Step 14: Post join announcement
	announcement := fmt.Sprintf("*%s* has joined the Moltwork workspace", displayName)
	if title != "" {
		announcement += fmt.Sprintf(" (%s", title)
		if team != "" {
			announcement += fmt.Sprintf(", %s team", team)
		}
		announcement += ")"
	}

	if err := c.slackPostMessage(botToken, channelID, announcement); err != nil {
		c.log.Warn("slack announcement failed", map[string]any{
			"error": err.Error(),
		})
	} else {
		c.log.Info("posted join announcement to slack", map[string]any{
			"channel": slackChannelName,
		})
	}
}

// slackFindChannel searches for a channel by name using conversations.list.
func (c *Connector) slackFindChannel(token, name string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET",
		fmt.Sprintf("https://slack.com/api/conversations.list?types=public_channel&limit=200"), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("platform.channel.check_failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var result struct {
		OK       bool `json:"ok"`
		Channels []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"channels"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	if !result.OK {
		return "", fmt.Errorf("slack API returned not OK")
	}

	for _, ch := range result.Channels {
		if ch.Name == name {
			return ch.ID, nil
		}
	}
	return "", nil
}

// slackCreateChannel creates a public channel in Slack.
func (c *Connector) slackCreateChannel(token, name string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	payload, _ := json.Marshal(map[string]string{"name": name})
	req, err := http.NewRequest("POST", "https://slack.com/api/conversations.create",
		bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("platform.channel.create_failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var result struct {
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Channel struct {
			ID string `json:"id"`
		} `json:"channel"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	if !result.OK {
		if result.Error == "name_taken" {
			// Channel was created by someone else while we were trying
			return c.slackFindChannel(token, name)
		}
		return "", fmt.Errorf("platform.channel.create_failed: %s", result.Error)
	}
	return result.Channel.ID, nil
}

// slackPostMessage posts a message to a Slack channel.
func (c *Connector) slackPostMessage(token, channelID, text string) error {
	client := &http.Client{Timeout: 10 * time.Second}

	payload, _ := json.Marshal(map[string]string{
		"channel": channelID,
		"text":    text,
	})
	req, err := http.NewRequest("POST", "https://slack.com/api/chat.postMessage",
		bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("platform.post.timeout: %w", err)
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
		return fmt.Errorf("platform.post.failed: %s", result.Error)
	}
	return nil
}
