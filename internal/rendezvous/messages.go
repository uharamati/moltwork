package rendezvous

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Message type tags used in fenced code blocks.
const (
	TagRendezvous   = "moltwork-rendezvous"
	TagJoinRequest  = "moltwork-join-request"
	TagJoinResponse = "moltwork-join-response"
	TagClaim        = "moltwork-claim"
)

// gossipAddrJSON is the wire format for gossip address messages.
type gossipAddrJSON struct {
	Type      string `json:"type"`
	PeerID    string `json:"peer_id"`
	Multiaddr string `json:"multiaddr"`
	SyncURL   string `json:"sync_url,omitempty"`
	PubKey    string `json:"pubkey"` // base64
	Timestamp int64  `json:"ts"`
}

// joinRequestJSON is the wire format for join request messages.
type joinRequestJSON struct {
	Type            string `json:"type"`
	SlackUserID     string `json:"slack_user_id"`
	EphemeralPubKey string `json:"ephemeral_pubkey"` // base64
	AgentName       string `json:"agent_name"`
	Timestamp       int64  `json:"ts"`
}

// joinResponseJSON is the wire format for join response messages.
type joinResponseJSON struct {
	Type         string `json:"type"`
	EncryptedPSK string `json:"encrypted_psk"` // base64
	ResponderKey string `json:"responder_key"` // base64
}

// claimJSON is the wire format for claim messages.
type claimJSON struct {
	Type       string `json:"type"`
	ClaimerKey string `json:"claimer_key"` // base64
	Timestamp  int64  `json:"ts"`
}

// FormatGossipAddress builds a Slack message advertising a gossip address.
// Format: human-readable text + fenced code block with machine-readable JSON.
func FormatGossipAddress(agentName string, addr GossipAddress) string {
	data := gossipAddrJSON{
		Type:      "gossip_addr",
		PeerID:    addr.PeerID,
		Multiaddr: addr.Multiaddr,
		SyncURL:   addr.SyncURL,
		PubKey:    base64.StdEncoding.EncodeToString(addr.PublicKey),
		Timestamp: addr.Timestamp,
	}
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Sprintf("error: failed to marshal gossip address: %s", err.Error())
	}
	return fmt.Sprintf("*%s* is online in Moltwork\n```%s\n%s\n```",
		agentName, TagRendezvous, string(jsonBytes))
}

// FormatJoinRequest builds a Slack message for a join request.
func FormatJoinRequest(req JoinRequest) string {
	data := joinRequestJSON{
		Type:            "join_req",
		SlackUserID:     req.SlackUserID,
		EphemeralPubKey: base64.StdEncoding.EncodeToString(req.EphemeralPubKey),
		AgentName:       req.AgentName,
		Timestamp:       req.Timestamp,
	}
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Sprintf("error: failed to marshal join request: %s", err.Error())
	}
	return fmt.Sprintf("*%s* (Slack user <@%s>) is requesting to join Moltwork\n```%s\n%s\n```",
		req.AgentName, req.SlackUserID, TagJoinRequest, string(jsonBytes))
}

// FormatJoinResponse builds a threaded reply with the encrypted PSK.
func FormatJoinResponse(agentName string, resp JoinResponse) string {
	data := joinResponseJSON{
		Type:         "join_resp",
		EncryptedPSK: base64.StdEncoding.EncodeToString(resp.EncryptedPSK),
		ResponderKey: base64.StdEncoding.EncodeToString(resp.ResponderKey),
	}
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Sprintf("error: failed to marshal join response: %s", err.Error())
	}
	return fmt.Sprintf("PSK delivered to *%s*\n```%s\n%s\n```",
		agentName, TagJoinResponse, string(jsonBytes))
}

// FormatClaim builds a threaded reply to claim a join request (rule SR5).
func FormatClaim(claimerKey []byte) string {
	data := claimJSON{
		Type:       "claim",
		ClaimerKey: base64.StdEncoding.EncodeToString(claimerKey),
	}
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Sprintf("error: failed to marshal claim: %s", err.Error())
	}
	return fmt.Sprintf("Handling this join request\n```%s\n%s\n```",
		TagClaim, string(jsonBytes))
}

// ParseGossipAddress extracts a GossipAddress from a Slack message text.
// Returns nil if the message doesn't contain a rendezvous code block.
func ParseGossipAddress(text string) *GossipAddress {
	jsonStr := extractCodeBlock(text, TagRendezvous)
	if jsonStr == "" {
		return nil
	}

	var data gossipAddrJSON
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return nil
	}
	if data.Type != "gossip_addr" {
		return nil
	}

	pubKey, err := base64.StdEncoding.DecodeString(data.PubKey)
	if err != nil {
		return nil
	}

	// Slack auto-links URLs, wrapping them in <> (e.g. <http://...>).
	// Strip the angle brackets so the URL is usable.
	syncURL := strings.TrimPrefix(strings.TrimSuffix(data.SyncURL, ">"), "<")

	return &GossipAddress{
		PeerID:    data.PeerID,
		Multiaddr: data.Multiaddr,
		SyncURL:   syncURL,
		PublicKey:  pubKey,
		Timestamp: data.Timestamp,
	}
}

// ParseJoinRequest extracts a JoinRequest from a Slack message text.
// Returns nil if the message doesn't contain a join request code block.
func ParseJoinRequest(text string) *JoinRequest {
	jsonStr := extractCodeBlock(text, TagJoinRequest)
	if jsonStr == "" {
		return nil
	}

	var data joinRequestJSON
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return nil
	}
	if data.Type != "join_req" {
		return nil
	}

	ephPub, err := base64.StdEncoding.DecodeString(data.EphemeralPubKey)
	if err != nil {
		return nil
	}

	return &JoinRequest{
		SlackUserID:     data.SlackUserID,
		EphemeralPubKey: ephPub,
		AgentName:       data.AgentName,
		Timestamp:       data.Timestamp,
	}
}

// ParseJoinResponse extracts a JoinResponse from a Slack message text.
// Returns nil if the message doesn't contain a join response code block.
func ParseJoinResponse(text string) *JoinResponse {
	jsonStr := extractCodeBlock(text, TagJoinResponse)
	if jsonStr == "" {
		return nil
	}

	var data joinResponseJSON
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return nil
	}
	if data.Type != "join_resp" {
		return nil
	}

	encPSK, err := base64.StdEncoding.DecodeString(data.EncryptedPSK)
	if err != nil {
		return nil
	}
	respKey, err := base64.StdEncoding.DecodeString(data.ResponderKey)
	if err != nil {
		return nil
	}

	return &JoinResponse{
		EncryptedPSK: encPSK,
		ResponderKey: respKey,
	}
}

// Claim represents a parsed claim message with the claimer's public key.
type Claim struct {
	ClaimerKey []byte
}

// ParseClaim checks if a message is a claim reply. Returns the parsed Claim
// with the claimer's public key, or nil if the message is not a claim.
func ParseClaim(text string) *Claim {
	jsonStr := extractCodeBlock(text, TagClaim)
	if jsonStr == "" {
		return nil
	}

	var data claimJSON
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return nil
	}
	if data.Type != "claim" {
		return nil
	}

	key, err := base64.StdEncoding.DecodeString(data.ClaimerKey)
	if err != nil {
		return nil
	}
	return &Claim{ClaimerKey: key}
}

// extractCodeBlock finds a fenced code block with the given tag and
// returns its JSON content. Expected format:
//
//	```tag
//	{"key":"value",...}
//	```
func extractCodeBlock(text, tag string) string {
	opener := "```" + tag
	idx := strings.Index(text, opener)
	if idx == -1 {
		return ""
	}

	// Move past the opener and any whitespace/newline
	content := text[idx+len(opener):]
	content = strings.TrimLeft(content, " \t\r\n")

	// Find the closing ```
	closeIdx := strings.Index(content, "```")
	if closeIdx == -1 {
		return ""
	}

	return strings.TrimSpace(content[:closeIdx])
}
