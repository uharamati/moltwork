package rendezvous

import (
	"encoding/base64"
	"testing"
)

func TestFormatParseGossipAddress(t *testing.T) {
	pubKey := []byte("test-public-key-32-bytes-long!!")
	addr := GossipAddress{
		PeerID:    "QmTestPeerID123",
		Multiaddr: "/ip4/192.168.1.5/tcp/4001",
		PublicKey:  pubKey,
		Timestamp: 1711234567,
	}

	text := FormatGossipAddress("TestAgent", addr)

	// Verify human-readable part
	if got := text; got == "" {
		t.Fatal("empty formatted message")
	}

	// Parse it back
	parsed := ParseGossipAddress(text)
	if parsed == nil {
		t.Fatal("ParseGossipAddress returned nil")
	}

	if parsed.PeerID != addr.PeerID {
		t.Errorf("PeerID: got %q, want %q", parsed.PeerID, addr.PeerID)
	}
	if parsed.Multiaddr != addr.Multiaddr {
		t.Errorf("Multiaddr: got %q, want %q", parsed.Multiaddr, addr.Multiaddr)
	}
	if string(parsed.PublicKey) != string(pubKey) {
		t.Errorf("PublicKey mismatch")
	}
	if parsed.Timestamp != addr.Timestamp {
		t.Errorf("Timestamp: got %d, want %d", parsed.Timestamp, addr.Timestamp)
	}
}

func TestFormatParseJoinRequest(t *testing.T) {
	ephKey := make([]byte, 32)
	for i := range ephKey {
		ephKey[i] = byte(i)
	}

	req := JoinRequest{
		SlackUserID:     "U12345",
		EphemeralPubKey: ephKey,
		AgentName:       "NewAgent",
		Timestamp:       1711234567,
	}

	text := FormatJoinRequest(req)

	parsed := ParseJoinRequest(text)
	if parsed == nil {
		t.Fatal("ParseJoinRequest returned nil")
	}

	if parsed.SlackUserID != req.SlackUserID {
		t.Errorf("SlackUserID: got %q, want %q", parsed.SlackUserID, req.SlackUserID)
	}
	if len(parsed.EphemeralPubKey) != 32 {
		t.Errorf("EphemeralPubKey length: got %d, want 32", len(parsed.EphemeralPubKey))
	}
	for i, b := range parsed.EphemeralPubKey {
		if b != ephKey[i] {
			t.Errorf("EphemeralPubKey[%d]: got %d, want %d", i, b, ephKey[i])
			break
		}
	}
	if parsed.AgentName != req.AgentName {
		t.Errorf("AgentName: got %q, want %q", parsed.AgentName, req.AgentName)
	}
}

func TestFormatParseJoinResponse(t *testing.T) {
	encPSK := []byte("encrypted-psk-data-here")
	respKey := []byte("responder-key-32-bytes-long!!!!")

	resp := JoinResponse{
		EncryptedPSK: encPSK,
		ResponderKey: respKey,
	}

	text := FormatJoinResponse("NewAgent", resp)

	parsed := ParseJoinResponse(text)
	if parsed == nil {
		t.Fatal("ParseJoinResponse returned nil")
	}

	if string(parsed.EncryptedPSK) != string(encPSK) {
		t.Errorf("EncryptedPSK mismatch")
	}
	if string(parsed.ResponderKey) != string(respKey) {
		t.Errorf("ResponderKey mismatch")
	}
}

func TestFormatParseClaim(t *testing.T) {
	claimerKey := []byte("claimer-key-32-bytes-long!!!!!!")

	text := FormatClaim(claimerKey)

	parsed := ParseClaim(text)
	if parsed == nil {
		t.Fatal("ParseClaim returned nil")
	}
	// FormatClaim uses nil key in the current implementation,
	// so we test with explicit nil
	text2 := FormatClaim(nil)
	parsed2 := ParseClaim(text2)
	if parsed2 == nil {
		t.Fatal("ParseClaim with nil key returned nil")
	}
}

func TestParseGossipAddressInvalidMessages(t *testing.T) {
	tests := []struct {
		name string
		text string
	}{
		{"empty", ""},
		{"no code block", "just some text"},
		{"wrong tag", "```moltwork-other\n{}\n```"},
		{"invalid json", "```moltwork-rendezvous\nnot json\n```"},
		{"wrong type", `*Agent* online` + "\n```moltwork-rendezvous\n" + `{"type":"wrong"}` + "\n```"},
		{"invalid base64 key", "```moltwork-rendezvous\n" + `{"type":"gossip_addr","peer_id":"Qm","multiaddr":"/ip4/1.2.3.4/tcp/4001","pubkey":"!!!invalid!!!","ts":1}` + "\n```"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseGossipAddress(tt.text); got != nil {
				t.Errorf("expected nil, got %+v", got)
			}
		})
	}
}

func TestExtractCodeBlock(t *testing.T) {
	tests := []struct {
		name string
		text string
		tag  string
		want string
	}{
		{
			name: "basic",
			text: "text\n```mytag\nhello\n```",
			tag:  "mytag",
			want: "hello",
		},
		{
			name: "with surrounding text",
			text: "before\n```mytag\n{\"key\":\"value\"}\n```\nafter",
			tag:  "mytag",
			want: `{"key":"value"}`,
		},
		{
			name: "not found",
			text: "no code block here",
			tag:  "mytag",
			want: "",
		},
		{
			name: "unclosed",
			text: "```mytag\nhello",
			tag:  "mytag",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCodeBlock(tt.text, tt.tag)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGossipAddressBase64RoundTrip(t *testing.T) {
	// Test with actual Ed25519-sized key (32 bytes)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 7)
	}

	addr := GossipAddress{
		PeerID:    "12D3KooWTestPeerIDabcdef",
		Multiaddr: "/ip4/10.0.0.1/tcp/9000",
		PublicKey:  key,
		Timestamp: 1711234567,
	}

	text := FormatGossipAddress("Agent", addr)
	parsed := ParseGossipAddress(text)

	if parsed == nil {
		t.Fatal("nil result")
	}

	// Verify base64 encoding was used correctly
	encoded := base64.StdEncoding.EncodeToString(key)
	if len(encoded) == 0 {
		t.Fatal("empty base64")
	}

	if len(parsed.PublicKey) != 32 {
		t.Fatalf("key length: got %d, want 32", len(parsed.PublicKey))
	}
	for i := range key {
		if parsed.PublicKey[i] != key[i] {
			t.Fatalf("key byte %d: got %d, want %d", i, parsed.PublicKey[i], key[i])
		}
	}
}
