package cbor

import (
	"bytes"
	"strings"
	"testing"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	original := Envelope{
		Version: ProtocolVersion,
		Type:    EntryTypeMessage,
		Payload: []byte{0x01, 0x02, 0x03},
	}

	data, err := Marshal(original)
	if err != nil {
		t.Fatal(err)
	}

	var decoded Envelope
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.Version != original.Version {
		t.Errorf("version: got %d, want %d", decoded.Version, original.Version)
	}
	if decoded.Type != original.Type {
		t.Errorf("type: got %d, want %d", decoded.Type, original.Type)
	}
	if !bytes.Equal(decoded.Payload, original.Payload) {
		t.Error("payload mismatch")
	}
}

func TestAgentRegistrationRoundTrip(t *testing.T) {
	reg := AgentRegistration{
		PublicKey:      bytes.Repeat([]byte{0xAA}, 32),
		PlatformUserID: "U12345",
		Platform:       "slack",
		DisplayName:    "Alice Agent",
		Title:          "Software Engineer",
		Team:           "Platform",
	}

	data, err := Marshal(reg)
	if err != nil {
		t.Fatal(err)
	}

	var decoded AgentRegistration
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.PlatformUserID != reg.PlatformUserID {
		t.Errorf("platform user id: got %s, want %s", decoded.PlatformUserID, reg.PlatformUserID)
	}
	if decoded.DisplayName != reg.DisplayName {
		t.Errorf("display name: got %s, want %s", decoded.DisplayName, reg.DisplayName)
	}
}

func TestMessageRoundTrip(t *testing.T) {
	msg := Message{
		ChannelID:   []byte("chan-general"),
		Content:     []byte("hello agents"),
		MessageType: 0, // discussion
	}

	data, err := Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	var decoded Message
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decoded.Content, msg.Content) {
		t.Error("content mismatch")
	}
}

func TestChannelCreateRoundTrip(t *testing.T) {
	ch := ChannelCreate{
		ChannelID:   []byte("chan-123"),
		Name:        "project-alpha",
		Description: "Alpha project coordination",
		ChannelType: ChannelTypePublic,
	}

	data, err := Marshal(ch)
	if err != nil {
		t.Fatal(err)
	}

	var decoded ChannelCreate
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.Name != ch.Name {
		t.Errorf("name: got %s, want %s", decoded.Name, ch.Name)
	}
	if decoded.ChannelType != ch.ChannelType {
		t.Errorf("type: got %d, want %d", decoded.ChannelType, ch.ChannelType)
	}
}

func TestRevocationRoundTrip(t *testing.T) {
	rev := Revocation{
		RevokedKeyHash: bytes.Repeat([]byte{0xBB}, 32),
		Reason:         RevocationByManager,
		Timestamp:      1711234567,
		Signatures:     [][]byte{bytes.Repeat([]byte{0xCC}, 64)},
		Revokers:       [][]byte{bytes.Repeat([]byte{0xDD}, 32)},
	}

	data, err := Marshal(rev)
	if err != nil {
		t.Fatal(err)
	}

	var decoded Revocation
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.Reason != RevocationByManager {
		t.Errorf("reason: got %d, want %d", decoded.Reason, RevocationByManager)
	}
	if decoded.Timestamp != rev.Timestamp {
		t.Errorf("timestamp: got %d, want %d", decoded.Timestamp, rev.Timestamp)
	}
}

func TestOrgRelationshipRoundTrip(t *testing.T) {
	rel := OrgRelationship{
		SubjectPubKey: bytes.Repeat([]byte{0x01}, 32),
		ManagerPubKey: bytes.Repeat([]byte{0x02}, 32),
		SubjectSig:    bytes.Repeat([]byte{0x03}, 64),
		ManagerSig:    bytes.Repeat([]byte{0x04}, 64),
		Timestamp:     1711234567,
	}

	data, err := Marshal(rel)
	if err != nil {
		t.Fatal(err)
	}

	var decoded OrgRelationship
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decoded.SubjectPubKey, rel.SubjectPubKey) {
		t.Error("subject pubkey mismatch")
	}
}

func TestSizeLimit(t *testing.T) {
	oversized := make([]byte, MaxEntrySize+1)
	var v Envelope
	err := Unmarshal(oversized, &v)
	if err == nil {
		t.Error("should reject oversized data")
	}
	if !strings.Contains(err.Error(), "exceeds max size") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestIndefLengthRejected(t *testing.T) {
	// CBOR indefinite-length byte string: 0x5F followed by chunks
	// This should be rejected by strict mode
	indefBytes := []byte{0x5F, 0x41, 0xAA, 0xFF}
	var v []byte
	err := Unmarshal(indefBytes, &v)
	if err == nil {
		t.Error("should reject indefinite-length encoding")
	}
}

func TestNestedEnvelopeWithPayload(t *testing.T) {
	// Encode a payload, then wrap in envelope
	msg := Message{
		ChannelID:   []byte("chan-1"),
		Content:     []byte("test message"),
		MessageType: 0,
	}
	payloadBytes, err := Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	env := Envelope{
		Version: ProtocolVersion,
		Type:    EntryTypeMessage,
		Payload: payloadBytes,
	}
	envBytes, err := Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	// Decode envelope, then decode payload
	var decodedEnv Envelope
	if err := Unmarshal(envBytes, &decodedEnv); err != nil {
		t.Fatal(err)
	}

	if decodedEnv.Version != ProtocolVersion {
		t.Fatal("version check failed — rule B4 violation")
	}

	var decodedMsg Message
	if err := Unmarshal(decodedEnv.Payload, &decodedMsg); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decodedMsg.Content, msg.Content) {
		t.Error("nested payload content mismatch")
	}
}
