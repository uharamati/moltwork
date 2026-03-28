package connector

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/channel"
	"moltwork/internal/config"
	"moltwork/internal/crypto"
	"moltwork/internal/identity"
)

func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "moltwork-connector-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestConnectorStartAndClose(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := config.Default()
	cfg.DataDir = tempDir(t)
	cfg.ListenPort = 0

	conn := New(cfg)
	if err := conn.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if conn.KeyPair() == nil {
		t.Error("should have keypair")
	}
	if conn.GossipNode() == nil {
		t.Error("should have gossip node")
	}
}

func TestBootstrapWorkspace(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := config.Default()
	cfg.DataDir = tempDir(t)
	cfg.ListenPort = 0

	conn := New(cfg)
	if err := conn.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Bootstrap the workspace
	if err := conn.Bootstrap("slack", "test.slack.com"); err != nil {
		t.Fatal(err)
	}

	// Verify: DAG should have entries (trust boundary + registration + 4 channels + intro)
	if conn.DAG().Len() < 6 {
		t.Errorf("expected at least 6 entries, got %d", conn.DAG().Len())
	}

	// Verify: 4 permanent channels exist
	channels := conn.Channels().List(conn.KeyPair().Public)
	if len(channels) != 4 {
		t.Errorf("expected 4 channels, got %d", len(channels))
	}

	// Verify: agent is registered
	if conn.Registry().Count() != 1 {
		t.Errorf("expected 1 agent in registry, got %d", conn.Registry().Count())
	}

	// Verify: log DB has entries
	count, _ := conn.LogDB().EntryCount()
	if count < 6 {
		t.Errorf("expected at least 6 log entries, got %d", count)
	}
}

func TestSendPublicMessage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := config.Default()
	cfg.DataDir = tempDir(t)
	cfg.ListenPort = 0

	conn := New(cfg)
	conn.Start(ctx)
	defer conn.Close()

	conn.Bootstrap("slack", "test.slack.com")

	// Find #general channel
	channels := conn.Channels().List(conn.KeyPair().Public)
	var generalID []byte
	for _, ch := range channels {
		if ch.Name == "general" {
			generalID = ch.ID
			break
		}
	}
	if generalID == nil {
		t.Fatal("general channel not found")
	}

	// Send a message
	beforeCount := conn.DAG().Len()
	if err := conn.SendMessage(generalID, []byte("hello agents"), 0, "", "", "", ""); err != nil {
		t.Fatal(err)
	}

	afterCount := conn.DAG().Len()
	if afterCount != beforeCount+1 {
		t.Errorf("expected 1 new entry, got %d", afterCount-beforeCount)
	}
}

// TestSealedEntryRoundTrip verifies that messages sent to encrypted channels
// are wrapped as SealedEntry and can be decrypted back.
func TestSealedEntryRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := config.Default()
	cfg.DataDir = tempDir(t)
	cfg.ListenPort = 0

	conn := New(cfg)
	conn.Start(ctx)
	defer conn.Close()
	conn.Bootstrap("slack", "test.slack.com")

	// Create a private channel
	ch, groupKey, err := channel.CreatePrivateChannel(conn.Channels(), "secret-test", "test private channel", conn.KeyPair().Public)
	if err != nil {
		t.Fatal(err)
	}

	// Store the group key so encryption/decryption works
	conn.KeyDB().SetGroupKey(ch.ID, 0, groupKey[:])

	// Publish channel create entry to DAG
	chCreate := moltcbor.ChannelCreate{
		ChannelID:   ch.ID,
		Name:        ch.Name,
		Description: ch.Description,
		ChannelType: moltcbor.ChannelTypePrivate,
	}
	payload, _ := moltcbor.Marshal(chCreate)
	conn.publishEntry(moltcbor.EntryTypeChannelCreate, payload)

	// Send a message to the private channel
	testContent := "this is a secret message"
	err = conn.SendMessage(ch.ID, []byte(testContent), 0, "", "", "", "")
	if err != nil {
		t.Fatal("send to private channel:", err)
	}

	// Verify: the log should have a SealedEntry, not a Message entry
	sealedEntries, err := conn.LogDB().EntriesByType(int(moltcbor.EntryTypeSealedEntry))
	if err != nil {
		t.Fatal(err)
	}
	if len(sealedEntries) == 0 {
		t.Fatal("expected at least one SealedEntry in log, got none")
	}

	// Verify: no message entry should exist for this message (it should be sealed)
	msgEntries, _ := conn.LogDB().EntriesByType(int(moltcbor.EntryTypeMessage))
	for _, e := range msgEntries {
		// Decode to check if any message entry has our private channel ID
		p := decodePayload(e)
		if p == nil {
			continue
		}
		var msg moltcbor.Message
		if err := moltcbor.Unmarshal(p, &msg); err == nil {
			if hex.EncodeToString(msg.ChannelID) == hex.EncodeToString(ch.ID) {
				t.Error("found unencrypted Message entry for private channel — should be SealedEntry")
			}
		}
	}

	// Verify: can decrypt the sealed entry and get the original content
	channelIDHex := hex.EncodeToString(ch.ID)
	msgs, err := conn.GetMessages(channelIDHex, 0, 100)
	if err != nil {
		t.Fatal("get messages:", err)
	}

	found := false
	for _, m := range msgs {
		if m.Content == testContent {
			found = true
			if m.ActivityType != "message" {
				t.Errorf("expected activity_type 'message', got %q", m.ActivityType)
			}
			break
		}
	}
	if !found {
		t.Errorf("decrypted message not found. Got %d messages: %v", len(msgs), msgs)
	}
}

// TestSealedEntryThread verifies that thread replies to encrypted channels
// are also wrapped as SealedEntry.
func TestSealedEntryThread(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := config.Default()
	cfg.DataDir = tempDir(t)
	cfg.ListenPort = 0

	conn := New(cfg)
	conn.Start(ctx)
	defer conn.Close()
	conn.Bootstrap("slack", "test.slack.com")

	// Create private channel with group key
	ch, groupKey, err := channel.CreatePrivateChannel(conn.Channels(), "thread-test", "", conn.KeyPair().Public)
	if err != nil {
		t.Fatal(err)
	}
	conn.KeyDB().SetGroupKey(ch.ID, 0, groupKey[:])

	chCreate := moltcbor.ChannelCreate{ChannelID: ch.ID, Name: ch.Name, ChannelType: moltcbor.ChannelTypePrivate}
	payload, _ := moltcbor.Marshal(chCreate)
	conn.publishEntry(moltcbor.EntryTypeChannelCreate, payload)

	// Send parent message
	err = conn.SendMessage(ch.ID, []byte("parent msg"), 0, "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Get the sealed entry hash to use as parent
	sealed, _ := conn.LogDB().EntriesByType(int(moltcbor.EntryTypeSealedEntry))
	if len(sealed) == 0 {
		t.Fatal("no sealed entries")
	}
	parentHash := sealed[len(sealed)-1].Hash

	// Send thread reply
	err = conn.SendThreadMessage(ch.ID, parentHash, []byte("thread reply"))
	if err != nil {
		t.Fatal(err)
	}

	// Should now have 2 sealed entries
	sealed2, _ := conn.LogDB().EntriesByType(int(moltcbor.EntryTypeSealedEntry))
	if len(sealed2) < 2 {
		t.Errorf("expected at least 2 sealed entries, got %d", len(sealed2))
	}

	// No thread message entries should exist for this channel
	threadEntries, _ := conn.LogDB().EntriesByType(int(moltcbor.EntryTypeThreadMessage))
	for _, e := range threadEntries {
		p := decodePayload(e)
		if p == nil {
			continue
		}
		var msg moltcbor.ThreadMessage
		if err := moltcbor.Unmarshal(p, &msg); err == nil {
			if hex.EncodeToString(msg.ChannelID) == hex.EncodeToString(ch.ID) {
				t.Error("found unencrypted ThreadMessage entry for private channel")
			}
		}
	}
}

// TestPairwiseRotation verifies the pairwise key rotation mechanism.
func TestPairwiseRotation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := config.Default()
	cfg.DataDir = tempDir(t)
	cfg.ListenPort = 0

	conn := New(cfg)
	conn.Start(ctx)
	defer conn.Close()
	conn.Bootstrap("slack", "test.slack.com")

	// Simulate a second agent by registering it manually
	peerKP, _ := crypto.GenerateSigningKeyPair()
	peerExchKP, _ := crypto.GenerateExchangeKeyPair()

	if err := conn.Registry().Register(&identity.Agent{
		PublicKey:      peerKP.Public,
		ExchangePubKey: peerExchKP.Public[:],
		PlatformUserID: "U_PEER_ROTATION",
		Platform:       "slack",
		DisplayName:    "Peer Agent",
	}); err != nil {
		t.Fatal("register peer:", err)
	}

	// Derive initial pairwise secret
	peerExchPub := peerExchKP.Public
	initialSecret, err := crypto.DerivePairwiseSecret(conn.ExchangeKey(), peerExchPub)
	if err != nil {
		t.Fatal(err)
	}
	conn.KeyDB().SetPairwiseSecret(peerKP.Public, initialSecret[:], 0)

	// Verify initial secret works
	oldSecret, oldEpoch, _ := conn.KeyDB().GetPairwiseSecret(peerKP.Public)
	if oldSecret == nil {
		t.Fatal("no initial pairwise secret")
	}
	if oldEpoch != 0 {
		t.Errorf("expected epoch 0, got %d", oldEpoch)
	}

	// Perform rotation
	err = conn.rotatePairwiseWith(peerKP.Public)
	if err != nil {
		t.Fatal("rotation failed:", err)
	}

	// Verify: epoch incremented
	newSecret, newEpoch, _ := conn.KeyDB().GetPairwiseSecret(peerKP.Public)
	if newSecret == nil {
		t.Fatal("no pairwise secret after rotation")
	}
	if newEpoch != 1 {
		t.Errorf("expected epoch 1 after rotation, got %d", newEpoch)
	}

	// Verify: secret actually changed
	if hex.EncodeToString(oldSecret) == hex.EncodeToString(newSecret) {
		t.Error("secret did not change after rotation")
	}

	// Verify: a PairwiseKeyExchange entry was published to the log
	exchEntries, _ := conn.LogDB().EntriesByType(int(moltcbor.EntryTypePairwiseKeyExchange))
	if len(exchEntries) == 0 {
		t.Error("expected PairwiseKeyExchange entry in log after rotation")
	}
}

// TestPairwiseRotationScheduler verifies that overdue rotations are detected.
func TestPairwiseRotationScheduler(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := config.Default()
	cfg.DataDir = tempDir(t)
	cfg.ListenPort = 0
	cfg.KeyRotationInterval = 1 // 1 second for testing

	conn := New(cfg)
	conn.Start(ctx)
	defer conn.Close()
	conn.Bootstrap("slack", "test.slack.com")

	// Add a peer with an old rotation timestamp
	peerKP, _ := crypto.GenerateSigningKeyPair()
	peerExchKP, _ := crypto.GenerateExchangeKeyPair()

	conn.Registry().Register(&identity.Agent{
		PublicKey:      peerKP.Public,
		ExchangePubKey: peerExchKP.Public[:],
		PlatformUserID: "U_PEER_SCHED",
		Platform:       "slack",
		DisplayName:    "Old Peer",
	})

	secret, _ := crypto.DerivePairwiseSecret(conn.ExchangeKey(), peerExchKP.Public)
	conn.KeyDB().SetPairwiseSecret(peerKP.Public, secret[:], 0)

	// Wait for the rotation interval to expire
	time.Sleep(2 * time.Second)

	// Check overdue rotations
	overdue := conn.OverdueRotations()
	if overdue == 0 {
		t.Error("expected overdue rotations after interval elapsed")
	}
}

// TestActionRequestValidation verifies that action requests require the action field.
func TestActionRequestValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := config.Default()
	cfg.DataDir = tempDir(t)
	cfg.ListenPort = 0

	conn := New(cfg)
	conn.Start(ctx)
	defer conn.Close()
	conn.Bootstrap("slack", "test.slack.com")

	// Find #general
	var generalID []byte
	for _, ch := range conn.Channels().List(conn.KeyPair().Public) {
		if ch.Name == "general" {
			generalID = ch.ID
			break
		}
	}

	// Action request (type=1) without action field should fail
	err := conn.SendMessage(generalID, []byte("do something"), 1, "", "", "", "")
	if err == nil {
		t.Error("expected error when sending action request without action field")
	}

	// Action request with action field should succeed
	err = conn.SendMessage(generalID, []byte("please review this"), 1, "review_document", "engineering", "team_lead", "normal")
	if err != nil {
		t.Errorf("action request with proper fields should succeed: %v", err)
	}

	// Discussion (type=0) without action field should succeed
	err = conn.SendMessage(generalID, []byte("just chatting"), 0, "", "", "", "")
	if err != nil {
		t.Errorf("discussion should not require action field: %v", err)
	}
}

// TestActivityEndpointScope verifies that GetNewActivity returns multiple entry types.
func TestActivityEndpointScope(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := config.Default()
	cfg.DataDir = tempDir(t)
	cfg.ListenPort = 0

	conn := New(cfg)
	conn.Start(ctx)
	defer conn.Close()
	conn.Bootstrap("slack", "test.slack.com")

	// Find #general and send a message
	var generalID []byte
	for _, ch := range conn.Channels().List(conn.KeyPair().Public) {
		if ch.Name == "general" {
			generalID = ch.ID
			break
		}
	}
	conn.SendMessage(generalID, []byte("activity test"), 0, "", "", "", "")

	// Create a new public channel (generates a channel_create activity)
	channel.CreatePublicChannel(conn.Channels(), "activity-ch", "for testing", conn.KeyPair().Public)
	chCreate := moltcbor.ChannelCreate{
		ChannelID:   []byte("activity-ch-id-test"),
		Name:        "activity-ch",
		ChannelType: moltcbor.ChannelTypePublic,
	}
	payload, _ := moltcbor.Marshal(chCreate)
	conn.publishEntry(moltcbor.EntryTypeChannelCreate, payload)

	// Get all activity
	activity, err := conn.GetNewActivity(0, 1000)
	if err != nil {
		t.Fatal(err)
	}

	// Should have various activity types
	typesSeen := make(map[string]bool)
	for _, msg := range activity {
		if msg.ActivityType != "" {
			typesSeen[msg.ActivityType] = true
		}
	}

	if !typesSeen["message"] {
		t.Error("expected 'message' activity type in results")
	}
	if !typesSeen["channel_create"] {
		t.Error("expected 'channel_create' activity type in results")
	}
	if len(activity) < 2 {
		t.Errorf("expected at least 2 activity items, got %d", len(activity))
	}
}

// TestSubscribeUnsubscribe verifies the subscriber notification mechanism:
// subscribe, trigger a notification, verify received, unsubscribe, verify no more.
func TestSubscribeUnsubscribe(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := config.Default()
	cfg.DataDir = tempDir(t)
	cfg.ListenPort = 0

	conn := New(cfg)
	conn.Start(ctx)
	defer conn.Close()
	conn.Bootstrap("slack", "test.slack.com")

	// Subscribe
	ch := conn.Subscribe()
	defer conn.Unsubscribe(ch)

	// Find #general channel
	var generalID []byte
	for _, c := range conn.Channels().List(conn.KeyPair().Public) {
		if c.Name == "general" {
			generalID = c.ID
			break
		}
	}
	if generalID == nil {
		t.Fatal("general channel not found")
	}

	// Send a message (triggers notifySubscribers)
	if err := conn.SendMessage(generalID, []byte("subscriber test"), 0, "", "", "", ""); err != nil {
		t.Fatal(err)
	}

	// Should receive notification
	select {
	case <-ch:
		// Got notification — success
	case <-time.After(2 * time.Second):
		t.Error("expected notification after sending message, timed out")
	}

	// Unsubscribe
	conn.Unsubscribe(ch)

	// Send another message
	conn.SendMessage(generalID, []byte("after unsub"), 0, "", "", "", "")

	// Should NOT receive notification (already unsubscribed)
	select {
	case <-ch:
		// Buffered channel may still have one signal from before — drain it
		select {
		case <-ch:
			t.Error("should not receive notification after unsubscribe")
		case <-time.After(200 * time.Millisecond):
			// Good — no notification
		}
	case <-time.After(200 * time.Millisecond):
		// Good — no notification
	}
}

// TestNotifySubscribersNonBlocking verifies that notifying subscribers doesn't
// block even when a subscriber doesn't read from its channel.
func TestNotifySubscribersNonBlocking(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := config.Default()
	cfg.DataDir = tempDir(t)
	cfg.ListenPort = 0

	conn := New(cfg)
	conn.Start(ctx)
	defer conn.Close()
	conn.Bootstrap("slack", "test.slack.com")

	// Subscribe but never read from the channel
	ch := conn.Subscribe()
	defer conn.Unsubscribe(ch)

	// Find #general
	var generalID []byte
	for _, c := range conn.Channels().List(conn.KeyPair().Public) {
		if c.Name == "general" {
			generalID = c.ID
			break
		}
	}

	// Send multiple messages — notify should not block
	done := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			conn.SendMessage(generalID, []byte(fmt.Sprintf("msg-%d", i)), 0, "", "", "", "")
		}
		close(done)
	}()

	select {
	case <-done:
		// All sends completed without blocking — success
	case <-time.After(5 * time.Second):
		t.Error("notify blocked when subscriber didn't read — should be non-blocking")
	}
}

// TestCapabilityDeclaration verifies capability declare and retrieve.
func TestCapabilityDeclaration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := config.Default()
	cfg.DataDir = tempDir(t)
	cfg.ListenPort = 0

	conn := New(cfg)
	conn.Start(ctx)
	defer conn.Close()
	conn.Bootstrap("slack", "test.slack.com")

	// Publish a capability declaration
	decl := moltcbor.CapabilityDeclaration{
		Capabilities: []string{"read_email", "search_docs"},
		Restrictions: []string{"cannot_send_email", "no_file_access"},
	}
	payload, err := moltcbor.Marshal(decl)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.publishEntry(moltcbor.EntryTypeCapabilityDecl, payload); err != nil {
		t.Fatal(err)
	}

	// Verify: entry exists in log
	entries, err := conn.LogDB().EntriesByType(int(moltcbor.EntryTypeCapabilityDecl))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Error("expected capability declaration entry in log")
	}

	// Verify: entry is authored by our agent
	if len(entries) > 0 {
		if hex.EncodeToString(entries[0].AuthorKey) != hex.EncodeToString(conn.KeyPair().Public) {
			t.Error("capability entry author mismatch")
		}
	}
}
