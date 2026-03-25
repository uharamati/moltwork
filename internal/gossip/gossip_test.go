package gossip

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/crypto"
	"moltwork/internal/dag"
	"moltwork/internal/logging"
	"moltwork/internal/store"
)

func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "moltwork-gossip-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)

	if !rl.Allow("alice") {
		t.Error("first request should be allowed")
	}
	if !rl.Allow("alice") {
		t.Error("second request should be allowed")
	}
	if !rl.Allow("alice") {
		t.Error("third request should be allowed")
	}
	if rl.Allow("alice") {
		t.Error("fourth request should be rate limited")
	}

	// Different author should be independent
	if !rl.Allow("bob") {
		t.Error("bob should be allowed")
	}
}

func TestTwoNodeSync(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log := logging.New("test")

	// Generate keys for two agents
	kp1, _ := crypto.GenerateSigningKeyPair()
	kp2, _ := crypto.GenerateSigningKeyPair()

	// Shared PSK
	psk := crypto.RandomBytes(32)

	// Create databases
	dir1 := tempDir(t)
	dir2 := tempDir(t)

	logDB1, err := store.OpenLogDB(filepath.Join(dir1, "log.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer logDB1.Close()

	logDB2, err := store.OpenLogDB(filepath.Join(dir2, "log.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer logDB2.Close()

	// Create an entry on node 1
	payload, _ := moltcbor.Marshal(moltcbor.Message{
		ChannelID: []byte("general"),
		Content:   []byte("hello from node 1"),
	})
	entry, err := dag.NewSignedEntry(moltcbor.EntryTypeMessage, payload, kp1, nil)
	if err != nil {
		t.Fatal(err)
	}

	err = logDB1.InsertEntry(entry.Hash[:], entry.RawCBOR, entry.AuthorKey, entry.Signature, int(moltcbor.EntryTypeMessage), entry.CreatedAt, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create an entry on node 2
	payload2, _ := moltcbor.Marshal(moltcbor.Message{
		ChannelID: []byte("general"),
		Content:   []byte("hello from node 2"),
	})
	entry2, err := dag.NewSignedEntry(moltcbor.EntryTypeMessage, payload2, kp2, nil)
	if err != nil {
		t.Fatal(err)
	}

	err = logDB2.InsertEntry(entry2.Hash[:], entry2.RawCBOR, entry2.AuthorKey, entry2.Signature, int(moltcbor.EntryTypeMessage), entry2.CreatedAt, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Verify: node 1 has 1 entry, node 2 has 1 entry
	count1, _ := logDB1.EntryCount()
	count2, _ := logDB2.EntryCount()
	if count1 != 1 || count2 != 1 {
		t.Fatalf("before sync: node1=%d, node2=%d (expected 1, 1)", count1, count2)
	}

	// Start both gossip nodes
	node1, err := NewNode(ctx, NodeConfig{
		PrivateKey:   kp1.Private,
		PSK:          psk,
		ListenPort:   0, // random port
		LogDB:        logDB1,
		Logger:       log,
		SyncInterval: 1 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer node1.Close()

	node2, err := NewNode(ctx, NodeConfig{
		PrivateKey:   kp2.Private,
		PSK:          psk,
		ListenPort:   0,
		LogDB:        logDB2,
		Logger:       log,
		SyncInterval: 1 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer node2.Close()

	// Manually introduce peers (mDNS may not work in test environment)
	node1.Tracker().HandlePeerFound(peer.AddrInfo{ID: node2.Host().ID(), Addrs: node2.Host().Addrs()})
	node2.Tracker().HandlePeerFound(peer.AddrInfo{ID: node1.Host().ID(), Addrs: node1.Host().Addrs()})

	// Allow time for libp2p connections to establish
	time.Sleep(500 * time.Millisecond)

	// Wait for sync to happen
	deadline := time.After(20 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			count1, _ = logDB1.EntryCount()
			count2, _ = logDB2.EntryCount()
			t.Fatalf("sync timeout: node1=%d, node2=%d (expected 2, 2)", count1, count2)
		case <-ticker.C:
			count1, _ = logDB1.EntryCount()
			count2, _ = logDB2.EntryCount()
			if count1 == 2 && count2 == 2 {
				// Both nodes have both entries
				t.Logf("sync successful: both nodes have 2 entries")

				// Verify node 1 has node 2's entry
				has, _ := logDB1.HasEntry(entry2.Hash[:])
				if !has {
					t.Error("node 1 missing node 2's entry")
				}

				// Verify node 2 has node 1's entry
				has, _ = logDB2.HasEntry(entry.Hash[:])
				if !has {
					t.Error("node 2 missing node 1's entry")
				}
				return
			}
		}
	}
}
