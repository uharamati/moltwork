package connector

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"moltwork/internal/crypto"
	"moltwork/internal/gossip"
)

// startHTTPSyncLoop starts a background goroutine that periodically polls
// sync peer URLs when gossip peers aren't available. This is a fallback
// for agents on different networks that can't reach each other via libp2p.
func (c *Connector) startHTTPSyncLoop(ctx context.Context) {
	if len(c.syncPeerURLs) == 0 {
		return
	}

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Only poll when gossip peers aren't available
				if c.node != nil && len(c.node.Tracker().Peers()) > 0 {
					continue
				}

				psk := c.GetPSK()
				if psk == nil {
					continue
				}

				for _, url := range c.syncPeerURLs {
					if err := c.httpChainSync(url, psk); err != nil {
						c.log.Warn("background HTTP sync failed", map[string]any{
							"url":   url,
							"error": err.Error(),
						})
						continue
					}
					c.log.Info("background HTTP sync succeeded", map[string]any{"url": url})
					break // one successful sync is enough
				}
			}
		}
	}()
}

// httpChainSync performs an initial block download from a peer's HTTP sync endpoint.
// It authenticates with the PSK using the same BLAKE3 challenge-response as gossip,
// then pulls all entries the local node is missing.
func (c *Connector) httpChainSync(syncURL string, psk []byte) error {
	client := &http.Client{Timeout: 10 * time.Second}

	// Step 1: Challenge — prove we know the PSK, verify the server does too
	token, err := c.syncChallenge(client, syncURL, psk)
	if err != nil {
		return fmt.Errorf("sync challenge: %w", err)
	}

	// Step 2: Pull — request all entries we don't have
	if err := c.syncPull(client, syncURL, token); err != nil {
		return fmt.Errorf("sync pull: %w", err)
	}

	return nil
}

// syncChallenge performs the PSK challenge-response handshake and returns a session token.
func (c *Connector) syncChallenge(client *http.Client, syncURL string, psk []byte) (string, error) {
	// Generate our challenge
	challenge := crypto.RandomBytes(32)
	proof := crypto.Hash(append(psk, challenge...))

	reqBody, _ := json.Marshal(map[string]string{
		"challenge": base64.StdEncoding.EncodeToString(challenge),
		"proof":     base64.StdEncoding.EncodeToString(proof[:]),
	})

	resp, err := client.Post(syncURL+"/api/sync/challenge", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("POST challenge: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("challenge failed (%d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		Challenge string `json:"challenge"`
		Proof     string `json:"proof"`
		Token     string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode challenge response: %w", err)
	}

	// Verify server's proof (mutual auth)
	serverChallenge, err := base64.StdEncoding.DecodeString(result.Challenge)
	if err != nil {
		return "", fmt.Errorf("decode server challenge: %w", err)
	}
	serverProof, err := base64.StdEncoding.DecodeString(result.Proof)
	if err != nil {
		return "", fmt.Errorf("decode server proof: %w", err)
	}

	expected := crypto.Hash(append(psk, serverChallenge...))
	if !crypto.ConstantTimeEqual(expected[:], serverProof) {
		return "", fmt.Errorf("server PSK proof verification failed — possible rogue sync server")
	}

	c.log.Info("HTTP sync: mutual PSK authentication succeeded", map[string]any{"url": syncURL})
	return result.Token, nil
}

// syncPull requests entries from the peer and stores them locally.
func (c *Connector) syncPull(client *http.Client, syncURL string, token string) error {
	// Get our current hashes
	localHashes, err := c.logDB.AllHashes()
	if err != nil {
		return fmt.Errorf("get local hashes: %w", err)
	}

	knownHashes := make([]string, 0, len(localHashes))
	for _, h := range localHashes {
		knownHashes = append(knownHashes, hex.EncodeToString(h))
	}

	reqBody, _ := json.Marshal(map[string]any{
		"token":        token,
		"known_hashes": knownHashes,
	})

	resp, err := client.Post(syncURL+"/api/sync/pull", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("POST pull: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("pull failed (%d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		Entries []struct {
			Hash      string   `json:"hash"`
			RawCBOR   string   `json:"raw_cbor"`
			AuthorKey string   `json:"author_key"`
			Signature string   `json:"signature"`
			EntryType int      `json:"entry_type"`
			CreatedAt int64    `json:"created_at"`
			Parents   []string `json:"parents"`
		} `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode pull response: %w", err)
	}

	if len(result.Entries) == 0 {
		c.log.Info("HTTP sync: no new entries from peer")
		return nil
	}

	// Convert to RawSyncEntry for validation and storage
	var syncEntries []gossip.RawSyncEntry
	for _, e := range result.Entries {
		hash, err := hex.DecodeString(e.Hash)
		if err != nil {
			c.log.Warn("HTTP sync: invalid hash, skipping", map[string]any{"hash": e.Hash})
			continue
		}
		rawCBOR, err := base64.StdEncoding.DecodeString(e.RawCBOR)
		if err != nil {
			c.log.Warn("HTTP sync: invalid raw_cbor, skipping")
			continue
		}
		authorKey, err := hex.DecodeString(e.AuthorKey)
		if err != nil {
			c.log.Warn("HTTP sync: invalid author_key, skipping")
			continue
		}
		signature, err := base64.StdEncoding.DecodeString(e.Signature)
		if err != nil {
			c.log.Warn("HTTP sync: invalid signature, skipping")
			continue
		}

		var parents [][]byte
		for _, p := range e.Parents {
			parent, err := hex.DecodeString(p)
			if err != nil {
				continue
			}
			parents = append(parents, parent)
		}

		syncEntries = append(syncEntries, gossip.RawSyncEntry{
			Hash:      hash,
			RawCBOR:   rawCBOR,
			AuthorKey: authorKey,
			Signature: signature,
			EntryType: e.EntryType,
			CreatedAt: e.CreatedAt,
			Parents:   parents,
		})
	}

	// Use the same validation and storage logic as gossip sync
	gossip.StoreEntries(c.logDB, syncEntries, c.registry, c.log)

	c.log.Info("HTTP sync: pulled entries from peer", map[string]any{
		"url":      syncURL,
		"received": len(syncEntries),
	})

	// Rebuild in-memory state from the updated log
	c.registry.LoadFromDB(c.logDB)
	c.replayRevocations()
	c.replayOrgRelationships()
	c.replayChannelState()

	return nil
}
