package connector

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/crypto"
)

// startPairwiseRotation runs a periodic loop that rotates pairwise secrets
// with peers when the rotation interval has elapsed (rule C9).
func (c *Connector) startPairwiseRotation(ctx context.Context) {
	interval := time.Duration(c.cfg.KeyRotationInterval) * time.Second
	if interval == 0 {
		interval = 24 * time.Hour // default: 1 day
	}

	// Jitter before starting: spread out rotation checks across agents
	// that joined at the same time to avoid thundering herd on the ticker.
	jitter := time.Duration(rand.Int63n(int64(5 * time.Minute)))
	select {
	case <-ctx.Done():
		return
	case <-time.After(jitter):
	}

	// Check every 10 minutes if any peers need rotation
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.rotatePairwiseSecrets(interval)
		}
	}
}

// rotatePairwiseSecrets checks all pairwise secrets and rotates any that
// are older than the rotation interval.
func (c *Connector) rotatePairwiseSecrets(maxAge time.Duration) {
	threshold := time.Now().Add(-maxAge).Unix()
	peers, err := c.keyDB.PeersNeedingRotation(threshold)
	if err != nil {
		c.log.Warn("query peers for rotation failed", map[string]any{"error": err.Error()})
		return
	}

	for _, peerPubKey := range peers {
		// Skip revoked agents
		if c.registry.IsRevoked(peerPubKey) {
			continue
		}

		if err := c.rotatePairwiseWith(peerPubKey); err != nil {
			c.log.Warn("pairwise rotation failed", map[string]any{
				"peer":  fmt.Sprintf("%x", peerPubKey[:8]),
				"error": err.Error(),
			})
		}
	}
}

// rotatePairwiseWith initiates a pairwise key rotation with a specific peer.
// Uses our current exchange key (NOT a new one per peer) to avoid breaking
// pairwise secrets with other peers. The exchange key is stable — only the
// pairwise shared secret is re-derived using a fresh ephemeral key that is
// encrypted and sent to the specific peer.
func (c *Connector) rotatePairwiseWith(peerPubKey []byte) error {
	c.pairwiseMu.Lock()
	defer c.pairwiseMu.Unlock()

	// Get current pairwise secret for encrypting the rotation message
	oldSecret, oldEpoch, err := c.keyDB.GetPairwiseSecret(peerPubKey)
	if err != nil || oldSecret == nil {
		return fmt.Errorf("no existing pairwise secret")
	}

	// Generate a per-rotation ephemeral X25519 key pair.
	// This is NOT stored as our global exchange key — it's used only for
	// deriving the new pairwise secret with THIS specific peer.
	ephemeralKP, err := crypto.GenerateExchangeKeyPair()
	if err != nil {
		return fmt.Errorf("generate ephemeral key: %w", err)
	}

	// Encrypt our ephemeral exchange public key with the current pairwise secret
	var oldSecretArr [32]byte
	copy(oldSecretArr[:], oldSecret)
	sealed, err := crypto.SealForPeer(oldSecretArr, ephemeralKP.Public[:])
	if err != nil {
		return fmt.Errorf("seal rotation key: %w", err)
	}

	// Publish PairwiseKeyExchange entry
	exchange := moltcbor.PairwiseKeyExchange{
		TargetPubKey: peerPubKey,
		Sealed:       sealed,
	}
	payload, err := moltcbor.Marshal(exchange)
	if err != nil {
		return fmt.Errorf("marshal key exchange: %w", err)
	}

	if err := c.publishEntry(moltcbor.EntryTypePairwiseKeyExchange, payload); err != nil {
		return fmt.Errorf("publish key exchange: %w", err)
	}

	// Look up the peer's current exchange public key from registry
	peerAgent := c.registry.GetByPublicKey(peerPubKey)
	if peerAgent == nil || len(peerAgent.ExchangePubKey) != 32 {
		return fmt.Errorf("peer has no exchange key")
	}

	// Derive new shared secret using the ephemeral private key and peer's current public key
	var peerExchPub [32]byte
	copy(peerExchPub[:], peerAgent.ExchangePubKey)
	newSecret, err := crypto.DerivePairwiseSecret(ephemeralKP, peerExchPub)
	if err != nil {
		return fmt.Errorf("derive new secret: %w", err)
	}

	// Store new secret with incremented epoch
	newEpoch := oldEpoch + 1
	if err := c.keyDB.SetPairwiseSecret(peerPubKey, newSecret[:], newEpoch); err != nil {
		return fmt.Errorf("store new secret: %w", err)
	}

	// Zero old secret and ephemeral key material (rule C5)
	crypto.Zero(oldSecret)
	crypto.Zero(ephemeralKP.Private[:])

	// NOTE: We do NOT update c.exchangeKey here. The global exchange key is
	// stable and shared across all peer relationships. Replacing it per-peer
	// would desync pairwise secrets with every other peer.

	c.log.Info("pairwise secret rotated", map[string]any{
		"peer":  fmt.Sprintf("%x", peerPubKey[:8]),
		"epoch": newEpoch,
	})

	return nil
}

// processPairwiseKeyExchange handles incoming key exchange entries from peers
// during log replay or gossip sync. When a peer publishes a rotation, we
// re-derive the shared secret using our keys and their new exchange public key.
func (c *Connector) processPairwiseKeyExchange(authorKey []byte, exchange *moltcbor.PairwiseKeyExchange) {
	// Only process entries targeted at us
	if !crypto.ConstantTimeEqual(exchange.TargetPubKey, c.keyPair.Public) {
		return
	}

	// Get current pairwise secret to decrypt the sealed material
	secret, epoch, err := c.keyDB.GetPairwiseSecret(authorKey)
	if err != nil || secret == nil {
		return // No existing secret with this peer
	}

	// Decrypt the sealed exchange material (peer's new exchange public key)
	var secretArr [32]byte
	copy(secretArr[:], secret)
	peerNewExchPub, err := crypto.OpenFromPeer(secretArr, exchange.Sealed)
	if err != nil {
		return // Can't decrypt — may already be using new key
	}

	if len(peerNewExchPub) != 32 {
		return // Invalid exchange key
	}

	// Derive new shared secret using our current exchange key and peer's new exchange key
	var peerPub [32]byte
	copy(peerPub[:], peerNewExchPub)
	newSecret, err := crypto.DerivePairwiseSecret(c.exchangeKey, peerPub)
	if err != nil {
		c.log.Warn("derive rotated secret failed", map[string]any{
			"peer":  fmt.Sprintf("%x", authorKey[:8]),
			"error": err.Error(),
		})
		return
	}

	// Store new secret
	newEpoch := epoch + 1
	if err := c.keyDB.SetPairwiseSecret(authorKey, newSecret[:], newEpoch); err != nil {
		c.log.Warn("store rotated secret failed", map[string]any{"error": err.Error()})
		return
	}

	// Zero old secret (rule C5)
	crypto.Zero(secret)

	c.log.Info("processed pairwise rotation from peer", map[string]any{
		"peer":  fmt.Sprintf("%x", authorKey[:8]),
		"epoch": newEpoch,
	})
}
