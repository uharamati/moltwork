package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// KeyDB manages the key database with restricted permissions (rule S2).
//
// SECURITY NOTE: Secrets (PSK, platform tokens, private keys, pairwise secrets)
// are stored as plaintext in this SQLite database. The file has 0600 permissions,
// which prevents other users from reading it, but does NOT protect against:
//   - Root access on the machine
//   - Disk theft or backup exposure
//   - Process memory dumps
//
// For production deployments, consider encrypting the database with a master key
// derived from the OS keychain (macOS Keychain, Linux libsecret) or an HSM.
type KeyDB struct {
	db *sql.DB
}

// OpenKeyDB opens or creates the key database with 0600 file permissions.
func OpenKeyDB(path string) (*KeyDB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create key db dir: %w", err)
	}

	// Create file with restricted permissions if it doesn't exist
	if _, err := os.Stat(path); os.IsNotExist(err) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, fmt.Errorf("create key db file: %w", err)
		}
		f.Close()
	}

	db, err := sql.Open("sqlite", path+"?_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open key db: %w", err)
	}

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}

	// Integrity check on startup — without this, a corrupted keyDB opens silently
	// and the agent starts with no identity, no PSK, no group keys.
	var result string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&result); err != nil {
		db.Close()
		return nil, fmt.Errorf("key db integrity check: %w", err)
	}
	if result != "ok" {
		db.Close()
		return nil, fmt.Errorf("key db integrity check failed: %s", result)
	}

	s := &KeyDB{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *KeyDB) migrate() error {
	// Schema version tracking
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		version INTEGER NOT NULL DEFAULT 1
	)`); err != nil {
		return fmt.Errorf("create schema_version: %w", err)
	}
	s.db.Exec("INSERT OR IGNORE INTO schema_version (id, version) VALUES (1, 1)")

	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS identity (
			id           INTEGER PRIMARY KEY CHECK (id = 1),
			public_key   BLOB NOT NULL,
			private_key  BLOB NOT NULL
		);

		CREATE TABLE IF NOT EXISTS pairwise_secrets (
			peer_pubkey    BLOB PRIMARY KEY,
			shared_secret  BLOB NOT NULL,
			rotation_epoch INTEGER NOT NULL DEFAULT 0,
			rotated_at     INTEGER NOT NULL DEFAULT 0
		);

		CREATE TABLE IF NOT EXISTS group_keys (
			channel_id   BLOB NOT NULL,
			epoch        INTEGER NOT NULL,
			key_bytes    BLOB NOT NULL,
			PRIMARY KEY (channel_id, epoch)
		);

		CREATE TABLE IF NOT EXISTS platform_token (
			id               INTEGER PRIMARY KEY CHECK (id = 1),
			token            BLOB NOT NULL,
			platform         TEXT NOT NULL,
			workspace_domain TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS psk (
			id    INTEGER PRIMARY KEY CHECK (id = 1),
			value BLOB NOT NULL
		);

		CREATE TABLE IF NOT EXISTS exchange_keys (
			id          INTEGER PRIMARY KEY CHECK (id = 1),
			public_key  BLOB NOT NULL,
			private_key BLOB NOT NULL
		);

		CREATE TABLE IF NOT EXISTS rendezvous_channel (
			id         INTEGER PRIMARY KEY CHECK (id = 1),
			channel_id TEXT NOT NULL
		);
	`)
	if err != nil {
		return fmt.Errorf("migrate key db: %w", err)
	}

	// Add rotated_at column if it doesn't exist (migration for existing databases)
	var hasRotatedAt bool
	rows, err := s.db.Query("PRAGMA table_info(pairwise_secrets)")
	if err != nil {
		return fmt.Errorf("check pairwise_secrets schema: %w", err)
	}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull int
		var dflt *string
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return fmt.Errorf("scan table_info: %w", err)
		}
		if name == "rotated_at" {
			hasRotatedAt = true
		}
	}
	rows.Close()
	if !hasRotatedAt {
		if _, err := s.db.Exec("ALTER TABLE pairwise_secrets ADD COLUMN rotated_at INTEGER NOT NULL DEFAULT 0"); err != nil {
			return fmt.Errorf("alter pairwise_secrets: %w", err)
		}
	}

	// Read receipts — local only, not gossiped
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS read_receipts (
		channel_id TEXT NOT NULL,
		last_read_hash TEXT NOT NULL,
		last_read_ts INTEGER NOT NULL,
		PRIMARY KEY (channel_id)
	)`); err != nil {
		return fmt.Errorf("create read_receipts: %w", err)
	}

	// Quorum revocation proposals
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS revocation_proposals (
		id TEXT PRIMARY KEY,
		target_key TEXT NOT NULL,
		reason INTEGER NOT NULL,
		created_at INTEGER NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending'
	)`); err != nil {
		return fmt.Errorf("create revocation_proposals: %w", err)
	}

	// Rendezvous post dedup — prevents announcement spam across restarts (BUG-1)
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS rendezvous_post (
		id         INTEGER PRIMARY KEY CHECK (id = 1),
		multiaddr  TEXT NOT NULL,
		posted_at  INTEGER NOT NULL
	)`); err != nil {
		return fmt.Errorf("create rendezvous_post: %w", err)
	}

	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS revocation_signatures (
		proposal_id TEXT NOT NULL,
		signer_key TEXT NOT NULL,
		signature TEXT NOT NULL,
		PRIMARY KEY (proposal_id, signer_key),
		FOREIGN KEY (proposal_id) REFERENCES revocation_proposals(id)
	)`); err != nil {
		return fmt.Errorf("create revocation_signatures: %w", err)
	}

	// Pending group key distributions — queued when pairwise secret not yet available
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS pending_key_distributions (
		channel_id BLOB NOT NULL,
		target_key BLOB NOT NULL,
		created_at INTEGER NOT NULL,
		PRIMARY KEY (channel_id, target_key)
	)`); err != nil {
		return fmt.Errorf("create pending_key_distributions: %w", err)
	}

	// DM rate limits — persisted so rate limiting survives restarts
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS dm_rate_limits (
		recipient_key TEXT PRIMARY KEY,
		send_count    INTEGER NOT NULL DEFAULT 0,
		window_start  INTEGER NOT NULL
	)`); err != nil {
		return fmt.Errorf("create dm_rate_limits: %w", err)
	}

	// Gossip sync watermarks — persisted per-peer so incremental sync survives restarts
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS peer_watermarks (
		peer_id    TEXT PRIMARY KEY,
		watermark  INTEGER NOT NULL,
		sync_count INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		return fmt.Errorf("create peer_watermarks: %w", err)
	}

	return nil
}

// SetIdentity stores the agent's own keypair.
func (s *KeyDB) SetIdentity(publicKey, privateKey []byte) error {
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO identity (id, public_key, private_key) VALUES (1, ?, ?)",
		publicKey, privateKey,
	)
	return err
}

// GetIdentity retrieves the agent's own keypair.
func (s *KeyDB) GetIdentity() (publicKey, privateKey []byte, err error) {
	err = s.db.QueryRow("SELECT public_key, private_key FROM identity WHERE id = 1").Scan(&publicKey, &privateKey)
	if err == sql.ErrNoRows {
		return nil, nil, nil
	}
	return
}

// SetPairwiseSecret stores or updates a pairwise secret with a peer.
func (s *KeyDB) SetPairwiseSecret(peerPubKey, sharedSecret []byte, epoch int) error {
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO pairwise_secrets (peer_pubkey, shared_secret, rotation_epoch, rotated_at) VALUES (?, ?, ?, ?)",
		peerPubKey, sharedSecret, epoch, time.Now().Unix(),
	)
	return err
}

// GetPairwiseSecret retrieves the pairwise secret for a peer.
func (s *KeyDB) GetPairwiseSecret(peerPubKey []byte) (sharedSecret []byte, epoch int, err error) {
	err = s.db.QueryRow(
		"SELECT shared_secret, rotation_epoch FROM pairwise_secrets WHERE peer_pubkey = ?",
		peerPubKey,
	).Scan(&sharedSecret, &epoch)
	if err == sql.ErrNoRows {
		return nil, 0, nil
	}
	return
}

// PeersNeedingRotation returns public keys of peers whose pairwise secret
// was last rotated before the given threshold timestamp.
func (s *KeyDB) PeersNeedingRotation(olderThan int64) ([][]byte, error) {
	rows, err := s.db.Query(
		"SELECT peer_pubkey FROM pairwise_secrets WHERE rotated_at < ?",
		olderThan,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var peers [][]byte
	for rows.Next() {
		var pubkey []byte
		if err := rows.Scan(&pubkey); err != nil {
			return nil, err
		}
		peers = append(peers, pubkey)
	}
	return peers, rows.Err()
}

// DeletePairwiseSecret removes the pairwise secret for a revoked peer.
func (s *KeyDB) DeletePairwiseSecret(peerPubKey []byte) error {
	_, err := s.db.Exec("DELETE FROM pairwise_secrets WHERE peer_pubkey = ?", peerPubKey)
	return err
}

// SetGroupKey stores a group key for a channel at a specific epoch.
func (s *KeyDB) SetGroupKey(channelID []byte, epoch int, keyBytes []byte) error {
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO group_keys (channel_id, epoch, key_bytes) VALUES (?, ?, ?)",
		channelID, epoch, keyBytes,
	)
	return err
}

// GetGroupKey retrieves the latest group key for a channel.
func (s *KeyDB) GetGroupKey(channelID []byte) (keyBytes []byte, epoch int, err error) {
	err = s.db.QueryRow(
		"SELECT key_bytes, epoch FROM group_keys WHERE channel_id = ? ORDER BY epoch DESC LIMIT 1",
		channelID,
	).Scan(&keyBytes, &epoch)
	if err == sql.ErrNoRows {
		return nil, 0, nil
	}
	return
}

// SetPlatformToken stores the platform token.
func (s *KeyDB) SetPlatformToken(token []byte, platform, workspaceDomain string) error {
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO platform_token (id, token, platform, workspace_domain) VALUES (1, ?, ?, ?)",
		token, platform, workspaceDomain,
	)
	return err
}

// GetPlatformToken retrieves the platform token.
func (s *KeyDB) GetPlatformToken() (token []byte, platform, workspaceDomain string, err error) {
	err = s.db.QueryRow("SELECT token, platform, workspace_domain FROM platform_token WHERE id = 1").Scan(&token, &platform, &workspaceDomain)
	if err == sql.ErrNoRows {
		return nil, "", "", nil
	}
	return
}

// SetPSK stores the current pre-shared key.
func (s *KeyDB) SetPSK(psk []byte) error {
	_, err := s.db.Exec("INSERT OR REPLACE INTO psk (id, value) VALUES (1, ?)", psk)
	return err
}

// GetPSK retrieves the current pre-shared key.
func (s *KeyDB) GetPSK() ([]byte, error) {
	var psk []byte
	err := s.db.QueryRow("SELECT value FROM psk WHERE id = 1").Scan(&psk)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return psk, err
}

// SetExchangeKeys stores the agent's X25519 exchange keypair.
func (s *KeyDB) SetExchangeKeys(publicKey, privateKey []byte) error {
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO exchange_keys (id, public_key, private_key) VALUES (1, ?, ?)",
		publicKey, privateKey,
	)
	return err
}

// GetExchangeKeys retrieves the agent's X25519 exchange keypair.
func (s *KeyDB) GetExchangeKeys() (publicKey, privateKey []byte, err error) {
	err = s.db.QueryRow("SELECT public_key, private_key FROM exchange_keys WHERE id = 1").Scan(&publicKey, &privateKey)
	if err == sql.ErrNoRows {
		return nil, nil, nil
	}
	return
}

// SetRendezvousChannelID persists the Slack channel ID after first resolution.
func (s *KeyDB) SetRendezvousChannelID(channelID string) error {
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO rendezvous_channel (id, channel_id) VALUES (1, ?)",
		channelID,
	)
	return err
}

// GetRendezvousChannelID returns the cached Slack channel ID, or empty string.
func (s *KeyDB) GetRendezvousChannelID() string {
	var id string
	err := s.db.QueryRow("SELECT channel_id FROM rendezvous_channel WHERE id = 1").Scan(&id)
	if err != nil {
		return ""
	}
	return id
}

// SetRendezvousPost records the last posted rendezvous multiaddr and timestamp.
func (s *KeyDB) SetRendezvousPost(multiaddr string, postedAt int64) error {
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO rendezvous_post (id, multiaddr, posted_at) VALUES (1, ?, ?)",
		multiaddr, postedAt,
	)
	return err
}

// GetRendezvousPost returns the last posted multiaddr and timestamp, or ("", 0).
func (s *KeyDB) GetRendezvousPost() (multiaddr string, postedAt int64) {
	err := s.db.QueryRow("SELECT multiaddr, posted_at FROM rendezvous_post WHERE id = 1").Scan(&multiaddr, &postedAt)
	if err != nil {
		return "", 0
	}
	return multiaddr, postedAt
}

// --- Read Receipts ---

// SetReadReceipt stores the last read position for a channel.
func (s *KeyDB) SetReadReceipt(channelID string, messageHash string, timestamp int64) error {
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO read_receipts (channel_id, last_read_hash, last_read_ts) VALUES (?, ?, ?)",
		channelID, messageHash, timestamp,
	)
	return err
}

// GetReadReceipt retrieves the last read position for a channel.
func (s *KeyDB) GetReadReceipt(channelID string) (messageHash string, timestamp int64, err error) {
	err = s.db.QueryRow(
		"SELECT last_read_hash, last_read_ts FROM read_receipts WHERE channel_id = ?",
		channelID,
	).Scan(&messageHash, &timestamp)
	if err == sql.ErrNoRows {
		return "", 0, nil
	}
	return
}

// --- Quorum Revocation Proposals ---

// RevocationSig represents a single signature on a revocation proposal.
type RevocationSig struct {
	SignerKey string `json:"signer_key"`
	Signature string `json:"signature"`
}

// RevocationProposal represents a pending quorum revocation proposal.
type RevocationProposal struct {
	ID        string `json:"id"`
	TargetKey string `json:"target_key"`
	Reason    int    `json:"reason"`
	CreatedAt int64  `json:"created_at"`
	Status    string `json:"status"`
}

// CreateRevocationProposal stores a new revocation proposal.
func (s *KeyDB) CreateRevocationProposal(id, targetKey string, reason int, createdAt int64) error {
	_, err := s.db.Exec(
		"INSERT INTO revocation_proposals (id, target_key, reason, created_at, status) VALUES (?, ?, ?, ?, 'pending')",
		id, targetKey, reason, createdAt,
	)
	return err
}

// GetRevocationProposal retrieves a proposal and its signatures.
func (s *KeyDB) GetRevocationProposal(id string) (targetKey string, reason int, status string, sigs []RevocationSig, err error) {
	err = s.db.QueryRow(
		"SELECT target_key, reason, status FROM revocation_proposals WHERE id = ?", id,
	).Scan(&targetKey, &reason, &status)
	if err != nil {
		return "", 0, "", nil, err
	}

	rows, err := s.db.Query(
		"SELECT signer_key, signature FROM revocation_signatures WHERE proposal_id = ?", id,
	)
	if err != nil {
		return targetKey, reason, status, nil, nil
	}
	defer rows.Close()

	for rows.Next() {
		var sig RevocationSig
		if err := rows.Scan(&sig.SignerKey, &sig.Signature); err != nil {
			continue
		}
		sigs = append(sigs, sig)
	}
	return targetKey, reason, status, sigs, nil
}

// AddRevocationSignature adds a signature to a proposal.
func (s *KeyDB) AddRevocationSignature(proposalID, signerKey, signature string) error {
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO revocation_signatures (proposal_id, signer_key, signature) VALUES (?, ?, ?)",
		proposalID, signerKey, signature,
	)
	return err
}

// ListRevocationProposals returns all revocation proposals.
func (s *KeyDB) ListRevocationProposals() ([]RevocationProposal, error) {
	rows, err := s.db.Query(
		"SELECT id, target_key, reason, created_at, status FROM revocation_proposals ORDER BY created_at DESC",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var proposals []RevocationProposal
	for rows.Next() {
		var p RevocationProposal
		if err := rows.Scan(&p.ID, &p.TargetKey, &p.Reason, &p.CreatedAt, &p.Status); err != nil {
			continue
		}
		proposals = append(proposals, p)
	}
	return proposals, rows.Err()
}

// --- DM Rate Limits ---

// RecordDMSend records a DM send for rate limiting persistence.
func (s *KeyDB) RecordDMSend(recipientKey string) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO dm_rate_limits (recipient_key, send_count, window_start) VALUES (?, COALESCE((SELECT CASE WHEN ? - window_start < 60 THEN send_count + 1 ELSE 1 END FROM dm_rate_limits WHERE recipient_key = ?), 1), COALESCE((SELECT CASE WHEN ? - window_start < 60 THEN window_start ELSE ? END FROM dm_rate_limits WHERE recipient_key = ?), ?))",
		recipientKey, now, recipientKey, now, now, recipientKey, now,
	)
	return err
}

// CheckDMRate returns true if the DM send is within rate limits.
func (s *KeyDB) CheckDMRate(recipientKey string, limit int) bool {
	now := time.Now().Unix()
	var count int
	var windowStart int64
	err := s.db.QueryRow(
		"SELECT send_count, window_start FROM dm_rate_limits WHERE recipient_key = ?",
		recipientKey,
	).Scan(&count, &windowStart)
	if err != nil {
		return true // no record = allowed
	}
	if now-windowStart >= 60 {
		return true // window expired
	}
	return count < limit
}

// --- HTTP Sync Watermark ---

// SetHTTPSyncWatermark persists the HTTP sync watermark.
func (s *KeyDB) SetHTTPSyncWatermark(ts int64) error {
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO peer_watermarks (peer_id, watermark, sync_count) VALUES ('_http_sync', ?, 0)", ts)
	return err
}

// GetHTTPSyncWatermark retrieves the persisted HTTP sync watermark.
func (s *KeyDB) GetHTTPSyncWatermark() (int64, error) {
	var ts int64
	err := s.db.QueryRow("SELECT watermark FROM peer_watermarks WHERE peer_id = '_http_sync'").Scan(&ts)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return ts, err
}

// --- Pending Group Key Distributions ---

// AddPendingKeyDistribution queues a group key distribution for later delivery.
func (s *KeyDB) AddPendingKeyDistribution(channelID, targetKey []byte) error {
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO pending_key_distributions (channel_id, target_key, created_at) VALUES (?, ?, ?)",
		channelID, targetKey, time.Now().Unix(),
	)
	return err
}

// RemovePendingKeyDistribution removes a completed distribution.
func (s *KeyDB) RemovePendingKeyDistribution(channelID, targetKey []byte) error {
	_, err := s.db.Exec(
		"DELETE FROM pending_key_distributions WHERE channel_id = ? AND target_key = ?",
		channelID, targetKey,
	)
	return err
}

// PendingKeyDistribution represents a queued group key delivery.
type PendingKeyDistribution struct {
	ChannelID []byte
	TargetKey []byte
	CreatedAt int64
}

// GetPendingKeyDistributions returns all pending distributions for a target.
func (s *KeyDB) GetPendingKeyDistributions(targetKey []byte) ([]PendingKeyDistribution, error) {
	rows, err := s.db.Query(
		"SELECT channel_id, target_key, created_at FROM pending_key_distributions WHERE target_key = ?",
		targetKey,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []PendingKeyDistribution
	for rows.Next() {
		var p PendingKeyDistribution
		if err := rows.Scan(&p.ChannelID, &p.TargetKey, &p.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

// --- Peer Watermarks (gossip incremental sync) ---

// PeerWatermark holds the sync state for a single peer.
type PeerWatermark struct {
	PeerID    string
	Watermark int64
	SyncCount int
}

// SetPeerWatermark persists the watermark and sync count for a peer.
func (s *KeyDB) SetPeerWatermark(peerID string, watermark int64, syncCount int) error {
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO peer_watermarks (peer_id, watermark, sync_count) VALUES (?, ?, ?)",
		peerID, watermark, syncCount,
	)
	return err
}

// GetPeerWatermark retrieves the watermark and sync count for a peer.
func (s *KeyDB) GetPeerWatermark(peerID string) (watermark int64, syncCount int, err error) {
	err = s.db.QueryRow(
		"SELECT watermark, sync_count FROM peer_watermarks WHERE peer_id = ?", peerID,
	).Scan(&watermark, &syncCount)
	if err == sql.ErrNoRows {
		return 0, 0, nil
	}
	return
}

// AllPeerWatermarks returns all persisted watermarks.
func (s *KeyDB) AllPeerWatermarks() ([]PeerWatermark, error) {
	rows, err := s.db.Query("SELECT peer_id, watermark, sync_count FROM peer_watermarks")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []PeerWatermark
	for rows.Next() {
		var pw PeerWatermark
		if err := rows.Scan(&pw.PeerID, &pw.Watermark, &pw.SyncCount); err != nil {
			return nil, err
		}
		result = append(result, pw)
	}
	return result, rows.Err()
}

// ClearPeerWatermarks removes all persisted watermarks (called on PSK rotation).
func (s *KeyDB) ClearPeerWatermarks() error {
	_, err := s.db.Exec("DELETE FROM peer_watermarks")
	return err
}

// IntegrityCheck runs PRAGMA integrity_check and returns the result.
func (s *KeyDB) IntegrityCheck() (string, error) {
	var result string
	err := s.db.QueryRow("PRAGMA integrity_check").Scan(&result)
	return result, err
}

// Close closes the database.
func (s *KeyDB) Close() error {
	return s.db.Close()
}
