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
	s.db.Exec("ALTER TABLE pairwise_secrets ADD COLUMN rotated_at INTEGER NOT NULL DEFAULT 0")

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

// Close closes the database.
func (s *KeyDB) Close() error {
	return s.db.Close()
}
