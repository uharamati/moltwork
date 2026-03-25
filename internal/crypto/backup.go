package crypto

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Backup format version for future compatibility.
const backupVersion = 1

// Argon2id parameters per security rule C6:
// minimum 256MB memory, 3 iterations.
const (
	argon2Memory  = 256 * 1024 // 256 MB in KiB
	argon2Time    = 3
	argon2Threads = 4
	argon2KeyLen  = 32
	argon2SaltLen = 16
)

var ErrInvalidBackup = errors.New("invalid backup format")

// BackupExport encrypts key material with a user-provided passphrase.
// Uses Argon2id for key derivation + XChaCha20-Poly1305 for encryption.
// Returns: [version (1 byte)] [salt (16 bytes)] [encrypted blob]
func BackupExport(keyMaterial []byte, passphrase []byte) ([]byte, error) {
	salt := RandomBytes(argon2SaltLen)
	derivedKey := argon2.IDKey(passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	defer Zero(derivedKey)

	encrypted, err := Encrypt(derivedKey, keyMaterial)
	if err != nil {
		return nil, fmt.Errorf("backup encrypt: %w", err)
	}

	// version || salt || encrypted
	result := make([]byte, 0, 1+argon2SaltLen+len(encrypted))
	result = append(result, byte(backupVersion))
	result = append(result, salt...)
	result = append(result, encrypted...)
	return result, nil
}

// BackupImport decrypts key material from a backup using the passphrase.
func BackupImport(backup []byte, passphrase []byte) ([]byte, error) {
	if len(backup) < 1+argon2SaltLen+1 {
		return nil, ErrInvalidBackup
	}

	version := backup[0]
	if version != backupVersion {
		return nil, fmt.Errorf("unsupported backup version: %d", version)
	}

	salt := backup[1 : 1+argon2SaltLen]
	encrypted := backup[1+argon2SaltLen:]

	derivedKey := argon2.IDKey(passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	defer Zero(derivedKey)

	plaintext, err := Decrypt(derivedKey, encrypted)
	if err != nil {
		return nil, fmt.Errorf("backup decrypt (wrong passphrase?): %w", err)
	}
	return plaintext, nil
}
