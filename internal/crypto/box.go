package crypto

import (
	"fmt"
)

// SealToPublicKey encrypts plaintext to a recipient's X25519 public key
// using an ephemeral X25519 keypair. This is used for the Slack-mediated
// PSK exchange where no pairwise secret exists yet (rule SR1).
//
// The process:
// 1. Generate ephemeral X25519 keypair
// 2. Compute shared secret via X25519 DH(ephemeral_private, recipient_public)
// 3. Derive symmetric key via BLAKE3(shared_secret)
// 4. Encrypt with XChaCha20-Poly1305
// 5. Zero ephemeral private key
//
// Returns: ephemeral_public_key (32 bytes) || nonce (24 bytes) || ciphertext
func SealToPublicKey(recipientPub [32]byte, plaintext []byte) ([]byte, error) {
	// Generate ephemeral keypair
	ephemeral, err := GenerateExchangeKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}
	defer ephemeral.Zero() // Rule C5: zero ephemeral private key after use

	// Compute shared secret via X25519 DH
	shared, err := DeriveSharedSecret(ephemeral.Private, recipientPub)
	if err != nil {
		return nil, fmt.Errorf("derive shared secret: %w", err)
	}
	defer Zero(shared[:]) // Zero shared secret after use

	// Derive symmetric key via BLAKE3
	symKey := Hash(shared[:])
	defer Zero(symKey[:])

	// Encrypt with XChaCha20-Poly1305
	encrypted, err := Encrypt(symKey[:], plaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	// Prepend ephemeral public key: pubkey (32) || nonce (24) || ciphertext
	result := make([]byte, 32+len(encrypted))
	copy(result[:32], ephemeral.Public[:])
	copy(result[32:], encrypted)
	return result, nil
}

// OpenFromPublicKey decrypts a blob sealed with SealToPublicKey using the
// recipient's X25519 private key.
//
// Input format: ephemeral_public_key (32 bytes) || nonce (24 bytes) || ciphertext
func OpenFromPublicKey(recipientPriv [32]byte, sealed []byte) ([]byte, error) {
	if len(sealed) < 32+24+16 { // pubkey + nonce + Poly1305 tag minimum
		return nil, ErrDecryptionFailed
	}

	// Extract ephemeral public key
	var ephemeralPub [32]byte
	copy(ephemeralPub[:], sealed[:32])

	// Compute shared secret via X25519 DH
	shared, err := DeriveSharedSecret(recipientPriv, ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("derive shared secret: %w", err)
	}
	defer Zero(shared[:])

	// Derive symmetric key via BLAKE3
	symKey := Hash(shared[:])
	defer Zero(symKey[:])

	// Decrypt (the remaining bytes are nonce || ciphertext)
	return Decrypt(symKey[:], sealed[32:])
}
