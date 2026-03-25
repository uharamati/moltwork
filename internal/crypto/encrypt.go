package crypto

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

var ErrDecryptionFailed = errors.New("decryption failed")

// Encrypt encrypts plaintext with XChaCha20-Poly1305 using a 32-byte key.
// Returns nonce || ciphertext (nonce is random, per rule C1).
func Encrypt(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create xchacha20: %w", err)
	}

	nonce := Nonce(aead.NonceSize()) // 24 bytes for XChaCha20
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts a nonce || ciphertext blob with XChaCha20-Poly1305.
func Decrypt(key, blob []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create xchacha20: %w", err)
	}

	nonceSize := aead.NonceSize()
	if len(blob) < nonceSize {
		return nil, ErrDecryptionFailed
	}

	nonce := blob[:nonceSize]
	ciphertext := blob[nonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}
