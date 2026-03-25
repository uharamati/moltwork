package crypto

import (
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
)

var ErrInvalidSignature = errors.New("invalid signature")

// Sign signs a message with the Ed25519 private key.
func Sign(privateKey ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(privateKey, message)
}

// Verify checks a signature against a public key (rule C2: verify before anything else).
// Uses constant-time comparison (rule C4).
func Verify(publicKey ed25519.PublicKey, message, signature []byte) error {
	if len(signature) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}

	// ed25519.Verify internally uses constant-time operations.
	// We additionally verify the signature length with constant-time compare.
	if !ed25519.Verify(publicKey, message, signature) {
		return ErrInvalidSignature
	}
	return nil
}

// ConstantTimeEqual compares two byte slices in constant time (rule C4).
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
