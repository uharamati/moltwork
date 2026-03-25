package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"

	"golang.org/x/crypto/curve25519"
)

// SigningKeyPair holds an Ed25519 signing keypair.
type SigningKeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// ExchangeKeyPair holds an X25519 key exchange keypair.
type ExchangeKeyPair struct {
	Public  [32]byte
	Private [32]byte
}

// GenerateSigningKeyPair creates a new Ed25519 keypair.
func GenerateSigningKeyPair() (*SigningKeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 keypair: %w", err)
	}
	return &SigningKeyPair{Public: pub, Private: priv}, nil
}

// GenerateExchangeKeyPair creates a new X25519 keypair.
func GenerateExchangeKeyPair() (*ExchangeKeyPair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, fmt.Errorf("generate x25519 private key: %w", err)
	}

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive x25519 public key: %w", err)
	}

	var pubArr [32]byte
	copy(pubArr[:], pub)
	return &ExchangeKeyPair{Public: pubArr, Private: priv}, nil
}

// Zero overwrites a byte slice with zeros (rule C5).
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ZeroSigningKey zeros the private key material.
func (kp *SigningKeyPair) Zero() {
	Zero(kp.Private)
}

// ZeroExchangeKey zeros the private key material.
func (kp *ExchangeKeyPair) Zero() {
	Zero(kp.Private[:])
}

// WriteKeyFile writes data to a file with 0600 permissions.
func WriteKeyFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0600)
}

// ReadKeyFile reads a file that should have restricted permissions.
func ReadKeyFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
