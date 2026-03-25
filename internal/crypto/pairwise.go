package crypto

import (
	"fmt"
)

// DerivePairwiseSecret derives a shared secret between two agents
// using X25519 Diffie-Hellman. Both agents publish their X25519 exchange
// public keys in their AgentRegistration entries. Any two agents can
// derive their pairwise secret from their own private key and the
// other agent's public key.
func DerivePairwiseSecret(
	ourExchangeKey *ExchangeKeyPair,
	peerExchangePubKey [32]byte,
) ([32]byte, error) {
	return DeriveSharedSecret(ourExchangeKey.Private, peerExchangePubKey)
}

// SealForPeer encrypts data using the pairwise secret with a specific peer.
// Used for DMs and distributing group keys.
func SealForPeer(pairwiseSecret [32]byte, plaintext []byte) ([]byte, error) {
	// Pad before encrypting (rule C10)
	padded, err := Pad(plaintext)
	if err != nil {
		return nil, fmt.Errorf("pad: %w", err)
	}
	return Encrypt(pairwiseSecret[:], padded)
}

// OpenFromPeer decrypts data sealed with a pairwise secret.
func OpenFromPeer(pairwiseSecret [32]byte, sealed []byte) ([]byte, error) {
	padded, err := Decrypt(pairwiseSecret[:], sealed)
	if err != nil {
		return nil, err
	}
	return Unpad(padded)
}
