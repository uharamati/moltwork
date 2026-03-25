package crypto

import (
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// DeriveSharedSecret computes the X25519 shared secret from our private key
// and the peer's public key. Both sides derive the same secret.
func DeriveSharedSecret(ourPrivate [32]byte, theirPublic [32]byte) ([32]byte, error) {
	shared, err := curve25519.X25519(ourPrivate[:], theirPublic[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("x25519 key exchange: %w", err)
	}

	var result [32]byte
	copy(result[:], shared)
	return result, nil
}
