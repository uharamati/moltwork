package crypto

import (
	"bytes"
	"testing"
)

func TestPairwiseSecretDerivation(t *testing.T) {
	alice, _ := GenerateExchangeKeyPair()
	bob, _ := GenerateExchangeKeyPair()

	secretA, err := DerivePairwiseSecret(alice, bob.Public)
	if err != nil {
		t.Fatal(err)
	}

	secretB, err := DerivePairwiseSecret(bob, alice.Public)
	if err != nil {
		t.Fatal(err)
	}

	if secretA != secretB {
		t.Error("pairwise secrets should match")
	}
}

func TestSealOpenForPeer(t *testing.T) {
	alice, _ := GenerateExchangeKeyPair()
	bob, _ := GenerateExchangeKeyPair()

	secret, _ := DerivePairwiseSecret(alice, bob.Public)

	plaintext := []byte("secret DM message between agents")

	sealed, err := SealForPeer(secret, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Bob derives same secret and opens
	secretB, _ := DerivePairwiseSecret(bob, alice.Public)
	opened, err := OpenFromPeer(secretB, sealed)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(opened, plaintext) {
		t.Error("decrypted message doesn't match original")
	}
}

func TestSealOpenWrongSecret(t *testing.T) {
	alice, _ := GenerateExchangeKeyPair()
	bob, _ := GenerateExchangeKeyPair()
	carol, _ := GenerateExchangeKeyPair()

	secretAB, _ := DerivePairwiseSecret(alice, bob.Public)
	secretAC, _ := DerivePairwiseSecret(alice, carol.Public)

	sealed, _ := SealForPeer(secretAB, []byte("for bob only"))

	_, err := OpenFromPeer(secretAC, sealed)
	if err == nil {
		t.Error("carol should not be able to decrypt bob's message")
	}
}

func TestSealPadsToSizeBucket(t *testing.T) {
	alice, _ := GenerateExchangeKeyPair()
	bob, _ := GenerateExchangeKeyPair()

	secret, _ := DerivePairwiseSecret(alice, bob.Public)

	// Short message
	sealed1, _ := SealForPeer(secret, []byte("hi"))
	// Slightly longer message
	sealed2, _ := SealForPeer(secret, []byte("hello there agent"))

	// Both should produce similar-sized ciphertext due to padding
	// (both fit in 256-byte bucket, so padded sizes are same,
	// ciphertext adds nonce + auth tag overhead)
	diff := len(sealed1) - len(sealed2)
	if diff < 0 {
		diff = -diff
	}
	// Should be identical size since both pad to same bucket
	if diff != 0 {
		t.Errorf("sealed sizes should be equal due to padding: %d vs %d", len(sealed1), len(sealed2))
	}
}
