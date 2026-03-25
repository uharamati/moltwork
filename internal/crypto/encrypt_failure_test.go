package crypto

import (
	"bytes"
	"testing"
)

// --- DecryptGroupKey failure cases ---

func TestDecryptGroupKeyCorruptedCiphertext(t *testing.T) {
	pairwise := [32]byte{}
	copy(pairwise[:], RandomBytes(32))

	groupKey := GenerateGroupKey()
	encrypted, err := EncryptGroupKeyForMember(pairwise, groupKey)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt several bytes in the ciphertext
	for i := len(encrypted) / 2; i < len(encrypted)/2+4; i++ {
		encrypted[i] ^= 0xff
	}

	_, err = DecryptGroupKey(pairwise, encrypted)
	if err == nil {
		t.Error("DecryptGroupKey with corrupted ciphertext should return error, not succeed")
	}
}

func TestDecryptGroupKeyWrongKey(t *testing.T) {
	pairwise := [32]byte{}
	copy(pairwise[:], RandomBytes(32))
	wrongKey := [32]byte{}
	copy(wrongKey[:], RandomBytes(32))

	groupKey := GenerateGroupKey()
	encrypted, err := EncryptGroupKeyForMember(pairwise, groupKey)
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptGroupKey(wrongKey, encrypted)
	if err == nil {
		t.Error("DecryptGroupKey with wrong pairwise secret should return error")
	}
}

func TestDecryptGroupKeyEmptyInput(t *testing.T) {
	pairwise := [32]byte{}
	copy(pairwise[:], RandomBytes(32))

	_, err := DecryptGroupKey(pairwise, []byte{})
	if err == nil {
		t.Error("DecryptGroupKey with empty input should return error")
	}
}

func TestDecryptGroupKeyTruncatedInput(t *testing.T) {
	pairwise := [32]byte{}
	copy(pairwise[:], RandomBytes(32))

	groupKey := GenerateGroupKey()
	encrypted, err := EncryptGroupKeyForMember(pairwise, groupKey)
	if err != nil {
		t.Fatal(err)
	}

	// Truncate to half the ciphertext
	_, err = DecryptGroupKey(pairwise, encrypted[:len(encrypted)/2])
	if err == nil {
		t.Error("DecryptGroupKey with truncated ciphertext should return error")
	}
}

// --- OpenFromPeer failure cases ---

func TestOpenFromPeerCorruptedSealed(t *testing.T) {
	alice, _ := GenerateExchangeKeyPair()
	bob, _ := GenerateExchangeKeyPair()

	secret, _ := DerivePairwiseSecret(alice, bob.Public)
	sealed, err := SealForPeer(secret, []byte("confidential agent message"))
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt the sealed data
	corrupted := make([]byte, len(sealed))
	copy(corrupted, sealed)
	for i := len(corrupted) / 2; i < len(corrupted)/2+4; i++ {
		corrupted[i] ^= 0xff
	}

	_, err = OpenFromPeer(secret, corrupted)
	if err == nil {
		t.Error("OpenFromPeer with corrupted sealed data should return error")
	}
}

func TestOpenFromPeerEmptySealed(t *testing.T) {
	secret := [32]byte{}
	copy(secret[:], RandomBytes(32))

	_, err := OpenFromPeer(secret, []byte{})
	if err == nil {
		t.Error("OpenFromPeer with empty sealed data should return error")
	}
}

func TestOpenFromPeerTruncatedSealed(t *testing.T) {
	alice, _ := GenerateExchangeKeyPair()
	bob, _ := GenerateExchangeKeyPair()

	secret, _ := DerivePairwiseSecret(alice, bob.Public)
	sealed, err := SealForPeer(secret, []byte("secret coordination data"))
	if err != nil {
		t.Fatal(err)
	}

	// Only provide the nonce portion (first 24 bytes), no actual ciphertext
	if len(sealed) > 24 {
		_, err = OpenFromPeer(secret, sealed[:24])
		if err == nil {
			t.Error("OpenFromPeer with nonce-only data should return error")
		}
	}
}

// --- SealForPeer / OpenFromPeer mismatched keys ---

func TestSealOpenMismatchedKeys(t *testing.T) {
	alice, _ := GenerateExchangeKeyPair()
	bob, _ := GenerateExchangeKeyPair()
	carol, _ := GenerateExchangeKeyPair()

	secretAB, _ := DerivePairwiseSecret(alice, bob.Public)
	secretBC, _ := DerivePairwiseSecret(bob, carol.Public)

	plaintext := []byte("message sealed with alice-bob secret")
	sealed, err := SealForPeer(secretAB, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Try to open with bob-carol secret — should fail
	_, err = OpenFromPeer(secretBC, sealed)
	if err == nil {
		t.Error("OpenFromPeer with mismatched pairwise secret should fail")
	}
}

func TestSealOpenRandomSecret(t *testing.T) {
	alice, _ := GenerateExchangeKeyPair()
	bob, _ := GenerateExchangeKeyPair()

	secret, _ := DerivePairwiseSecret(alice, bob.Public)
	sealed, err := SealForPeer(secret, []byte("sensitive data"))
	if err != nil {
		t.Fatal(err)
	}

	// Try with a completely random secret
	randomSecret := [32]byte{}
	copy(randomSecret[:], RandomBytes(32))

	_, err = OpenFromPeer(randomSecret, sealed)
	if err == nil {
		t.Error("OpenFromPeer with random secret should fail")
	}
}

// --- EncryptGroupKeyForMember + DecryptGroupKey round-trip ---

func TestGroupKeyRoundTripWithDerivedSecret(t *testing.T) {
	alice, _ := GenerateExchangeKeyPair()
	bob, _ := GenerateExchangeKeyPair()

	// Alice and Bob derive same pairwise secret
	secretA, _ := DerivePairwiseSecret(alice, bob.Public)
	secretB, _ := DerivePairwiseSecret(bob, alice.Public)

	groupKey := GenerateGroupKey()

	// Alice encrypts group key for Bob
	encrypted, err := EncryptGroupKeyForMember(secretA, groupKey)
	if err != nil {
		t.Fatal(err)
	}

	// Bob decrypts with his derived secret
	decrypted, err := DecryptGroupKey(secretB, encrypted)
	if err != nil {
		t.Fatalf("Bob should be able to decrypt group key: %v", err)
	}

	if decrypted != groupKey {
		t.Error("decrypted group key doesn't match original")
	}
}

func TestGroupKeyRoundTripMultipleMembers(t *testing.T) {
	// Simulate distributing a group key to multiple members
	admin, _ := GenerateExchangeKeyPair()
	member1, _ := GenerateExchangeKeyPair()
	member2, _ := GenerateExchangeKeyPair()

	groupKey := GenerateGroupKey()

	// Admin encrypts for each member
	secret1, _ := DerivePairwiseSecret(admin, member1.Public)
	secret2, _ := DerivePairwiseSecret(admin, member2.Public)

	enc1, err := EncryptGroupKeyForMember(secret1, groupKey)
	if err != nil {
		t.Fatal(err)
	}
	enc2, err := EncryptGroupKeyForMember(secret2, groupKey)
	if err != nil {
		t.Fatal(err)
	}

	// Each member decrypts with their own pairwise secret
	sec1B, _ := DerivePairwiseSecret(member1, admin.Public)
	sec2B, _ := DerivePairwiseSecret(member2, admin.Public)

	dec1, err := DecryptGroupKey(sec1B, enc1)
	if err != nil {
		t.Fatalf("member1 decrypt failed: %v", err)
	}
	dec2, err := DecryptGroupKey(sec2B, enc2)
	if err != nil {
		t.Fatalf("member2 decrypt failed: %v", err)
	}

	if dec1 != groupKey || dec2 != groupKey {
		t.Error("members should recover the same group key")
	}

	// Ciphertexts should differ (different keys, different nonces)
	if bytes.Equal(enc1, enc2) {
		t.Error("encrypted group keys for different members should differ")
	}

	// Member1 should NOT be able to decrypt member2's copy
	_, err = DecryptGroupKey(sec1B, enc2)
	if err == nil {
		t.Error("member1 should not decrypt group key encrypted for member2")
	}
}
