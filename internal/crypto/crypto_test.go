package crypto

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// --- Keys ---

func TestGenerateSigningKeyPair(t *testing.T) {
	kp, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if len(kp.Public) != ed25519.PublicKeySize {
		t.Errorf("public key size: got %d, want %d", len(kp.Public), ed25519.PublicKeySize)
	}
	if len(kp.Private) != ed25519.PrivateKeySize {
		t.Errorf("private key size: got %d, want %d", len(kp.Private), ed25519.PrivateKeySize)
	}
}

func TestGenerateExchangeKeyPair(t *testing.T) {
	kp, err := GenerateExchangeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if kp.Public == [32]byte{} {
		t.Error("public key is zero")
	}
	if kp.Private == [32]byte{} {
		t.Error("private key is zero")
	}
}

func TestZero(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	Zero(data)
	for i, b := range data {
		if b != 0 {
			t.Errorf("byte %d not zeroed: %d", i, b)
		}
	}
}

func TestSigningKeyZero(t *testing.T) {
	kp, _ := GenerateSigningKeyPair()
	kp.Zero()
	for _, b := range kp.Private {
		if b != 0 {
			t.Fatal("private key not zeroed")
		}
	}
}

// --- Sign/Verify ---

func TestSignVerifyRoundTrip(t *testing.T) {
	kp, _ := GenerateSigningKeyPair()
	msg := []byte("hello moltwork")

	sig := Sign(kp.Private, msg)
	if err := Verify(kp.Public, msg, sig); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
}

func TestVerifyRejectsTamperedMessage(t *testing.T) {
	kp, _ := GenerateSigningKeyPair()
	msg := []byte("hello")
	sig := Sign(kp.Private, msg)

	tampered := []byte("HELLO")
	if err := Verify(kp.Public, tampered, sig); err == nil {
		t.Error("tampered message should fail verification")
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	kp, _ := GenerateSigningKeyPair()
	msg := []byte("hello")
	sig := Sign(kp.Private, msg)

	sig[0] ^= 0xff
	if err := Verify(kp.Public, msg, sig); err == nil {
		t.Error("tampered signature should fail verification")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	kp1, _ := GenerateSigningKeyPair()
	kp2, _ := GenerateSigningKeyPair()
	msg := []byte("hello")
	sig := Sign(kp1.Private, msg)

	if err := Verify(kp2.Public, msg, sig); err == nil {
		t.Error("wrong public key should fail verification")
	}
}

func TestVerifyRejectsShortSignature(t *testing.T) {
	kp, _ := GenerateSigningKeyPair()
	if err := Verify(kp.Public, []byte("hello"), []byte("short")); err == nil {
		t.Error("short signature should fail")
	}
}

func TestConstantTimeEqual(t *testing.T) {
	a := []byte("hello")
	b := []byte("hello")
	c := []byte("world")

	if !ConstantTimeEqual(a, b) {
		t.Error("equal slices should match")
	}
	if ConstantTimeEqual(a, c) {
		t.Error("different slices should not match")
	}
}

// --- Encrypt/Decrypt ---

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := RandomBytes(32)
	plaintext := []byte("secret agent coordination data")

	blob, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	result, err := Decrypt(key, blob)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(result, plaintext) {
		t.Error("decrypted data doesn't match original")
	}
}

func TestDecryptFailsWithWrongKey(t *testing.T) {
	key1 := RandomBytes(32)
	key2 := RandomBytes(32)

	blob, _ := Encrypt(key1, []byte("secret"))
	_, err := Decrypt(key2, blob)
	if err == nil {
		t.Error("decrypt with wrong key should fail")
	}
}

func TestDecryptFailsWithTamperedData(t *testing.T) {
	key := RandomBytes(32)
	blob, _ := Encrypt(key, []byte("secret"))

	blob[len(blob)-1] ^= 0xff
	_, err := Decrypt(key, blob)
	if err == nil {
		t.Error("decrypt with tampered data should fail")
	}
}

func TestDecryptFailsWithShortBlob(t *testing.T) {
	key := RandomBytes(32)
	_, err := Decrypt(key, []byte("short"))
	if err == nil {
		t.Error("decrypt with short blob should fail")
	}
}

// --- Key Exchange ---

func TestDeriveSharedSecret(t *testing.T) {
	alice, _ := GenerateExchangeKeyPair()
	bob, _ := GenerateExchangeKeyPair()

	secretAlice, err := DeriveSharedSecret(alice.Private, bob.Public)
	if err != nil {
		t.Fatal(err)
	}

	secretBob, err := DeriveSharedSecret(bob.Private, alice.Public)
	if err != nil {
		t.Fatal(err)
	}

	if secretAlice != secretBob {
		t.Error("shared secrets should be identical")
	}

	if secretAlice == [32]byte{} {
		t.Error("shared secret should not be zero")
	}
}

// --- Group Key ---

func TestGroupKeyDistribution(t *testing.T) {
	pairwise := [32]byte{}
	copy(pairwise[:], RandomBytes(32))

	groupKey := GenerateGroupKey()

	encrypted, err := EncryptGroupKeyForMember(pairwise, groupKey)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := DecryptGroupKey(pairwise, encrypted)
	if err != nil {
		t.Fatal(err)
	}

	if decrypted != groupKey {
		t.Error("decrypted group key doesn't match original")
	}
}

func TestGroupKeyDecryptWrongSecret(t *testing.T) {
	pairwise1 := [32]byte{}
	copy(pairwise1[:], RandomBytes(32))
	pairwise2 := [32]byte{}
	copy(pairwise2[:], RandomBytes(32))

	groupKey := GenerateGroupKey()
	encrypted, _ := EncryptGroupKeyForMember(pairwise1, groupKey)

	_, err := DecryptGroupKey(pairwise2, encrypted)
	if err == nil {
		t.Error("wrong pairwise secret should fail")
	}
}

// --- Padding ---

func TestPadUnpadRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, 100, 250, 500, 1000, 4000, 16000, 60000} {
		data := RandomBytes(size)
		padded, err := Pad(data)
		if err != nil {
			t.Fatalf("pad size %d: %v", size, err)
		}

		// Verify padded to a valid bucket
		validBucket := false
		for _, bucket := range sizeBuckets {
			if len(padded) == bucket {
				validBucket = true
				break
			}
		}
		if !validBucket {
			t.Errorf("size %d padded to %d, not a valid bucket", size, len(padded))
		}

		unpadded, err := Unpad(padded)
		if err != nil {
			t.Fatalf("unpad size %d: %v", size, err)
		}

		if !bytes.Equal(unpadded, data) {
			t.Errorf("round-trip failed for size %d", size)
		}
	}
}

func TestPadTooLarge(t *testing.T) {
	data := make([]byte, 70000)
	_, err := Pad(data)
	if err == nil {
		t.Error("should reject data too large for any bucket")
	}
}

func TestUnpadTooShort(t *testing.T) {
	_, err := Unpad([]byte{1, 2})
	if err == nil {
		t.Error("should reject too-short padded data")
	}
}

// --- Hash ---

func TestHash(t *testing.T) {
	h1 := Hash([]byte("hello"))
	h2 := Hash([]byte("hello"))
	h3 := Hash([]byte("world"))

	if h1 != h2 {
		t.Error("same input should produce same hash")
	}
	if h1 == h3 {
		t.Error("different input should produce different hash")
	}
	if h1 == [32]byte{} {
		t.Error("hash should not be zero")
	}
}

func TestHashMulti(t *testing.T) {
	h1 := HashMulti([]byte("hello"), []byte("world"))
	h2 := HashMulti([]byte("hello"), []byte("world"))
	h3 := HashMulti([]byte("helloworld"))

	if h1 != h2 {
		t.Error("same parts should produce same hash")
	}
	// HashMulti(a, b) == Hash(a || b) since both just concatenate
	if h1 != h3 {
		t.Error("concatenated should match multi")
	}
}

// --- Backup ---

func TestBackupRoundTrip(t *testing.T) {
	keyMaterial := RandomBytes(64)
	passphrase := []byte("test-passphrase-123")

	backup, err := BackupExport(keyMaterial, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	restored, err := BackupImport(backup, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(restored, keyMaterial) {
		t.Error("restored key material doesn't match original")
	}
}

func TestBackupWrongPassphrase(t *testing.T) {
	keyMaterial := RandomBytes(32)
	backup, _ := BackupExport(keyMaterial, []byte("correct"))

	_, err := BackupImport(backup, []byte("wrong"))
	if err == nil {
		t.Error("wrong passphrase should fail")
	}
}

func TestBackupInvalidData(t *testing.T) {
	_, err := BackupImport([]byte{}, []byte("pass"))
	if err == nil {
		t.Error("empty backup should fail")
	}
}

// --- Nonce ---

func TestNonceUniqueness(t *testing.T) {
	n1 := Nonce(24)
	n2 := Nonce(24)
	if bytes.Equal(n1, n2) {
		t.Error("two nonces should not be equal")
	}
}
