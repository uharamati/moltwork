package crypto

import (
	"bytes"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	// Generate recipient keypair
	recipient, err := GenerateExchangeKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("this is the PSK that needs to be distributed")

	// Seal to recipient's public key
	sealed, err := SealToPublicKey(recipient.Public, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Must be longer than the plaintext (has pubkey + nonce overhead)
	if len(sealed) <= len(plaintext) {
		t.Errorf("sealed length %d should be > plaintext length %d", len(sealed), len(plaintext))
	}

	// Open with recipient's private key
	decrypted, err := OpenFromPublicKey(recipient.Private, sealed)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted does not match plaintext")
	}
}

func TestSealOpenWrongKey(t *testing.T) {
	recipient, err := GenerateExchangeKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := GenerateExchangeKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("secret data")
	sealed, err := SealToPublicKey(recipient.Public, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Try to open with wrong private key — should fail
	_, err = OpenFromPublicKey(wrongKey.Private, sealed)
	if err == nil {
		t.Fatal("expected decryption to fail with wrong key")
	}
}

func TestSealOpenEmptyPlaintext(t *testing.T) {
	recipient, err := GenerateExchangeKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Empty plaintext should work
	sealed, err := SealToPublicKey(recipient.Public, []byte{})
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := OpenFromPublicKey(recipient.Private, sealed)
	if err != nil {
		t.Fatal(err)
	}

	if len(decrypted) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(decrypted))
	}
}

func TestOpenTruncatedSealed(t *testing.T) {
	recipient, err := GenerateExchangeKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Too short — less than pubkey + nonce + 1
	_, err = OpenFromPublicKey(recipient.Private, make([]byte, 30))
	if err == nil {
		t.Fatal("expected error for truncated input")
	}
}

func TestSealDifferentEachTime(t *testing.T) {
	recipient, err := GenerateExchangeKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("same plaintext")

	sealed1, err := SealToPublicKey(recipient.Public, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	sealed2, err := SealToPublicKey(recipient.Public, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Two seals of the same plaintext should produce different ciphertext
	// (different ephemeral keys and nonces)
	if bytes.Equal(sealed1, sealed2) {
		t.Error("two seals produced identical output — ephemeral keys or nonces are not random")
	}

	// But both should decrypt to the same plaintext
	dec1, _ := OpenFromPublicKey(recipient.Private, sealed1)
	dec2, _ := OpenFromPublicKey(recipient.Private, sealed2)
	if !bytes.Equal(dec1, dec2) || !bytes.Equal(dec1, plaintext) {
		t.Error("decryption mismatch")
	}
}
