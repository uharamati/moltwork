package crypto

import (
	"testing"

	"pgregory.net/rapid"
)

func TestPropertyEncryptDecryptRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		plaintext := rapid.SliceOf(rapid.Byte()).Draw(t, "plaintext")
		if len(plaintext) == 0 {
			plaintext = []byte{0} // need at least 1 byte
		}

		key := RandomBytes(32)
		ciphertext, err := Encrypt(key, plaintext)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}

		decrypted, err := Decrypt(key, ciphertext)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}

		if !ConstantTimeEqual(plaintext, decrypted) {
			t.Fatal("round-trip failed: decrypted != plaintext")
		}
	})
}

func TestPropertyPadUnpadRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Max data size is 65536 - 4 (for length prefix)
		size := rapid.IntRange(0, 65532).Draw(t, "size")
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i % 256)
		}

		padded, err := Pad(data)
		if err != nil {
			t.Fatalf("pad: %v", err)
		}

		unpadded, err := Unpad(padded)
		if err != nil {
			t.Fatalf("unpad: %v", err)
		}

		if !ConstantTimeEqual(data, unpadded) {
			t.Fatal("round-trip failed: unpadded != data")
		}
	})
}

func TestPropertySignVerifyRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		message := rapid.SliceOfN(rapid.Byte(), 1, 1000).Draw(t, "message")

		kp, err := GenerateSigningKeyPair()
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}

		sig := Sign(kp.Private, message)
		if err := Verify(kp.Public, message, sig); err != nil {
			t.Fatalf("verify: %v", err)
		}
	})
}

func TestPairwiseSecretSymmetry(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		alice, err := GenerateExchangeKeyPair()
		if err != nil {
			t.Fatalf("keygen alice: %v", err)
		}
		bob, err := GenerateExchangeKeyPair()
		if err != nil {
			t.Fatalf("keygen bob: %v", err)
		}

		secretAB, err := DerivePairwiseSecret(alice, bob.Public)
		if err != nil {
			t.Fatalf("derive A->B: %v", err)
		}
		secretBA, err := DerivePairwiseSecret(bob, alice.Public)
		if err != nil {
			t.Fatalf("derive B->A: %v", err)
		}

		if secretAB != secretBA {
			t.Fatal("pairwise secret asymmetry: A->B != B->A")
		}
	})
}
