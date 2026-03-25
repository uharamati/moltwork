package dag

import (
	"crypto/ed25519"
	"fmt"
	"time"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/crypto"
)

// SignedEntry is a log entry with signature and content-addressed hash.
type SignedEntry struct {
	Hash      [32]byte            // BLAKE3 hash of the signed envelope
	Envelope  moltcbor.Envelope   // version, type, payload
	AuthorKey ed25519.PublicKey    // who signed this
	Signature []byte              // Ed25519 signature of the CBOR-encoded envelope
	Parents   [][32]byte          // content-addressed hashes of parent entries
	CreatedAt int64               // Unix timestamp
	RawCBOR   []byte              // the signed envelope bytes (for hash verification)
}

// SignedEnvelopeBytes is the format that gets signed and hashed:
// CBOR(envelope) with parent hashes prepended.
type signableData struct {
	Parents  [][]byte `cbor:"1,keyasint"`
	Envelope []byte   `cbor:"2,keyasint"`
	Time     int64    `cbor:"3,keyasint"`
}

// NewSignedEntry creates a new log entry, signs it, and computes its hash.
func NewSignedEntry(
	entryType moltcbor.EntryType,
	payload []byte,
	authorKey *crypto.SigningKeyPair,
	parents [][32]byte,
) (*SignedEntry, error) {
	env := moltcbor.Envelope{
		Version: moltcbor.ProtocolVersion,
		Type:    entryType,
		Payload: payload,
	}

	now := time.Now().Unix()

	// Build signable data: parents + envelope + timestamp
	parentSlices := make([][]byte, len(parents))
	for i, p := range parents {
		parentSlices[i] = p[:]
	}

	envBytes, err := moltcbor.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}

	sigData := signableData{
		Parents:  parentSlices,
		Envelope: envBytes,
		Time:     now,
	}
	sigBytes, err := moltcbor.Marshal(sigData)
	if err != nil {
		return nil, fmt.Errorf("marshal signable: %w", err)
	}

	// Sign (rule C2: signature covers everything)
	sig := crypto.Sign(authorKey.Private, sigBytes)

	// Hash = BLAKE3(signable || signature) — content-addressed
	hash := crypto.HashMulti(sigBytes, sig)

	return &SignedEntry{
		Hash:      hash,
		Envelope:  env,
		AuthorKey: authorKey.Public,
		Signature: sig,
		Parents:   parents,
		CreatedAt: now,
		RawCBOR:   sigBytes,
	}, nil
}

// VerifyEntry checks the signature and hash of an entry (rule C2: verify before anything else).
func VerifyEntry(entry *SignedEntry) error {
	// Verify signature first (rule C2)
	if err := crypto.Verify(entry.AuthorKey, entry.RawCBOR, entry.Signature); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// Verify hash
	expectedHash := crypto.HashMulti(entry.RawCBOR, entry.Signature)
	if expectedHash != entry.Hash {
		return fmt.Errorf("hash mismatch")
	}

	return nil
}
