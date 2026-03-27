package identity

import (
	"crypto/ed25519"
	"fmt"
	"time"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/crypto"
)

// CreateManagerRevocation creates a revocation entry signed by the verified manager.
func CreateManagerRevocation(
	revokedPubKey ed25519.PublicKey,
	managerKeyPair *crypto.SigningKeyPair,
	orgMap *OrgMap,
) (*moltcbor.Revocation, error) {
	// Verify the revoker is actually the manager (rule R5)
	if !orgMap.IsManager(managerKeyPair.Public, revokedPubKey) {
		return nil, fmt.Errorf("revoker is not the verified manager of the target agent")
	}

	revokedHash := crypto.Hash(revokedPubKey)
	now := time.Now().Unix()

	signData := revocationSignData(revokedHash[:], now, moltcbor.RevocationByManager)
	sig := crypto.Sign(managerKeyPair.Private, signData)

	return &moltcbor.Revocation{
		RevokedKeyHash: revokedHash[:],
		Reason:         moltcbor.RevocationByManager,
		Timestamp:      now,
		Signatures:     [][]byte{sig},
		Revokers:       [][]byte{managerKeyPair.Public},
	}, nil
}

// CreateSelfRevocation creates a self-revocation entry.
func CreateSelfRevocation(keyPair *crypto.SigningKeyPair) *moltcbor.Revocation {
	revokedHash := crypto.Hash(keyPair.Public)
	now := time.Now().Unix()

	signData := revocationSignData(revokedHash[:], now, moltcbor.RevocationBySelf)
	sig := crypto.Sign(keyPair.Private, signData)

	return &moltcbor.Revocation{
		RevokedKeyHash: revokedHash[:],
		Reason:         moltcbor.RevocationBySelf,
		Timestamp:      now,
		Signatures:     [][]byte{sig},
		Revokers:       [][]byte{keyPair.Public},
	}
}

// CreateQuorumRevocation creates a quorum revocation requiring 3+ signers
// meeting 2/3 threshold of eligible voters.
func CreateQuorumRevocation(
	revokedPubKey ed25519.PublicKey,
	signers []*crypto.SigningKeyPair,
	totalEligible int,
) (*moltcbor.Revocation, error) {
	if len(signers) < 3 {
		return nil, fmt.Errorf("quorum requires at least 3 signers, got %d", len(signers))
	}

	threshold := (2 * totalEligible) / 3
	if totalEligible%3 != 0 {
		threshold++
	}
	if len(signers) < threshold {
		return nil, fmt.Errorf("quorum requires %d/%d signers, got %d", threshold, totalEligible, len(signers))
	}

	revokedHash := crypto.Hash(revokedPubKey)
	now := time.Now().Unix()
	signData := revocationSignData(revokedHash[:], now, moltcbor.RevocationByQuorum)

	sigs := make([][]byte, len(signers))
	revokerKeys := make([][]byte, len(signers))
	for i, kp := range signers {
		sigs[i] = crypto.Sign(kp.Private, signData)
		revokerKeys[i] = kp.Public
	}

	return &moltcbor.Revocation{
		RevokedKeyHash: revokedHash[:],
		Reason:         moltcbor.RevocationByQuorum,
		Timestamp:      now,
		Signatures:     sigs,
		Revokers:       revokerKeys,
	}, nil
}

// VerifyRevocation checks that a revocation entry is properly signed.
func VerifyRevocation(rev *moltcbor.Revocation) error {
	signData := revocationSignData(rev.RevokedKeyHash, rev.Timestamp, rev.Reason)

	if len(rev.Signatures) != len(rev.Revokers) {
		return fmt.Errorf("signature/revoker count mismatch")
	}
	if len(rev.Signatures) > 100 {
		return fmt.Errorf("excessive signature count: %d", len(rev.Signatures))
	}

	for i := range rev.Signatures {
		if err := crypto.Verify(rev.Revokers[i], signData, rev.Signatures[i]); err != nil {
			return fmt.Errorf("invalid signature from revoker %d: %w", i, err)
		}
	}

	switch rev.Reason {
	case moltcbor.RevocationByManager:
		if len(rev.Signatures) != 1 {
			return fmt.Errorf("manager revocation requires exactly 1 signature")
		}
	case moltcbor.RevocationBySelf:
		if len(rev.Signatures) != 1 {
			return fmt.Errorf("self revocation requires exactly 1 signature")
		}
	case moltcbor.RevocationByQuorum:
		if len(rev.Signatures) < 3 {
			return fmt.Errorf("quorum revocation requires at least 3 signatures")
		}
	}

	return nil
}

// IsEntryPostRevocation checks if an entry timestamp is after the revocation timestamp (rule R2).
func IsEntryPostRevocation(entryTimestamp, revocationTimestamp int64) bool {
	return entryTimestamp > revocationTimestamp
}

func revocationSignData(revokedKeyHash []byte, timestamp int64, reason moltcbor.RevocationReason) []byte {
	data := struct {
		KeyHash   []byte `cbor:"1,keyasint"`
		Timestamp int64  `cbor:"2,keyasint"`
		Reason    uint8  `cbor:"3,keyasint"`
	}{
		KeyHash:   revokedKeyHash,
		Timestamp: timestamp,
		Reason:    uint8(reason),
	}
	encoded, err := moltcbor.Marshal(data)
	if err != nil {
		panic("revocationSignData: marshal failed: " + err.Error())
	}
	return encoded
}
