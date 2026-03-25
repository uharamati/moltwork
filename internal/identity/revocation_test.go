package identity

import (
	"testing"
	"time"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/crypto"
)

func TestSelfRevocation(t *testing.T) {
	kp, _ := crypto.GenerateSigningKeyPair()
	rev := CreateSelfRevocation(kp)

	if rev.Reason != moltcbor.RevocationBySelf {
		t.Error("should be self-revocation")
	}

	if err := VerifyRevocation(rev); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}

func TestManagerRevocation(t *testing.T) {
	subject, _ := crypto.GenerateSigningKeyPair()
	manager, _ := crypto.GenerateSigningKeyPair()

	// Set up org map
	om := NewOrgMap()
	now := time.Now().Unix()
	signData := CreateRelationshipSignData(subject.Public, manager.Public, now)
	rel := moltcbor.OrgRelationship{
		SubjectPubKey: subject.Public,
		ManagerPubKey: manager.Public,
		SubjectSig:    crypto.Sign(subject.Private, signData),
		ManagerSig:    crypto.Sign(manager.Private, signData),
		Timestamp:     now,
	}
	om.AddVerifiedRelationship(rel)

	// Manager revokes subject
	rev, err := CreateManagerRevocation(subject.Public, manager, om)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyRevocation(rev); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}

func TestManagerRevocationRequiresOrgRelationship(t *testing.T) {
	subject, _ := crypto.GenerateSigningKeyPair()
	notManager, _ := crypto.GenerateSigningKeyPair()

	om := NewOrgMap() // empty - no relationships

	_, err := CreateManagerRevocation(subject.Public, notManager, om)
	if err == nil {
		t.Error("should reject revocation from non-manager")
	}
}

func TestQuorumRevocation(t *testing.T) {
	target, _ := crypto.GenerateSigningKeyPair()

	signers := make([]*crypto.SigningKeyPair, 4)
	for i := range signers {
		signers[i], _ = crypto.GenerateSigningKeyPair()
	}

	// 4 signers out of 5 eligible (2/3 of 5 = 4 needed)
	rev, err := CreateQuorumRevocation(target.Public, signers, 5)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyRevocation(rev); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}

func TestQuorumRevocationInsufficientSigners(t *testing.T) {
	target, _ := crypto.GenerateSigningKeyPair()

	signers := make([]*crypto.SigningKeyPair, 2)
	for i := range signers {
		signers[i], _ = crypto.GenerateSigningKeyPair()
	}

	_, err := CreateQuorumRevocation(target.Public, signers, 5)
	if err == nil {
		t.Error("should reject insufficient signers")
	}
}

func TestIsEntryPostRevocation(t *testing.T) {
	revTime := int64(1000)

	if !IsEntryPostRevocation(1001, revTime) {
		t.Error("entry after revocation should be flagged")
	}
	if IsEntryPostRevocation(999, revTime) {
		t.Error("entry before revocation should not be flagged")
	}
	if IsEntryPostRevocation(1000, revTime) {
		t.Error("entry at exact revocation time should not be flagged")
	}
}
