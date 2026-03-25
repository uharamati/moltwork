package identity

import (
	"fmt"
	"sync"
	"testing"
	"time"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/crypto"
)

func TestRegistryRegisterAndLookup(t *testing.T) {
	r := NewRegistry()
	kp, _ := crypto.GenerateSigningKeyPair()

	agent := &Agent{
		PublicKey:      kp.Public,
		PlatformUserID: "U12345",
		Platform:       "slack",
		DisplayName:    "Alice",
	}

	if err := r.Register(agent); err != nil {
		t.Fatal(err)
	}

	// Lookup by key
	found := r.GetByPublicKey(kp.Public)
	if found == nil {
		t.Fatal("should find by public key")
	}
	if found.DisplayName != "Alice" {
		t.Error("display name mismatch")
	}

	// Lookup by platform ID
	found = r.GetByPlatformID("slack", "U12345")
	if found == nil {
		t.Fatal("should find by platform ID")
	}
}

func TestRegistryRejectsDuplicatePlatformID(t *testing.T) {
	r := NewRegistry()
	kp1, _ := crypto.GenerateSigningKeyPair()
	kp2, _ := crypto.GenerateSigningKeyPair()

	r.Register(&Agent{
		PublicKey:      kp1.Public,
		PlatformUserID: "U12345",
		Platform:       "slack",
	})

	err := r.Register(&Agent{
		PublicKey:      kp2.Public,
		PlatformUserID: "U12345",
		Platform:       "slack",
	})
	if err == nil {
		t.Error("should reject duplicate platform user ID with different key")
	}
}

func TestRegistryAllowsSameAgentReregister(t *testing.T) {
	r := NewRegistry()
	kp, _ := crypto.GenerateSigningKeyPair()

	r.Register(&Agent{
		PublicKey:      kp.Public,
		PlatformUserID: "U12345",
		Platform:       "slack",
		DisplayName:    "Alice",
	})

	// Same key re-registering should be fine
	err := r.Register(&Agent{
		PublicKey:      kp.Public,
		PlatformUserID: "U12345",
		Platform:       "slack",
		DisplayName:    "Alice Updated",
	})
	if err != nil {
		t.Errorf("re-registration with same key should succeed: %v", err)
	}
}

func TestRegistryRevocation(t *testing.T) {
	r := NewRegistry()
	kp, _ := crypto.GenerateSigningKeyPair()

	r.Register(&Agent{
		PublicKey:      kp.Public,
		PlatformUserID: "U12345",
		Platform:       "slack",
	})

	if r.IsRevoked(kp.Public) {
		t.Error("should not be revoked initially")
	}

	r.MarkRevoked(kp.Public)

	if !r.IsRevoked(kp.Public) {
		t.Error("should be revoked after marking")
	}
}

func TestOrgMapMutualHandshake(t *testing.T) {
	om := NewOrgMap()
	subject, _ := crypto.GenerateSigningKeyPair()
	manager, _ := crypto.GenerateSigningKeyPair()

	now := time.Now().Unix()
	signData := CreateRelationshipSignData(subject.Public, manager.Public, now)

	subjectSig := crypto.Sign(subject.Private, signData)
	managerSig := crypto.Sign(manager.Private, signData)

	rel := moltcbor.OrgRelationship{
		SubjectPubKey: subject.Public,
		ManagerPubKey: manager.Public,
		SubjectSig:    subjectSig,
		ManagerSig:    managerSig,
		Timestamp:     now,
	}

	if err := om.AddVerifiedRelationship(rel); err != nil {
		t.Fatal(err)
	}

	if !om.IsManager(manager.Public, subject.Public) {
		t.Error("manager should be verified")
	}

	reports := om.GetDirectReports(manager.Public)
	if len(reports) != 1 {
		t.Fatalf("expected 1 direct report, got %d", len(reports))
	}
}

func TestOrgMapRejectsInvalidSignature(t *testing.T) {
	om := NewOrgMap()
	subject, _ := crypto.GenerateSigningKeyPair()
	manager, _ := crypto.GenerateSigningKeyPair()
	imposter, _ := crypto.GenerateSigningKeyPair()

	now := time.Now().Unix()
	signData := CreateRelationshipSignData(subject.Public, manager.Public, now)

	subjectSig := crypto.Sign(subject.Private, signData)
	fakeSig := crypto.Sign(imposter.Private, signData) // wrong signer

	rel := moltcbor.OrgRelationship{
		SubjectPubKey: subject.Public,
		ManagerPubKey: manager.Public,
		SubjectSig:    subjectSig,
		ManagerSig:    fakeSig,
		Timestamp:     now,
	}

	if err := om.AddVerifiedRelationship(rel); err == nil {
		t.Error("should reject invalid manager signature")
	}
}

func TestRegistryConcurrentAccess(t *testing.T) {
	r := NewRegistry()

	const numGoroutines = 10

	// Pre-generate keys so each goroutine has its own agent identity.
	type agentFixture struct {
		kp   *crypto.SigningKeyPair
		id   string
		name string
	}
	fixtures := make([]agentFixture, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		kp, err := crypto.GenerateSigningKeyPair()
		if err != nil {
			t.Fatalf("key generation failed: %v", err)
		}
		fixtures[i] = agentFixture{
			kp:   kp,
			id:   fmt.Sprintf("U%05d", i),
			name: fmt.Sprintf("Agent-%d", i),
		}
	}

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			f := fixtures[idx]

			// Register this goroutine's agent.
			if err := r.Register(&Agent{
				PublicKey:      f.kp.Public,
				PlatformUserID: f.id,
				Platform:       "slack",
				DisplayName:    f.name,
			}); err != nil {
				t.Errorf("goroutine %d: Register failed: %v", idx, err)
				return
			}

			// Query our own agent by public key.
			if got := r.GetByPublicKey(f.kp.Public); got == nil {
				t.Errorf("goroutine %d: GetByPublicKey returned nil after Register", idx)
			}

			// Enumerate all agents (should not panic).
			_ = r.All()

			// Check registration status.
			if !r.IsRegisteredAgent(f.kp.Public) {
				t.Errorf("goroutine %d: IsRegisteredAgent returned false after Register", idx)
			}

			// Check revocation status (should be false).
			if r.IsRevoked(f.kp.Public) {
				t.Errorf("goroutine %d: IsRevoked returned true before marking", idx)
			}
		}(i)
	}

	wg.Wait()

	// After all goroutines complete, the registry should contain exactly numGoroutines agents.
	if got := r.Count(); got != numGoroutines {
		t.Errorf("expected %d agents, got %d", numGoroutines, got)
	}

	all := r.All()
	if len(all) != numGoroutines {
		t.Errorf("All() returned %d agents, expected %d", len(all), numGoroutines)
	}
}

func TestSlackDomainExtraction(t *testing.T) {
	tests := []struct {
		url    string
		domain string
	}{
		{"https://toriihq.slack.com/", "toriihq.slack.com"},
		{"https://mycompany.slack.com", "mycompany.slack.com"},
		{"http://test.slack.com/", "test.slack.com"},
	}

	for _, tt := range tests {
		got := extractDomain(tt.url)
		if got != tt.domain {
			t.Errorf("extractDomain(%q) = %q, want %q", tt.url, got, tt.domain)
		}
	}
}
