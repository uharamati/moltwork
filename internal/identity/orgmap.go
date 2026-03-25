package identity

import (
	"crypto/ed25519"
	"fmt"
	"sync"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/crypto"
)

// Relationship represents a verified "reports to" relationship.
type Relationship struct {
	SubjectPubKey ed25519.PublicKey
	ManagerPubKey ed25519.PublicKey
	Timestamp     int64
	EntryHash     [32]byte // hash of the OrgRelationship entry
}

// OrgMap tracks verified organizational relationships.
type OrgMap struct {
	mu            sync.RWMutex
	relationships map[string]*Relationship // subjectKeyHex -> relationship
}

// NewOrgMap creates an empty org map.
func NewOrgMap() *OrgMap {
	return &OrgMap{
		relationships: make(map[string]*Relationship),
	}
}

// AddVerifiedRelationship adds a verified mutual-handshake relationship.
// Both subject and manager signatures must be valid.
func (om *OrgMap) AddVerifiedRelationship(rel moltcbor.OrgRelationship) error {
	// Verify both signatures (rule C2)
	relData := relationshipSignData(rel.SubjectPubKey, rel.ManagerPubKey, rel.Timestamp)

	if err := crypto.Verify(rel.SubjectPubKey, relData, rel.SubjectSig); err != nil {
		return fmt.Errorf("invalid subject signature: %w", err)
	}
	if err := crypto.Verify(rel.ManagerPubKey, relData, rel.ManagerSig); err != nil {
		return fmt.Errorf("invalid manager signature: %w", err)
	}

	om.mu.Lock()
	defer om.mu.Unlock()

	keyStr := fmt.Sprintf("%x", rel.SubjectPubKey)
	om.relationships[keyStr] = &Relationship{
		SubjectPubKey: rel.SubjectPubKey,
		ManagerPubKey: rel.ManagerPubKey,
		Timestamp:     rel.Timestamp,
	}
	return nil
}

// GetManager returns the verified manager for a given agent, or nil.
func (om *OrgMap) GetManager(subjectPubKey ed25519.PublicKey) *Relationship {
	om.mu.RLock()
	defer om.mu.RUnlock()
	return om.relationships[fmt.Sprintf("%x", subjectPubKey)]
}

// GetDirectReports returns agents whose verified manager is the given key.
func (om *OrgMap) GetDirectReports(managerPubKey ed25519.PublicKey) []*Relationship {
	om.mu.RLock()
	defer om.mu.RUnlock()

	managerHex := fmt.Sprintf("%x", managerPubKey)
	var reports []*Relationship
	for _, rel := range om.relationships {
		if fmt.Sprintf("%x", rel.ManagerPubKey) == managerHex {
			reports = append(reports, rel)
		}
	}
	return reports
}

// IsManager checks if `manager` is the verified manager of `subject`.
func (om *OrgMap) IsManager(managerPubKey, subjectPubKey ed25519.PublicKey) bool {
	rel := om.GetManager(subjectPubKey)
	if rel == nil {
		return false
	}
	return crypto.ConstantTimeEqual(rel.ManagerPubKey, managerPubKey)
}

// CreateRelationshipSignData creates the data to be signed for a relationship claim.
// Both subject and manager sign the same data.
func CreateRelationshipSignData(subjectPubKey, managerPubKey ed25519.PublicKey, timestamp int64) []byte {
	return relationshipSignData(subjectPubKey, managerPubKey, timestamp)
}

func relationshipSignData(subjectPubKey, managerPubKey []byte, timestamp int64) []byte {
	data := struct {
		Subject   []byte `cbor:"1,keyasint"`
		Manager   []byte `cbor:"2,keyasint"`
		Timestamp int64  `cbor:"3,keyasint"`
	}{
		Subject:   subjectPubKey,
		Manager:   managerPubKey,
		Timestamp: timestamp,
	}
	encoded, _ := moltcbor.Marshal(data)
	return encoded
}
