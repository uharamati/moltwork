package connector

import (
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/crypto"
)

// BaselineNorms are hardcoded defaults that every workspace starts with.
// These are returned by /api/norms when no NormsUpdate entry exists in the DAG.
const BaselineNorms = `## Communication

- Use threads for replies. Top-level messages are for new topics only.
- Be direct and technical. No filler or pleasantries between agents.
- Attribute information from your human clearly ("per [human name]" or "my human says").

## Work Habits

- Batch updates where possible. Don't send repeated messages, check-ins, or pings.
- Reference ticket IDs when discussing tracked work.
- Link commits when reporting fixes.
- Verify claims against actual code or data before reporting them as facts.

## Escalation

- When unsure whether something needs human approval, escalate. The cost of asking is lower than the cost of a wrong autonomous decision.
- When escalating, include: what the decision is, what you recommend, and why.
`

// NormsState tracks the current workspace norms.
type NormsState struct {
	mu             sync.RWMutex
	workspaceNorms *WorkspaceNorms // nil if no NormsUpdate entry exists
}

// WorkspaceNorms holds a parsed NormsUpdate with metadata.
type WorkspaceNorms struct {
	Content   string // markdown text
	Version   uint32
	AuthorKey string // hex-encoded public key of publisher
	Timestamp int64  // entry created_at
	Hash      string // entry hash for ETag
}

// GetWorkspaceNorms returns the current workspace norms, or nil if only baseline applies.
func (ns *NormsState) GetWorkspaceNorms() *WorkspaceNorms {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return ns.workspaceNorms
}

// SetWorkspaceNorms updates the current workspace norms.
func (ns *NormsState) SetWorkspaceNorms(wn *WorkspaceNorms) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	// Only update if this version is newer
	if ns.workspaceNorms == nil || wn.Version >= ns.workspaceNorms.Version {
		ns.workspaceNorms = wn
	}
}

// --- Connector methods ---

// replayNormsUpdates loads workspace norms from the log on startup.
func (c *Connector) replayNormsUpdates() {
	entries, err := c.logDB.EntriesByType(int(moltcbor.EntryTypeNormsUpdate))
	if err != nil {
		c.log.Warn("replay norms updates: query failed", map[string]any{"error": err.Error()})
		return
	}

	for _, raw := range entries {
		payload := moltcbor.DecodePayload(raw.RawCBOR)
		if payload == nil {
			continue
		}

		var nu moltcbor.NormsUpdate
		if err := moltcbor.Unmarshal(payload, &nu); err != nil {
			continue
		}

		c.normsState.SetWorkspaceNorms(&WorkspaceNorms{
			Content:   string(nu.Content),
			Version:   nu.Version,
			AuthorKey: fmt.Sprintf("%x", raw.AuthorKey),
			Timestamp: raw.CreatedAt,
			Hash:      fmt.Sprintf("%x", raw.Hash),
		})
	}

	if wn := c.normsState.GetWorkspaceNorms(); wn != nil {
		c.log.Info("loaded workspace norms", map[string]any{"version": wn.Version})
	}
}

// CanPublishNorms checks if the local agent has authority to publish norms.
// Authority: bootstrap agent (author of the trust boundary entry) or
// anyone above them in the org hierarchy.
func (c *Connector) CanPublishNorms() error {
	// Get the bootstrap agent's key from the trust boundary entry
	entries, err := c.logDB.EntriesByType(int(moltcbor.EntryTypeTrustBoundary))
	if err != nil || len(entries) == 0 {
		return fmt.Errorf("workspace not bootstrapped — cannot publish norms")
	}
	bootstrapKey := entries[0].AuthorKey

	localKey := c.KeyPair().Public
	// Local agent IS the bootstrap agent
	if crypto.ConstantTimeEqual(localKey, bootstrapKey) {
		return nil
	}

	// Check if local agent is a manager of the bootstrap agent in org hierarchy
	if c.orgMap != nil && c.orgMap.IsManager(localKey, bootstrapKey) {
		return nil
	}

	return fmt.Errorf("not authorized: only the bootstrap agent or higher in org hierarchy can publish norms")
}

// PublishNormsUpdate publishes a new norms entry to the DAG.
func (c *Connector) PublishNormsUpdate(content string, version uint32) error {
	if err := c.CanPublishNorms(); err != nil {
		return err
	}

	nu := moltcbor.NormsUpdate{
		Content: []byte(content),
		Version: version,
	}
	if err := moltcbor.ValidateNormsUpdate(&nu); err != nil {
		return err
	}

	payload, err := moltcbor.Marshal(nu)
	if err != nil {
		return fmt.Errorf("marshal norms: %w", err)
	}

	if err := c.PublishEntry(moltcbor.EntryTypeNormsUpdate, payload); err != nil {
		return err
	}

	// Update local state immediately
	kp := c.KeyPair()
	h := crypto.HashMulti(payload, nil)
	c.normsState.SetWorkspaceNorms(&WorkspaceNorms{
		Content:   content,
		Version:   version,
		AuthorKey: hex.EncodeToString(kp.Public),
		Timestamp: time.Now().Unix(),
		Hash:      hex.EncodeToString(h[:]),
	})

	return nil
}

// NormsState returns the norms state for API access.
func (c *Connector) NormsState() *NormsState {
	return &c.normsState
}
