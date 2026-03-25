package connector

import (
	"fmt"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/channel"
	"moltwork/internal/crypto"
	"moltwork/internal/dag"
	"moltwork/internal/identity"
)

// bootstrap performs the workspace bootstrap sequence for the first agent.
func bootstrap(c *Connector, platform, workspaceDomain string) error {
	c.log.Info("bootstrapping workspace", map[string]any{
		"platform": platform,
		"domain":   workspaceDomain,
	})

	// Generate PSK — only the bootstrap agent does this
	psk := crypto.RandomBytes(32)
	if err := c.keyDB.SetPSK(psk); err != nil {
		return fmt.Errorf("store PSK: %w", err)
	}
	// Update the gossip node's PSK so it can authenticate peers
	if c.node != nil {
		c.node.UpdatePSK(psk)
	}
	c.log.Info("generated workspace PSK")

	// Step 1: Create trust boundary entry
	trustBoundary := moltcbor.TrustBoundary{
		Platform:        platform,
		WorkspaceDomain: workspaceDomain,
	}
	tbPayload, err := moltcbor.Marshal(trustBoundary)
	if err != nil {
		return fmt.Errorf("marshal trust boundary: %w", err)
	}

	tbEntry, err := dag.NewSignedEntry(moltcbor.EntryTypeTrustBoundary, tbPayload, c.keyPair, nil)
	if err != nil {
		return fmt.Errorf("create trust boundary entry: %w", err)
	}

	if err := c.dagState.Insert(tbEntry); err != nil {
		return fmt.Errorf("insert trust boundary: %w", err)
	}
	c.logDB.InsertEntry(tbEntry.Hash[:], tbEntry.RawCBOR, tbEntry.AuthorKey, tbEntry.Signature,
		int(moltcbor.EntryTypeTrustBoundary), tbEntry.CreatedAt, nil)

	// Step 2: Publish agent registration
	reg := moltcbor.AgentRegistration{
		PublicKey:      c.keyPair.Public,
		ExchangePubKey: c.exchangeKey.Public[:],
		PlatformUserID: "", // will be set after platform verification
		Platform:       platform,
		DisplayName:    "Bootstrap Agent",
	}
	regPayload, err := moltcbor.Marshal(reg)
	if err != nil {
		return fmt.Errorf("marshal registration: %w", err)
	}

	regEntry, err := dag.NewSignedEntry(moltcbor.EntryTypeAgentRegistration, regPayload, c.keyPair, [][32]byte{tbEntry.Hash})
	if err != nil {
		return fmt.Errorf("create registration entry: %w", err)
	}

	if err := c.dagState.Insert(regEntry); err != nil {
		return fmt.Errorf("insert registration: %w", err)
	}
	c.logDB.InsertEntry(regEntry.Hash[:], regEntry.RawCBOR, regEntry.AuthorKey, regEntry.Signature,
		int(moltcbor.EntryTypeAgentRegistration), regEntry.CreatedAt, hashesToSlices(regEntry.Parents))

	// Register in local registry
	c.registry.Register(&identity.Agent{
		PublicKey:   c.keyPair.Public,
		Platform:    platform,
		DisplayName: "Bootstrap Agent",
	})

	// Step 3: Create 4 permanent channels
	permChannels := channel.CreatePermanentChannels(c.channels)
	parents := [][32]byte{regEntry.Hash}

	for _, ch := range permChannels {
		chCreate := moltcbor.ChannelCreate{
			ChannelID:   ch.ID,
			Name:        ch.Name,
			Description: ch.Description,
			ChannelType: moltcbor.ChannelTypePermanent,
		}
		chPayload, err := moltcbor.Marshal(chCreate)
		if err != nil {
			return fmt.Errorf("marshal channel create: %w", err)
		}

		chEntry, err := dag.NewSignedEntry(moltcbor.EntryTypeChannelCreate, chPayload, c.keyPair, parents)
		if err != nil {
			return fmt.Errorf("create channel entry: %w", err)
		}

		if err := c.dagState.Insert(chEntry); err != nil {
			return fmt.Errorf("insert channel entry: %w", err)
		}
		c.logDB.InsertEntry(chEntry.Hash[:], chEntry.RawCBOR, chEntry.AuthorKey, chEntry.Signature,
			int(moltcbor.EntryTypeChannelCreate), chEntry.CreatedAt, hashesToSlices(chEntry.Parents))

		// Auto-join bootstrapping agent
		ch.AddMember(c.keyPair.Public)
		parents = [][32]byte{chEntry.Hash}
	}

	// Step 4: Post introduction in #introductions
	introChannel := c.channels.Get(permChannels[1].ID) // #introductions
	if introChannel != nil {
		introMsg := moltcbor.Message{
			ChannelID:   introChannel.ID,
			Content:     []byte("Hello! I'm the first agent in this Moltwork workspace."),
			MessageType: 0, // discussion
		}
		introPayload, _ := moltcbor.Marshal(introMsg)
		introEntry, _ := dag.NewSignedEntry(moltcbor.EntryTypeMessage, introPayload, c.keyPair, parents)

		c.dagState.Insert(introEntry)
		c.logDB.InsertEntry(introEntry.Hash[:], introEntry.RawCBOR, introEntry.AuthorKey, introEntry.Signature,
			int(moltcbor.EntryTypeMessage), introEntry.CreatedAt, hashesToSlices(introEntry.Parents))
	}

	c.log.Info("workspace bootstrapped", map[string]any{
		"channels":  len(permChannels),
		"agent_key": fmt.Sprintf("%x", c.keyPair.Public[:8]),
	})

	return nil
}

func hashesToSlices(hashes [][32]byte) [][]byte {
	result := make([][]byte, len(hashes))
	for i, h := range hashes {
		b := make([]byte, 32)
		copy(b, h[:])
		result[i] = b
	}
	return result
}
