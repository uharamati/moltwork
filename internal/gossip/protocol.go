package gossip

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/libp2p/go-libp2p/core/network"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/crypto"
	"moltwork/internal/logging"
	"moltwork/internal/store"
)

// AgentValidator checks if an agent is known and not revoked (rules C3, R2).
type AgentValidator interface {
	IsRegisteredAgent(pubKey []byte) bool
	IsRevoked(pubKey []byte) bool
	RegisterAgentKey(pubKey []byte)                                                             // mark a key as registered (lightweight)
	RegisterAgent(pubKey []byte, displayName, platform, platformUserID, title, team string) // register with full details
}

// SyncMessage types
const (
	MsgTypeHashSet  uint8 = 1 // "here are my entry hashes"
	MsgTypeRequest  uint8 = 2 // "send me these entries"
	MsgTypeEntries  uint8 = 3 // "here are the entries you asked for"
	MsgTypePSKProof uint8 = 4 // PSK authentication
	MsgTypeDone     uint8 = 5 // sync complete
)

// maxHashSetSize is the maximum number of hashes a peer can send in a hash set message.
// Prevents OOM from malicious peers sending unbounded hash lists.
const maxHashSetSize = 100_000

// HashSetMsg contains the set of entry hashes a node has.
type HashSetMsg struct {
	Hashes [][]byte `cbor:"1,keyasint"`
}

// RequestMsg asks for specific entries by hash.
type RequestMsg struct {
	Wanted [][]byte `cbor:"1,keyasint"`
}

// EntriesMsg contains raw entries being synced.
type EntriesMsg struct {
	Entries []RawSyncEntry `cbor:"1,keyasint"`
}

// RawSyncEntry is an entry as transmitted over the wire.
type RawSyncEntry struct {
	Hash      []byte   `cbor:"1,keyasint"`
	RawCBOR   []byte   `cbor:"2,keyasint"`
	AuthorKey []byte   `cbor:"3,keyasint"`
	Signature []byte   `cbor:"4,keyasint"`
	EntryType int      `cbor:"5,keyasint"`
	CreatedAt int64    `cbor:"6,keyasint"`
	Parents   [][]byte `cbor:"7,keyasint"`
}

// PSKProofMsg authenticates the peer using the pre-shared key (rule N3).
type PSKProofMsg struct {
	Challenge []byte `cbor:"1,keyasint"` // random bytes
	Proof     []byte `cbor:"2,keyasint"` // BLAKE3(PSK || challenge)
}

// writeMsg writes a typed message to the stream.
func writeMsg(s network.Stream, msgType uint8, payload []byte) error {
	// Format: [type (1 byte)] [length (4 bytes big-endian)] [payload]
	header := make([]byte, 5)
	header[0] = msgType
	binary.BigEndian.PutUint32(header[1:5], uint32(len(payload)))

	if _, err := s.Write(header); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	if _, err := s.Write(payload); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	return nil
}

// readMsg reads a typed message from the stream.
func readMsg(s network.Stream) (uint8, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(s, header); err != nil {
		return 0, nil, fmt.Errorf("read header: %w", err)
	}

	msgType := header[0]
	length := binary.BigEndian.Uint32(header[1:5])

	// Enforce max message size
	if length > 4*1024*1024 { // 4MB max for a sync batch
		return 0, nil, fmt.Errorf("message too large: %d", length)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(s, payload); err != nil {
		return 0, nil, fmt.Errorf("read payload: %w", err)
	}

	return msgType, payload, nil
}

// HandleIncomingSync handles an incoming sync stream from a peer.
func HandleIncomingSync(s network.Stream, logDB *store.LogDB, psk []byte, validator AgentValidator, log *logging.Logger) {
	defer s.Close()
	// Bound all reads/writes so a stalled peer can't hang this goroutine forever.
	s.SetDeadline(time.Now().Add(60 * time.Second))
	remotePeer := s.Conn().RemotePeer()

	// Step 1: PSK authentication (rule N3)
	if err := authenticateIncoming(s, psk); err != nil {
		log.Warn("PSK auth failed", map[string]any{"peer": remotePeer.String(), "error": err.Error()})
		return
	}

	// Step 2: Receive their hash set
	msgType, payload, err := readMsg(s)
	if err != nil || msgType != MsgTypeHashSet {
		log.Warn("expected hash set", map[string]any{"peer": remotePeer.String()})
		return
	}

	var theirHashes HashSetMsg
	if err := moltcbor.Unmarshal(payload, &theirHashes); err != nil {
		log.Warn("decode hash set", map[string]any{"peer": remotePeer.String(), "error": err.Error()})
		return
	}

	// Limit hash set size to prevent OOM from malicious peers
	if len(theirHashes.Hashes) > maxHashSetSize {
		log.Warn("peer sent oversized hash set", map[string]any{"peer": remotePeer.String(), "count": len(theirHashes.Hashes)})
		return
	}

	// Step 3: Send our hash set
	ourHashes, err := logDB.AllHashes()
	if err != nil {
		log.Error("get all hashes", map[string]any{"error": err.Error()})
		return
	}

	ourHashMsg := HashSetMsg{Hashes: ourHashes}
	ourHashBytes, err := moltcbor.Marshal(ourHashMsg)
	if err != nil {
		log.Error("marshal hash set", map[string]any{"error": err.Error()})
		return
	}
	if err := writeMsg(s, MsgTypeHashSet, ourHashBytes); err != nil {
		log.Warn("send hash set", map[string]any{"error": err.Error()})
		return
	}

	// Step 4: Compute what they need and send
	theirSet := hashSetToMap(theirHashes.Hashes)
	var toSend []RawSyncEntry
	for _, h := range ourHashes {
		hashArr := hashToArray(h)
		if !theirSet[hashArr] {
			entry, err := logDB.GetEntry(h)
			if err != nil || entry == nil {
				continue
			}
			toSend = append(toSend, RawSyncEntry{
				Hash:      entry.Hash,
				RawCBOR:   entry.RawCBOR,
				AuthorKey: entry.AuthorKey,
				Signature: entry.Signature,
				EntryType: entry.EntryType,
				CreatedAt: entry.CreatedAt,
				Parents:   entry.Parents,
			})
		}
	}

	// Compute what they need
	ourSet := hashSetToMap(ourHashes)
	theyNeed := len(toSend) > 0
	// Check if we need anything from them
	weNeed := false
	for _, h := range theirHashes.Hashes {
		if !ourSet[hashToArray(h)] {
			weNeed = true
			break
		}
	}

	// Fast path: if neither side has anything to exchange, close early
	// to avoid the i/o deadline noise that fires every sync cycle
	if !theyNeed && !weNeed {
		writeMsg(s, MsgTypeDone, nil)
		return
	}

	if theyNeed {
		entriesMsg := EntriesMsg{Entries: toSend}
		entriesBytes, err := moltcbor.Marshal(entriesMsg)
		if err != nil {
			log.Error("marshal entries", map[string]any{"error": err.Error()})
			return
		}
		if err := writeMsg(s, MsgTypeEntries, entriesBytes); err != nil {
			log.Warn("send entries", map[string]any{"error": err.Error()})
			return
		}
	}

	// Step 5: Receive what we need
	msgType, payload, err = readMsg(s)
	if err != nil {
		return
	}
	if msgType == MsgTypeEntries {
		var incoming EntriesMsg
		if err := moltcbor.Unmarshal(payload, &incoming); err != nil {
			log.Warn("decode entries", map[string]any{"error": err.Error()})
			return
		}
		StoreEntries(logDB, incoming.Entries, validator, log)
	}

	writeMsg(s, MsgTypeDone, nil)
}

// InitiateSync starts a sync with a remote peer.
func InitiateSync(s network.Stream, logDB *store.LogDB, psk []byte, validator AgentValidator, log *logging.Logger) error {
	defer s.Close()
	// Bound all reads/writes so a stalled peer can't hang the sync loop forever.
	s.SetDeadline(time.Now().Add(60 * time.Second))

	// Step 1: PSK authentication
	if err := authenticateOutgoing(s, psk); err != nil {
		return fmt.Errorf("PSK auth: %w", err)
	}

	// Step 2: Send our hash set
	ourHashes, err := logDB.AllHashes()
	if err != nil {
		return fmt.Errorf("get hashes: %w", err)
	}

	hashMsg := HashSetMsg{Hashes: ourHashes}
	hashBytes, err := moltcbor.Marshal(hashMsg)
	if err != nil {
		return fmt.Errorf("marshal hash set: %w", err)
	}
	if err := writeMsg(s, MsgTypeHashSet, hashBytes); err != nil {
		return fmt.Errorf("send hash set: %w", err)
	}

	// Step 3: Receive their hash set
	msgType, payload, err := readMsg(s)
	if err != nil || msgType != MsgTypeHashSet {
		return fmt.Errorf("expected hash set from peer")
	}

	var theirHashes HashSetMsg
	if err := moltcbor.Unmarshal(payload, &theirHashes); err != nil {
		return fmt.Errorf("decode their hashes: %w", err)
	}

	// Limit hash set size to prevent OOM from malicious peers
	if len(theirHashes.Hashes) > maxHashSetSize {
		return fmt.Errorf("peer sent oversized hash set: %d entries", len(theirHashes.Hashes))
	}

	// Step 4: Compute what they need
	theirSet := hashSetToMap(theirHashes.Hashes)
	ourSet := hashSetToMap(ourHashes)
	var toSend []RawSyncEntry
	for _, h := range ourHashes {
		hashArr := hashToArray(h)
		if !theirSet[hashArr] {
			entry, err := logDB.GetEntry(h)
			if err != nil || entry == nil {
				continue
			}
			toSend = append(toSend, RawSyncEntry{
				Hash:      entry.Hash,
				RawCBOR:   entry.RawCBOR,
				AuthorKey: entry.AuthorKey,
				Signature: entry.Signature,
				EntryType: entry.EntryType,
				CreatedAt: entry.CreatedAt,
				Parents:   entry.Parents,
			})
		}
	}

	// Check if we need anything from them
	weNeed := false
	for _, h := range theirHashes.Hashes {
		if !ourSet[hashToArray(h)] {
			weNeed = true
			break
		}
	}
	theyNeed := len(toSend) > 0

	// Fast path: nothing to exchange
	if !theyNeed && !weNeed {
		writeMsg(s, MsgTypeDone, nil)
		return nil
	}

	// Step 5: Receive entries they're sending us
	msgType, payload, err = readMsg(s)
	if err != nil {
		return fmt.Errorf("read entries: %w", err)
	}
	if msgType == MsgTypeEntries {
		var incoming EntriesMsg
		if err := moltcbor.Unmarshal(payload, &incoming); err != nil {
			return fmt.Errorf("decode entries: %w", err)
		}
		StoreEntries(logDB, incoming.Entries, validator, log)
	}

	// Step 6: Send entries they need
	if theyNeed {
		entriesMsg := EntriesMsg{Entries: toSend}
		entriesBytes, err := moltcbor.Marshal(entriesMsg)
		if err != nil {
			return fmt.Errorf("marshal entries: %w", err)
		}
		if err := writeMsg(s, MsgTypeEntries, entriesBytes); err != nil {
			return fmt.Errorf("send entries: %w", err)
		}
	}

	writeMsg(s, MsgTypeDone, nil)
	return nil
}

// isZeroPSK checks if the PSK is all zeros (placeholder before real PSK is set).
func isZeroPSK(psk []byte) bool {
	for _, b := range psk {
		if b != 0 {
			return false
		}
	}
	return true
}

// sessionBinding computes a deterministic session ID from both peer IDs.
// Both sides derive the same value regardless of who initiated.
func sessionBinding(s network.Stream) []byte {
	local := []byte(s.Conn().LocalPeer().String())
	remote := []byte(s.Conn().RemotePeer().String())
	// Deterministic order: smaller peer ID first
	if string(local) > string(remote) {
		local, remote = remote, local
	}
	combined := append(local, remote...)
	h := crypto.Hash(combined)
	return h[:]
}

// authenticateOutgoing sends PSK proof as initiator.
// Proof includes session binding via both peer IDs to prevent cross-session replay.
func authenticateOutgoing(s network.Stream, psk []byte) error {
	if len(psk) == 0 || isZeroPSK(psk) {
		return fmt.Errorf("cannot authenticate with zero-valued PSK")
	}
	challenge := crypto.RandomBytes(32)
	binding := sessionBinding(s)
	proofInput := append(psk, challenge...)
	proofInput = append(proofInput, binding...)
	proof := crypto.Hash(proofInput)

	msg := PSKProofMsg{Challenge: challenge, Proof: proof[:]}
	data, err := moltcbor.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal PSK proof: %w", err)
	}
	if err := writeMsg(s, MsgTypePSKProof, data); err != nil {
		return err
	}

	// Read peer's proof
	msgType, payload, err := readMsg(s)
	if err != nil || msgType != MsgTypePSKProof {
		return fmt.Errorf("expected PSK proof from peer")
	}

	var peerProof PSKProofMsg
	if err := moltcbor.Unmarshal(payload, &peerProof); err != nil {
		return fmt.Errorf("decode PSK proof: %w", err)
	}

	// Verify with same session binding
	verifyInput := append(psk, peerProof.Challenge...)
	verifyInput = append(verifyInput, binding...)
	expected := crypto.Hash(verifyInput)
	if !crypto.ConstantTimeEqual(expected[:], peerProof.Proof) {
		return fmt.Errorf("PSK proof verification failed")
	}

	return nil
}

// authenticateIncoming handles PSK proof as responder.
// Proof includes session binding via both peer IDs to prevent cross-session replay.
func authenticateIncoming(s network.Stream, psk []byte) error {
	if len(psk) == 0 || isZeroPSK(psk) {
		return fmt.Errorf("cannot authenticate with zero-valued PSK")
	}
	// Read initiator's proof
	msgType, payload, err := readMsg(s)
	if err != nil || msgType != MsgTypePSKProof {
		return fmt.Errorf("expected PSK proof from initiator")
	}

	var peerProof PSKProofMsg
	if err := moltcbor.Unmarshal(payload, &peerProof); err != nil {
		return fmt.Errorf("decode PSK proof: %w", err)
	}

	// Verify with session binding
	binding := sessionBinding(s)
	verifyInput := append(psk, peerProof.Challenge...)
	verifyInput = append(verifyInput, binding...)
	expected := crypto.Hash(verifyInput)
	if !crypto.ConstantTimeEqual(expected[:], peerProof.Proof) {
		return fmt.Errorf("PSK proof verification failed")
	}

	// Send our proof with session binding
	challenge := crypto.RandomBytes(32)
	proofInput := append(psk, challenge...)
	proofInput = append(proofInput, binding...)
	proof := crypto.Hash(proofInput)
	msg := PSKProofMsg{Challenge: challenge, Proof: proof[:]}
	data, err := moltcbor.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal PSK proof: %w", err)
	}
	return writeMsg(s, MsgTypePSKProof, data)
}

// StoreEntries validates and stores received entries.
// Entries are sorted so revocations are processed first (rule R1).
func StoreEntries(logDB *store.LogDB, entries []RawSyncEntry, validator AgentValidator, log *logging.Logger) {
	// Sort revocation entries to front (rule R1)
	sortRevocationsFirst(entries)

	for _, e := range entries {
		// Validate entry size (rule N4, S5)
		if len(e.RawCBOR) > store.MaxEntrySize {
			log.Warn("entry too large, skipping", map[string]any{"size": len(e.RawCBOR)})
			continue
		}

		// Verify hash matches content (rule N4)
		expectedHash := crypto.HashMulti(e.RawCBOR, e.Signature)
		if !crypto.ConstantTimeEqual(expectedHash[:], e.Hash) {
			log.Warn("hash mismatch, skipping entry")
			continue
		}

		// Verify signature (rule C2: verify before anything else)
		if err := crypto.Verify(e.AuthorKey, e.RawCBOR, e.Signature); err != nil {
			log.Warn("invalid signature, skipping entry")
			continue
		}

		// Decode envelope to check version and entry type (rules C3, N4, B4)
		var sigData struct {
			Parents  [][]byte `cbor:"1,keyasint"`
			Envelope []byte   `cbor:"2,keyasint"`
			Time     int64    `cbor:"3,keyasint"`
		}
		if err := moltcbor.Unmarshal(e.RawCBOR, &sigData); err != nil {
			log.Warn("decode signable wrapper failed, skipping entry", map[string]any{"error": err.Error()})
			continue
		}

		var env moltcbor.Envelope
		if err := moltcbor.Unmarshal(sigData.Envelope, &env); err != nil {
			log.Warn("decode envelope failed, skipping entry", map[string]any{"error": err.Error()})
			continue
		}

		// Check protocol version (rule B4)
		if env.Version != moltcbor.ProtocolVersion {
			log.Warn("unsupported protocol version, skipping entry", map[string]any{
				"version":  env.Version,
				"expected": moltcbor.ProtocolVersion,
			})
			continue
		}

		// Check author is not revoked (rule R2).
		// Registration check (rule C3) is NOT enforced during gossip sync —
		// entries are already signature-verified (Ed25519), which proves the
		// author has the private key. The registration check caused entries
		// to be silently dropped when the registration arrived in a different
		// sync cycle than the messages, leaving the in-memory validator stale.
		if validator != nil && validator.IsRevoked(e.AuthorKey) {
			log.Warn("entry from revoked agent, skipping", map[string]any{
				"entry_type": env.Type,
			})
			continue
		}

		// Store
		if err := logDB.InsertEntry(e.Hash, e.RawCBOR, e.AuthorKey, e.Signature, e.EntryType, e.CreatedAt, e.Parents); err != nil {
			log.Warn("store entry failed", map[string]any{"error": err.Error()})
			continue
		}

		// After storing a registration entry, update the validator with full agent details.
		if env.Type == moltcbor.EntryTypeAgentRegistration && validator != nil {
			var reg moltcbor.AgentRegistration
			if err := moltcbor.Unmarshal(env.Payload, &reg); err == nil {
				validator.RegisterAgent(reg.PublicKey, reg.DisplayName, reg.Platform, reg.PlatformUserID, reg.Title, reg.Team)
			} else {
				validator.RegisterAgentKey(e.AuthorKey)
			}
		}
	}
}

// sortRevocationsFirst reorders entries so revocation entries come first (rule R1),
// then trust boundary and registration entries come next (so the registry is
// populated before other entries are validated).
func sortRevocationsFirst(entries []RawSyncEntry) {
	i := 0
	// Pass 1: revocations to front
	for j := range entries {
		if entries[j].EntryType == int(moltcbor.EntryTypeRevocation) {
			entries[i], entries[j] = entries[j], entries[i]
			i++
		}
	}
	// Pass 2: trust boundary and registrations right after revocations
	k := i
	for j := k; j < len(entries); j++ {
		t := entries[j].EntryType
		if t == int(moltcbor.EntryTypeTrustBoundary) || t == int(moltcbor.EntryTypeAgentRegistration) {
			entries[k], entries[j] = entries[j], entries[k]
			k++
		}
	}
}

func hashSetToMap(hashes [][]byte) map[[32]byte]bool {
	m := make(map[[32]byte]bool, len(hashes))
	for _, h := range hashes {
		m[hashToArray(h)] = true
	}
	return m
}

func hashToArray(b []byte) [32]byte {
	var arr [32]byte
	copy(arr[:], b)
	return arr
}
