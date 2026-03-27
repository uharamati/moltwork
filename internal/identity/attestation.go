package identity

import (
	"context"
	"sync"
	"time"

	moltcbor "moltwork/internal/cbor"
	"moltwork/internal/crypto"
	"moltwork/internal/dag"
	"moltwork/internal/logging"
	"moltwork/internal/store"
)

// AttestationLoop periodically re-verifies platform token and publishes attestation entries (rule P3).
type AttestationLoop struct {
	verifier PlatformVerifier
	token    string
	keyPair  *crypto.SigningKeyPair
	logDB    *store.LogDB
	dagState *dag.DAG
	log      *logging.Logger
	interval time.Duration

	mu              sync.RWMutex
	lastVerified    time.Time
	lastValid       bool
	consecutiveFail int
}

// NewAttestationLoop creates an attestation loop.
func NewAttestationLoop(
	verifier PlatformVerifier,
	token string,
	keyPair *crypto.SigningKeyPair,
	logDB *store.LogDB,
	dagState *dag.DAG,
	log *logging.Logger,
	interval time.Duration,
) *AttestationLoop {
	return &AttestationLoop{
		verifier: verifier,
		token:    token,
		keyPair:  keyPair,
		logDB:    logDB,
		dagState: dagState,
		log:      log,
		interval: interval,
	}
}

// Run starts the attestation loop. Blocks until context is cancelled.
// Runs an immediate first attestation before entering the periodic loop.
func (al *AttestationLoop) Run(ctx context.Context) {
	// Immediate first attestation
	al.attest(ctx)

	ticker := time.NewTicker(al.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			al.attest(ctx)
		}
	}
}

func (al *AttestationLoop) attest(ctx context.Context) {
	// Exponential backoff on persistent failures: skip attestation if
	// we've failed recently and haven't waited long enough.
	al.mu.RLock()
	fails := al.consecutiveFail
	al.mu.RUnlock()
	if fails > 0 {
		backoff := time.Duration(1<<min(fails, 6)) * time.Minute // 1m, 2m, 4m, 8m, 16m, 32m, 64m cap
		if time.Since(al.lastVerified) < backoff {
			return
		}
	}

	identity, err := al.verifier.Verify(ctx, al.token)
	now := time.Now()

	al.mu.Lock()
	al.lastVerified = now
	al.lastValid = err == nil
	if err != nil {
		al.consecutiveFail++
	} else {
		al.consecutiveFail = 0
	}
	al.mu.Unlock()

	if err != nil {
		al.log.Warn("attestation failed, publishing token-invalid status", map[string]any{
			"error":       err.Error(),
			"fail_streak": al.consecutiveFail,
		})
		al.publishTokenStatus(false, err.Error())
		return
	}

	al.publishAttestation(identity)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// LastVerified returns the time and result of the last verification attempt.
func (al *AttestationLoop) LastVerified() (time.Time, bool) {
	al.mu.RLock()
	defer al.mu.RUnlock()
	return al.lastVerified, al.lastValid
}

func (al *AttestationLoop) publishAttestation(identity *PlatformIdentity) {
	att := moltcbor.Attestation{
		Platform:        identity.Platform,
		WorkspaceDomain: identity.WorkspaceDomain,
		PlatformUserID:  identity.UserID,
		Timestamp:       time.Now().Unix(),
	}

	payload, err := moltcbor.Marshal(att)
	if err != nil {
		al.log.Error("marshal attestation", map[string]any{"error": err.Error()})
		return
	}

	tips := al.dagState.Tips()
	entry, err := dag.NewSignedEntry(moltcbor.EntryTypeAttestation, payload, al.keyPair, tips)
	if err != nil {
		al.log.Error("create attestation entry", map[string]any{"error": err.Error()})
		return
	}

	if err := al.dagState.Insert(entry); err != nil {
		al.log.Error("insert attestation", map[string]any{"error": err.Error()})
		return
	}

	al.logDB.InsertEntry(entry.Hash[:], entry.RawCBOR, entry.AuthorKey, entry.Signature,
		int(moltcbor.EntryTypeAttestation), entry.CreatedAt, hashesToSlices(entry.Parents))

	al.log.Info("attestation published")
}

func (al *AttestationLoop) publishTokenStatus(valid bool, message string) {
	status := moltcbor.TokenStatus{
		Valid:    valid,
		Platform: al.verifier.Platform(),
		Message:  message,
	}

	payload, err := moltcbor.Marshal(status)
	if err != nil {
		return
	}

	tips := al.dagState.Tips()
	entry, err := dag.NewSignedEntry(moltcbor.EntryTypeTokenStatus, payload, al.keyPair, tips)
	if err != nil {
		return
	}

	al.dagState.Insert(entry)
	al.logDB.InsertEntry(entry.Hash[:], entry.RawCBOR, entry.AuthorKey, entry.Signature,
		int(moltcbor.EntryTypeTokenStatus), entry.CreatedAt, hashesToSlices(entry.Parents))
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
