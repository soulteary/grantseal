package license_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/soulteary/grantseal/internal/issuer"
	"github.com/soulteary/grantseal/pkg/license"
)

// TestRevocationReplayRejectsOlderSequence asserts that once a revocation list
// with sequence=100 has been accepted and recorded in a high-water state store,
// a validly-signed but OLDER list (sequence=99) is rejected as a rollback/stale
// distribution (replay resistance). This exercises the v2 revocation protocol.
func TestRevocationReplayRejectsOlderSequence(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", pub)
	now := time.Now().UTC()

	stateStore := license.NewMemRevocationStateStore()
	pol := license.RevocationPolicy{StateStore: stateStore}

	// Build + accept sequence=100 first.
	newList := func(seq uint64) []byte {
		env, err := issuer.BuildRevocationListV2(s, issuer.RevocationListOptions{
			ListID:     "list-seq",
			Sequence:   seq,
			IssuedAt:   now,
			ExpiresAt:  now.Add(30 * 24 * time.Hour),
			RevokedIDs: []string{"lic_x"},
		})
		if err != nil {
			t.Fatalf("build revocation seq=%d: %v", seq, err)
		}
		data, err := json.Marshal(env)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return data
	}

	if _, err := license.LoadRevocationListWithPolicy(ring, newList(100), now, pol); err != nil {
		t.Fatalf("accept seq=100: %v", err)
	}
	// Now a strictly older sequence must be rejected as stale/replay.
	_, err := license.LoadRevocationListWithPolicy(ring, newList(99), now, pol)
	if license.CodeOf(err) != license.CodeRevocationStale {
		t.Fatalf("older sequence must be rejected as stale, got %s", license.CodeOf(err))
	}
}

// TestRevocationV1RejectedByDefault asserts that a legacy v1 revocation list is
// rejected by default and only accepted when AllowLegacyV1Revocation is set.
func TestRevocationV1RejectedByDefault(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", pub)
	now := time.Now().UTC()

	v1env, err := issuer.BuildRevocationList(s, []string{"lic_x"}) //nolint:staticcheck // legacy v1
	if err != nil {
		t.Fatalf("build v1 revocation: %v", err)
	}
	data, err := json.Marshal(v1env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Default: v1 rejected.
	if _, derr := license.LoadRevocationList(ring, data, now); license.CodeOf(derr) != license.CodeUnsupportedSchema {
		t.Fatalf("v1 must be rejected by default, got %s", license.CodeOf(derr))
	}
	// Opt-in: v1 accepted.
	rp, aerr := license.LoadRevocationListWithPolicy(ring, data, now, license.RevocationPolicy{AllowLegacyV1: true})
	if aerr != nil {
		t.Fatalf("v1 with opt-in should load: %v", aerr)
	}
	if !rp.IsRevoked("lic_x") {
		t.Fatalf("v1 opt-in list should report lic_x revoked")
	}
}

// revV2 builds a v2 revocation list envelope with the given fields. It supplies
// a non-empty default ListID (required by the v2 static invariants); tests that
// need a specific list identity build the options directly.
func revV2(t *testing.T, s *issuer.Signer, seq uint64, issued, expires time.Time, ids ...string) []byte {
	t.Helper()
	env, err := issuer.BuildRevocationListV2(s, issuer.RevocationListOptions{
		ListID:     "list-test",
		Sequence:   seq,
		IssuedAt:   issued,
		ExpiresAt:  expires,
		RevokedIDs: ids,
	})
	if err != nil {
		t.Fatalf("build v2 revocation: %v", err)
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

// TestRevocationFromFutureRejected asserts an issued_at beyond tolerated skew is
// rejected as CodeRevocationFromFuture.
func TestRevocationFromFutureRejected(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", pub)
	now := time.Now().UTC()
	// issued far in the future relative to `now`.
	data := revV2(t, s, 1, now.Add(48*time.Hour), now.Add(72*time.Hour), "lic_x")
	pol := license.RevocationPolicy{ClockSkew: time.Minute}
	if _, err := license.LoadRevocationListWithPolicy(ring, data, now, pol); license.CodeOf(err) != license.CodeRevocationFromFuture {
		t.Fatalf("future issued_at must be rejected, got %s", license.CodeOf(err))
	}
}

// TestRevocationExpiredRejected asserts a list past its expires_at (beyond skew)
// is rejected as CodeRevocationExpired.
func TestRevocationExpiredRejected(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", pub)
	now := time.Now().UTC()
	data := revV2(t, s, 1, now.Add(-72*time.Hour), now.Add(-48*time.Hour), "lic_x")
	pol := license.RevocationPolicy{ClockSkew: time.Minute}
	if _, err := license.LoadRevocationListWithPolicy(ring, data, now, pol); license.CodeOf(err) != license.CodeRevocationExpired {
		t.Fatalf("expired list must be rejected, got %s", license.CodeOf(err))
	}
}

// TestRevocationSameSequenceDifferentContentRejected asserts that reusing an
// already-accepted sequence with different content is rejected as
// CodeRevocationRollback, while re-presenting the identical list is idempotent.
func TestRevocationSameSequenceDifferentContentRejected(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", pub)
	now := time.Now().UTC()
	store := license.NewMemRevocationStateStore()
	pol := license.RevocationPolicy{StateStore: store}

	first := revV2(t, s, 5, now, now.Add(30*24*time.Hour), "lic_a")
	if _, err := license.LoadRevocationListWithPolicy(ring, first, now, pol); err != nil {
		t.Fatalf("accept seq=5: %v", err)
	}
	// Same sequence, identical content: idempotent re-acceptance.
	if _, err := license.LoadRevocationListWithPolicy(ring, first, now, pol); err != nil {
		t.Fatalf("re-accept identical seq=5: %v", err)
	}
	// Same sequence, DIFFERENT content: rollback attempt.
	conflict := revV2(t, s, 5, now, now.Add(30*24*time.Hour), "lic_b")
	if _, err := license.LoadRevocationListWithPolicy(ring, conflict, now, pol); license.CodeOf(err) != license.CodeRevocationRollback {
		t.Fatalf("same-seq different-content must be rejected, got %s", license.CodeOf(err))
	}
}

// TestRevocationHigherSequenceAccepted asserts a strictly higher sequence is
// accepted and advances the high-water mark.
func TestRevocationHigherSequenceAccepted(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", pub)
	now := time.Now().UTC()
	store := license.NewMemRevocationStateStore()
	pol := license.RevocationPolicy{StateStore: store}

	if _, err := license.LoadRevocationListWithPolicy(ring, revV2(t, s, 10, now, now.Add(24*time.Hour), "lic_a"), now, pol); err != nil {
		t.Fatalf("accept seq=10: %v", err)
	}
	rp, err := license.LoadRevocationListWithPolicy(ring, revV2(t, s, 11, now, now.Add(24*time.Hour), "lic_a", "lic_b"), now, pol)
	if err != nil {
		t.Fatalf("accept seq=11: %v", err)
	}
	if !rp.IsRevoked("lic_b") {
		t.Fatalf("seq=11 list should revoke lic_b")
	}
}

// TestFileRevocationStateStoreIntegrity asserts the file-backed state store
// fails closed with CodeRevocationStateIntegrityFailure when its contents are
// tampered.
func TestFileRevocationStateStoreIntegrity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "revstate.json")
	store, err := license.NewFileRevocationStateStore(path, []byte("k"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := store.SaveRevocationState(&license.RevocationState{ListID: "l", Sequence: 3, IssuedAt: time.Now().UTC(), PayloadDigest: "deadbeef"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	// Tamper the file on disk.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	tampered := append([]byte(nil), raw...)
	// Corrupt a byte in the middle to break the MAC without breaking JSON shape
	// badly enough to change the error class.
	if len(tampered) > 10 {
		tampered[len(tampered)/2] ^= 0xFF
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, lerr := store.LoadRevocationState("l"); license.CodeOf(lerr) != license.CodeRevocationStateIntegrityFailure {
		t.Fatalf("tampered state must fail closed, got %s", license.CodeOf(lerr))
	}
}

// TestFileRevocationStateStoreRoundTrip covers the happy path of the file-backed
// state store: a missing file reads as no-state, a saved entry round-trips, and
// an unrelated list_id reads as no-state. It also verifies the store drives the
// end-to-end replay check via LoadRevocationListWithPolicy across a fresh store
// instance pointed at the same file (persistence across process restarts).
func TestFileRevocationStateStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "revstate.json")
	store, err := license.NewFileRevocationStateStore(path, []byte("hmac-key"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	// Missing file -> no state.
	if st, lerr := store.LoadRevocationState("l"); lerr != nil || st != nil {
		t.Fatalf("missing file should be (nil,nil), got st=%v err=%v", st, lerr)
	}

	s, pub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", pub)
	now := time.Now().UTC()
	pol := license.RevocationPolicy{StateStore: store}

	if _, err := license.LoadRevocationListWithPolicy(ring, revV2(t, s, 7, now, now.Add(24*time.Hour), "lic_a"), now, pol); err != nil {
		t.Fatalf("accept seq=7: %v", err)
	}
	// A brand-new store instance over the same file must see the persisted mark
	// and reject an older sequence.
	store2, err := license.NewFileRevocationStateStore(path, []byte("hmac-key"))
	if err != nil {
		t.Fatalf("new store2: %v", err)
	}
	pol2 := license.RevocationPolicy{StateStore: store2}
	if _, lerr := license.LoadRevocationListWithPolicy(ring, revV2(t, s, 6, now, now.Add(24*time.Hour), "lic_a"), now, pol2); license.CodeOf(lerr) != license.CodeRevocationStale {
		t.Fatalf("older sequence across restart must be stale, got %s", license.CodeOf(lerr))
	}
	// Unknown list_id reads as no-state.
	if st, lerr := store2.LoadRevocationState("does-not-exist"); lerr != nil || st != nil {
		t.Fatalf("unknown list_id should be (nil,nil), got st=%v err=%v", st, lerr)
	}
}
