package license_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/soulteary/grantseal/internal/issuer"
	"github.com/soulteary/grantseal/pkg/license"
)

// memRollbackStore is not used directly; the on-disk RollbackStore is exercised
// with a temp file so the mutex/atomic CheckAndSave path is under test.

// fixedClock returns a Manager option pinning trusted time to t.
func fixedClockAt(t time.Time) license.Option {
	return license.WithClock(license.FixedClock{T: t})
}

// newTempRollbackStore builds a RollbackStore backed by a fresh temp file.
func newTempRollbackStore(t *testing.T) (*license.RollbackStore, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rollback.state")
	store, err := license.NewRollbackStore(path, []byte("regression-key"), 0)
	if err != nil {
		t.Fatalf("new rollback store: %v", err)
	}
	return store, path
}

// TestProductIDRequiredByManager asserts that Manager.Validate fails closed
// with CodeProductRequired when the caller does not scope validation to a
// product (empty ProductID). Historically an empty ProductID silently skipped
// the product check, which is an authorization-scoping footgun.
func TestProductIDRequiredByManager(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	data := issueBytes(t, s, baseRequest())
	mgr := license.NewManager(ringWith(t, "k1", pub))
	_, err := mgr.Validate(data, license.ValidationContext{}) // no ProductID
	if license.CodeOf(err) != license.CodeProductRequired {
		t.Fatalf("empty ProductID must be rejected with CodeProductRequired, got %s", license.CodeOf(err))
	}
}

// TestUnscopedProductValidationOptIn asserts that WithUnscopedProductValidation
// restores the legacy behavior (no product scoping required).
func TestUnscopedProductValidationOptIn(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	data := issueBytes(t, s, baseRequest())
	mgr := license.NewManager(ringWith(t, "k1", pub), license.WithUnscopedProductValidation())
	res, err := mgr.Validate(data, license.ValidationContext{})
	if err != nil || !res.Valid() {
		t.Fatalf("unscoped validation should pass, got err=%v valid=%v", err, res.Valid())
	}
}

// TestInvalidLicenseDoesNotAdvanceRollback asserts that a license failing
// policy validation (expired) never writes/advances the anti-rollback
// high-water mark. Advancing state on an invalid license would let an attacker
// bump the trusted clock forward using rejected input.
func TestInvalidLicenseDoesNotAdvanceRollback(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	now := time.Now().UTC()
	req := baseRequest()
	req.IssuedAt = ptr(now.Add(-96 * time.Hour))
	req.ExpiresAt = ptr(now.Add(-72 * time.Hour)) // expired, no grace
	req.GracePeriodDays = 0
	data := issueBytes(t, s, req)

	store, path := newTempRollbackStore(t)
	mgr := license.NewManager(ringWith(t, "k1", pub),
		fixedClockAt(now),
		license.WithRollbackStore(store),
		license.WithUnscopedProductValidation())
	_, err := mgr.Validate(data, license.ValidationContext{})
	if license.CodeOf(err) != license.CodeExpired {
		t.Fatalf("expected expired, got %s", license.CodeOf(err))
	}
	// The state file must NOT have been created for a rejected license.
	if _, statErr := os.Stat(path); statErr == nil {
		t.Fatalf("rollback state must not be written for an invalid license")
	}
}

// TestRollbackConcurrentHighWaterMark drives many goroutines validating the
// same license concurrently and asserts the persisted high-water mark equals
// the maximum trusted time observed, with no lost updates. This requires the
// store to serialize load->check->save atomically.
func TestRollbackConcurrentHighWaterMark(t *testing.T) {
	store, _ := newTempRollbackStore(t)
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	const n = 100
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			// Each goroutine advances time by i minutes.
			_ = store.CheckAndSave(base.Add(time.Duration(i) * time.Minute))
		}(i)
	}
	wg.Wait()

	prev, err := store.Load()
	if err != nil {
		t.Fatalf("load after concurrent saves: %v", err)
	}
	if prev == nil {
		t.Fatalf("expected persisted state after concurrent saves")
	}
	want := base.Add(time.Duration(n-1) * time.Minute)
	if !prev.LastTrustedTime.Equal(want) {
		t.Fatalf("high-water mark = %s, want %s", prev.LastTrustedTime, want)
	}
}

// TestNilOptionsDoNotPanic asserts that passing nil dependencies via the Manager
// options falls back to safe defaults rather than causing a later nil-dereference
// panic. WithClock(nil) retains the default clock, and nil rollback/revocation
// providers leave those features disabled. Validation must still succeed.
func TestNilOptionsDoNotPanic(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	data := issueBytes(t, s, baseRequest())
	mgr := license.NewManager(ringWith(t, "k1", pub),
		license.WithClock(nil),
		license.WithRollbackStore(nil),
		license.WithRevocation(nil),
		license.WithClockSkew(-1),
		license.WithUnscopedProductValidation())
	res, err := mgr.Validate(data, license.ValidationContext{})
	if err != nil || !res.Valid() {
		t.Fatalf("nil options should fall back to defaults, got err=%v valid=%v", err, res.Valid())
	}
}

// TestStrictJSONRejectsTrailingGarbage asserts the envelope parser rejects a
// second top-level JSON value or trailing junk after the envelope object.
func TestStrictJSONRejectsTrailingGarbage(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	_ = pub
	env, err := issuer.Issue(s, baseRequest())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	good, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	cases := map[string][]byte{
		"array-close": append(append([]byte{}, good...), ']'),
		"obj-close":   append(append([]byte{}, good...), '}'),
		"second-json": append(append([]byte{}, good...), []byte(`{"x":1}`)...),
		"number":      append(append([]byte{}, good...), []byte(" 123")...),
		"nul":         append(append([]byte{}, good...), 0x00),
		"garbage":     append(append([]byte{}, good...), []byte("garbage")...),
	}
	for name, data := range cases {
		if _, perr := license.ParseEnvelope(data); license.CodeOf(perr) != license.CodeMalformed {
			t.Fatalf("%s: expected CodeMalformed, got %s", name, license.CodeOf(perr))
		}
	}
}

// TestStrictJSONRejectsDuplicateKeys asserts the envelope parser rejects a JSON
// object with a duplicate key (a classic smuggling/ambiguity vector).
func TestStrictJSONRejectsDuplicateKeys(t *testing.T) {
	dup := []byte(`{"algorithm":"Ed25519","algorithm":"Ed25519","key_id":"k","payload":"AAAA","signature":"AAAA"}`)
	if _, err := license.ParseEnvelope(dup); license.CodeOf(err) != license.CodeMalformed {
		t.Fatalf("duplicate key must be rejected with CodeMalformed, got %s", license.CodeOf(err))
	}
}

// TestNonCanonicalPayloadRejected asserts that a validly-signed payload whose
// carried bytes are NOT canonical is rejected (defends against a signer that
// signs canonical bytes but ships different, semantically-equal bytes, or a
// tamperer re-ordering keys under a permissive verifier).
func TestNonCanonicalPayloadRejected(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	env, err := issuer.Issue(s, baseRequest())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Decode the canonical bytes, re-marshal with an added insignificant space
	// so the bytes differ from canonical while decoding to the same payload,
	// then re-sign those non-canonical bytes with the same key.
	canonical, err := base64.URLEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	// Reformat: prepend a leading space (still valid JSON, non-canonical).
	nonCanon := append([]byte(" "), canonical...)
	// Build an envelope carrying non-canonical bytes but validly signed over
	// them (with license domain separation) via an issuer helper. This proves
	// the rejection is specifically for non-canonicality, not a bad signature.
	sig := issuer.SignLicenseBytes(s, nonCanon)
	tampered := &license.Envelope{
		Algorithm: license.AlgorithmEd25519,
		KeyID:     env.KeyID,
		Payload:   base64.URLEncoding.EncodeToString(nonCanon),
		Signature: base64.URLEncoding.EncodeToString(sig),
	}
	data, err := json.Marshal(tampered)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	mgr := license.NewManager(ringWith(t, "k1", pub), license.WithUnscopedProductValidation())
	_, verr := mgr.Validate(data, license.ValidationContext{})
	code := license.CodeOf(verr)
	if code != license.CodeNonCanonicalPayload && code != license.CodeMalformed {
		t.Fatalf("non-canonical payload must be rejected, got %s", code)
	}
}

// TestKeyIssuanceWindowVerifiesAfterExpiry asserts issuance-window semantics: a
// license signed by a key while it was active still verifies AFTER the key's
// NotAfter has passed (verification checks the key window against the signed
// Payload.IssuedAt, not wall-clock now). A revoked key remains an immediate
// kill switch, and a license claiming issuance AFTER the key expired is
// rejected.
func TestKeyIssuanceWindowVerifiesAfterExpiry(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	now := time.Now().UTC()
	keyNotAfter := now.Add(-24 * time.Hour) // key expired a day ago

	// License legitimately issued 48h ago, before the key expired.
	req := baseRequest()
	issued := now.Add(-48 * time.Hour)
	req.IssuedAt = ptr(issued)
	req.ExpiresAt = ptr(now.Add(365 * 24 * time.Hour))
	data := issueBytes(t, s, req)

	ring := license.NewKeyRing()
	if err := ring.Add(license.KeyEntry{KeyID: "k1", PublicKey: pub, Enabled: true, NotAfter: &keyNotAfter}); err != nil {
		t.Fatalf("add key: %v", err)
	}
	mgr := license.NewManager(ring,
		license.WithUnscopedProductValidation(),
		license.WithClock(license.FixedClock{T: now}),
	)
	res, err := mgr.Validate(data, license.ValidationContext{})
	if err != nil || !res.Valid() {
		t.Fatalf("license signed while key active must still verify after key expiry: err=%v code=%s", err, res.Code())
	}

	// A revoked key rejects everything regardless of issuance time.
	ringRevoked := license.NewKeyRing()
	if err := ringRevoked.Add(license.KeyEntry{KeyID: "k1", PublicKey: pub, Enabled: true, Revoked: true, NotAfter: &keyNotAfter}); err != nil {
		t.Fatalf("add revoked key: %v", err)
	}
	mgrRevoked := license.NewManager(ringRevoked,
		license.WithUnscopedProductValidation(),
		license.WithClock(license.FixedClock{T: now}),
	)
	if _, rerr := mgrRevoked.Validate(data, license.ValidationContext{}); license.CodeOf(rerr) != license.CodeKeyRevoked {
		t.Fatalf("revoked key must reject: got %s", license.CodeOf(rerr))
	}
}

// TestKeyIssuanceWindowRejectsIssuanceAfterExpiry asserts that a license whose
// signed IssuedAt is after the key's NotAfter is rejected (a forger cannot
// backdate an issuance to slip past a since-expired key with a future issuance).
func TestKeyIssuanceWindowRejectsIssuanceAfterExpiry(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	now := time.Now().UTC()
	keyNotAfter := now.Add(-72 * time.Hour)

	req := baseRequest()
	issued := now.Add(-24 * time.Hour) // issued AFTER the key expired
	req.IssuedAt = ptr(issued)
	req.ExpiresAt = ptr(now.Add(365 * 24 * time.Hour))
	data := issueBytes(t, s, req)

	ring := license.NewKeyRing()
	if err := ring.Add(license.KeyEntry{KeyID: "k1", PublicKey: pub, Enabled: true, NotAfter: &keyNotAfter}); err != nil {
		t.Fatalf("add key: %v", err)
	}
	mgr := license.NewManager(ring,
		license.WithUnscopedProductValidation(),
		license.WithClock(license.FixedClock{T: now}),
	)
	if _, err := mgr.Validate(data, license.ValidationContext{}); license.CodeOf(err) != license.CodeKeyDisabled {
		t.Fatalf("issuance after key NotAfter must be rejected as CodeKeyDisabled, got %s", license.CodeOf(err))
	}
}

// TestRequireLimitEnforced asserts the opt-in RequireLimit policy: a license
// that does not declare a required limit key is rejected with CodeLimitRequired
// (closing the "missing key == unlimited" footgun for callers that opt in).
func TestRequireLimitEnforced(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	req := baseRequest()
	req.Limits = map[string]int64{"seats": 10}
	data := issueBytes(t, s, req)
	mgr := newTestManager(ringWith(t, "k1", pub))

	// Declared limit present: CheckLimitStrict enforces the cap.
	res, err := mgr.Validate(data, license.ValidationContext{})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if lerr := res.CheckLimitStrict("seats", 5); lerr != nil {
		t.Fatalf("within declared limit must pass: %v", lerr)
	}
	if lerr := res.CheckLimitStrict("seats", 20); license.CodeOf(lerr) != license.CodeLimitExceeded {
		t.Fatalf("over declared limit must be CodeLimitExceeded, got %s", license.CodeOf(lerr))
	}
	// Undeclared key under strict mode: CodeLimitRequired (not silently unlimited).
	if lerr := res.CheckLimitStrict("bandwidth", 1); license.CodeOf(lerr) != license.CodeLimitRequired {
		t.Fatalf("undeclared limit under strict mode must be CodeLimitRequired, got %s", license.CodeOf(lerr))
	}
}

// TestRequireLimitFailClosed exercises the fail-closed RequireLimit(key,
// current) helper's full error-code matrix: undeclared key, empty key, negative
// current, over-limit, and the happy path.
func TestRequireLimitFailClosed(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	req := baseRequest()
	req.Limits = map[string]int64{"seats": 10}
	data := issueBytes(t, s, req)
	mgr := newTestManager(ringWith(t, "k1", pub))
	res, err := mgr.Validate(data, license.ValidationContext{})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}

	if lerr := res.RequireLimit("seats", 5); lerr != nil {
		t.Fatalf("within declared limit must pass, got %v", lerr)
	}
	if lerr := res.RequireLimit("seats", 20); license.CodeOf(lerr) != license.CodeLimitExceeded {
		t.Fatalf("over limit must be CodeLimitExceeded, got %s", license.CodeOf(lerr))
	}
	if lerr := res.RequireLimit("seats", -1); license.CodeOf(lerr) != license.CodeInvalidLimits {
		t.Fatalf("negative current must be CodeInvalidLimits, got %s", license.CodeOf(lerr))
	}
	if lerr := res.RequireLimit("bandwidth", 1); license.CodeOf(lerr) != license.CodeLimitRequired {
		t.Fatalf("undeclared key must be CodeLimitRequired, got %s", license.CodeOf(lerr))
	}
	if lerr := res.RequireLimit("", 1); license.CodeOf(lerr) != license.CodeLimitRequired {
		t.Fatalf("empty key must be CodeLimitRequired, got %s", license.CodeOf(lerr))
	}
}
