package license_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/soulteary/grantseal/internal/issuer"
	"github.com/soulteary/grantseal/pkg/license"
)

// ---------------------------------------------------------------------------
// Envelope parsing edge cases
// ---------------------------------------------------------------------------

func TestParseEnvelopeEmpty(t *testing.T) {
	if _, err := license.ParseEnvelope(nil); license.CodeOf(err) != license.CodeMalformed {
		t.Fatalf("empty: want CodeMalformed, got %s", license.CodeOf(err))
	}
}

func TestParseEnvelopeUnknownField(t *testing.T) {
	data := []byte(`{"algorithm":"Ed25519","key_id":"k","payload":"AAAA","signature":"AAAA","extra":"x"}`)
	if _, err := license.ParseEnvelope(data); license.CodeOf(err) != license.CodeMalformed {
		t.Fatalf("unknown field must be rejected, got %s", license.CodeOf(err))
	}
}

func TestParseEnvelopeTrailingData(t *testing.T) {
	data := []byte(`{"algorithm":"Ed25519","key_id":"k","payload":"AAAA","signature":"AAAA"} trailing`)
	if _, err := license.ParseEnvelope(data); license.CodeOf(err) != license.CodeMalformed {
		t.Fatalf("trailing data must be rejected, got %s", license.CodeOf(err))
	}
}

func TestParseEnvelopeDuplicateKey(t *testing.T) {
	// Strict parsing rejects duplicate object keys rather than silently keeping
	// the last value, so ambiguous envelopes cannot be smuggled past verifiers.
	data := []byte(`{"algorithm":"Ed25519","key_id":"k1","key_id":"k2","payload":"AAAA","signature":"AAAA"}`)
	if _, err := license.ParseEnvelope(data); license.CodeOf(err) != license.CodeMalformed {
		t.Fatalf("duplicate key must be rejected, got %s", license.CodeOf(err))
	}
}

func TestParseEnvelopeMissingFields(t *testing.T) {
	cases := []string{
		`{"algorithm":"","key_id":"k","payload":"AAAA","signature":"AAAA"}`,
		`{"algorithm":"Ed25519","key_id":"","payload":"AAAA","signature":"AAAA"}`,
		`{"algorithm":"Ed25519","key_id":"k","payload":"","signature":"AAAA"}`,
		`{"algorithm":"Ed25519","key_id":"k","payload":"AAAA","signature":""}`,
	}
	for i, c := range cases {
		if _, err := license.ParseEnvelope([]byte(c)); license.CodeOf(err) != license.CodeMalformed {
			t.Fatalf("case %d: want CodeMalformed, got %s", i, license.CodeOf(err))
		}
	}
}

func TestDecodeSignatureBadBase64(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	data := issueBytes(t, s, baseRequest())
	var env license.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	env.Signature = "!!!not-base64!!!"
	mut, _ := json.Marshal(env)
	mgr := newTestManager(ringWith(t, "k1", pub))
	if _, err := mgr.Validate(mut, license.ValidationContext{}); license.CodeOf(err) != license.CodeMalformed {
		t.Fatalf("bad signature base64: want CodeMalformed, got %s", license.CodeOf(err))
	}
}

// ---------------------------------------------------------------------------
// KeyRing edge cases
// ---------------------------------------------------------------------------

func TestKeyRingAddRejectsBadKeySize(t *testing.T) {
	ring := license.NewKeyRing()
	err := ring.Add(license.KeyEntry{KeyID: "k", PublicKey: ed25519.PublicKey([]byte("too-short")), Enabled: true})
	if license.CodeOf(err) != license.CodeMalformed {
		t.Fatalf("short key: want CodeMalformed, got %s", license.CodeOf(err))
	}
}

func TestKeyRingAddRejectsEmptyKeyID(t *testing.T) {
	_, pub := testKeyPair(t, "k1")
	ring := license.NewKeyRing()
	if err := ring.Add(license.KeyEntry{KeyID: "", PublicKey: pub, Enabled: true}); license.CodeOf(err) != license.CodeMalformed {
		t.Fatalf("empty key id: want CodeMalformed, got %s", license.CodeOf(err))
	}
}

func TestKeyRingLookupUnknown(t *testing.T) {
	ring := license.NewKeyRing()
	if _, err := ring.Lookup("nope", time.Now().UTC()); license.CodeOf(err) != license.CodeKeyUnknown {
		t.Fatalf("unknown key: want CodeKeyUnknown, got %s", license.CodeOf(err))
	}
}

func TestKeyRingLookupRevokedBeforeDisabled(t *testing.T) {
	_, pub := testKeyPair(t, "k1")
	ring := license.NewKeyRing()
	// Both revoked and disabled: revoked takes precedence in the error code.
	if err := ring.Add(license.KeyEntry{KeyID: "k1", PublicKey: pub, Enabled: false, Revoked: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Lookup("k1", time.Now().UTC()); license.CodeOf(err) != license.CodeKeyRevoked {
		t.Fatalf("revoked+disabled: want CodeKeyRevoked, got %s", license.CodeOf(err))
	}
}

func TestKeyRingLookupTimeWindow(t *testing.T) {
	_, pub := testKeyPair(t, "k1")
	now := time.Now().UTC()
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)

	ring := license.NewKeyRing()
	if err := ring.Add(license.KeyEntry{KeyID: "future", PublicKey: pub, Enabled: true, NotBefore: &future}); err != nil {
		t.Fatal(err)
	}
	if err := ring.Add(license.KeyEntry{KeyID: "expired", PublicKey: pub, Enabled: true, NotAfter: &past}); err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Lookup("future", now); license.CodeOf(err) != license.CodeKeyDisabled {
		t.Fatalf("not-yet-active: want CodeKeyDisabled, got %s", license.CodeOf(err))
	}
	if _, err := ring.Lookup("expired", now); license.CodeOf(err) != license.CodeKeyDisabled {
		t.Fatalf("past-window: want CodeKeyDisabled, got %s", license.CodeOf(err))
	}
}

func TestKeyRingKeyIDsSorted(t *testing.T) {
	_, pub := testKeyPair(t, "k")
	ring := license.NewKeyRing()
	for _, id := range []string{"c", "a", "b"} {
		if err := ring.AddPublicKey(id, pub); err != nil {
			t.Fatal(err)
		}
	}
	ids := ring.KeyIDs()
	if strings.Join(ids, ",") != "a,b,c" {
		t.Fatalf("KeyIDs not sorted: %v", ids)
	}
}

// ---------------------------------------------------------------------------
// Rollback state edge cases
// ---------------------------------------------------------------------------

func TestRollbackStoreRejectsEmptyPathAndKey(t *testing.T) {
	if _, err := license.NewRollbackStore("", []byte("k"), 0); license.CodeOf(err) != license.CodeStateIntegrityFailure {
		t.Fatalf("empty path: want CodeStateIntegrityFailure, got %s", license.CodeOf(err))
	}
	if _, err := license.NewRollbackStore("p", nil, 0); license.CodeOf(err) != license.CodeStateIntegrityFailure {
		t.Fatalf("empty key: want CodeStateIntegrityFailure, got %s", license.CodeOf(err))
	}
}

func TestRollbackStoreLoadMissingIsNoPriorState(t *testing.T) {
	store := mustStore(t, filepath.Join(t.TempDir(), "rollback.state"), []byte("key"))
	st, err := store.Load()
	if err != nil {
		t.Fatalf("missing file should not error, got %v", err)
	}
	if st != nil {
		t.Fatalf("missing file should return nil state, got %+v", st)
	}
}

func TestRollbackStoreLoadTruncatedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollback.state")
	if err := os.WriteFile(path, []byte(`{"last_trusted_time":`), 0o600); err != nil {
		t.Fatal(err)
	}
	store := mustStore(t, path, []byte("key"))
	if _, err := store.Load(); license.CodeOf(err) != license.CodeStateIntegrityFailure {
		t.Fatalf("truncated state: want CodeStateIntegrityFailure, got %s", license.CodeOf(err))
	}
}

func TestRollbackStoreLoadUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollback.state")
	if err := os.WriteFile(path, []byte(`{"last_trusted_time":"2024-01-01T00:00:00Z","last_verified_at":"2024-01-01T00:00:00Z","mac":"00","surprise":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	store := mustStore(t, path, []byte("key"))
	if _, err := store.Load(); license.CodeOf(err) != license.CodeStateIntegrityFailure {
		t.Fatalf("unknown field: want CodeStateIntegrityFailure, got %s", license.CodeOf(err))
	}
}

func TestRollbackStoreLoadOversized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollback.state")
	big := make([]byte, license.MaxRollbackStateSize+1)
	for i := range big {
		big[i] = 'x'
	}
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatal(err)
	}
	store := mustStore(t, path, []byte("key"))
	if _, err := store.Load(); license.CodeOf(err) != license.CodeStateIntegrityFailure {
		t.Fatalf("oversized state: want CodeStateIntegrityFailure, got %s", license.CodeOf(err))
	}
}

func TestRollbackStoreSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollback.state")
	store := mustStore(t, path, []byte("key"))
	now := time.Now().UTC().Truncate(time.Second)
	next, err := store.CheckRollback(nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(next); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("load after save: %v", err)
	}
	if !loaded.LastTrustedTime.Equal(now) {
		t.Fatalf("round-trip time mismatch: %v != %v", loaded.LastTrustedTime, now)
	}
}

func TestRollbackStoreDifferentKeyFailsIntegrity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollback.state")
	saver := mustStore(t, path, []byte("key-A"))
	st, _ := saver.CheckRollback(nil, time.Now().UTC())
	if err := saver.Save(st); err != nil {
		t.Fatal(err)
	}
	// A store with a different HMAC key must reject the state.
	other := mustStore(t, path, []byte("key-B"))
	if _, err := other.Load(); license.CodeOf(err) != license.CodeStateIntegrityFailure {
		t.Fatalf("wrong key: want CodeStateIntegrityFailure, got %s", license.CodeOf(err))
	}
}

func TestDeriveRollbackKeyStrictRejectsEmptyFingerprint(t *testing.T) {
	if _, err := license.DeriveRollbackKeyStrict([]byte("secret"), ""); license.CodeOf(err) != license.CodeStateIntegrityFailure {
		t.Fatalf("empty fingerprint: want CodeStateIntegrityFailure, got %s", license.CodeOf(err))
	}
	k, err := license.DeriveRollbackKeyStrict([]byte("secret"), "fp")
	if err != nil {
		t.Fatalf("valid fingerprint: unexpected error %v", err)
	}
	// Strict must equal the non-strict derivation for the same inputs.
	if string(k) != string(license.DeriveRollbackKey([]byte("secret"), "fp")) {
		t.Fatal("strict and non-strict derivations disagree")
	}
}

func TestLifetimeToleratesCorruptRollbackState(t *testing.T) {
	// A lifetime license is time-independent, so a corrupt state file is
	// tolerated (reset from clean slate) rather than fatal.
	path := filepath.Join(t.TempDir(), "rollback.state")
	if err := os.WriteFile(path, []byte("garbage-not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := license.DeriveRollbackKey([]byte("secret"), "fp")

	s, pub := testKeyPair(t, "k1")
	req := baseRequest()
	req.LicenseType = license.LicenseTypeLifetime
	req.ExpiresAt = nil
	data := issueBytes(t, s, req)

	mgr := newTestManager(ringWith(t, "k1", pub),
		license.WithRollbackStore(mustStore(t, path, key)),
		license.WithClock(license.FixedClock{T: time.Now().UTC()}),
	)
	res, err := mgr.Validate(data, license.ValidationContext{})
	if err != nil || !res.Valid() {
		t.Fatalf("lifetime should tolerate corrupt state: err=%v code=%s", err, res.Code())
	}
}

// ---------------------------------------------------------------------------
// Revocation edge cases
// ---------------------------------------------------------------------------

func TestLoadRevocationListWrongKeyID(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	env, err := issuer.BuildRevocationList(s, []string{"lic_x"}) //nolint:staticcheck // intentionally builds a legacy v1 list
	if err != nil {
		t.Fatal(err)
	}
	// The ring only knows a different key id; lookup must fail as unknown.
	ring := ringWith(t, "k2", pub)
	data, _ := json.Marshal(env)
	if _, err := license.LoadRevocationList(ring, data, time.Now().UTC()); license.CodeOf(err) != license.CodeKeyUnknown {
		t.Fatalf("unknown revocation key: want CodeKeyUnknown, got %s", license.CodeOf(err))
	}
}

func TestLoadRevocationListBadSignature(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	env, err := issuer.BuildRevocationList(s, []string{"lic_x"}) //nolint:staticcheck // intentionally builds a legacy v1 list
	if err != nil {
		t.Fatal(err)
	}
	// Flip the signature to a valid-length but wrong signature.
	sig := make([]byte, ed25519.SignatureSize)
	env.Signature = base64.URLEncoding.EncodeToString(sig)
	data, _ := json.Marshal(env)
	ring := ringWith(t, "k1", pub)
	if _, err := license.LoadRevocationList(ring, data, time.Now().UTC()); license.CodeOf(err) != license.CodeSignatureInvalid {
		t.Fatalf("bad revocation signature: want CodeSignatureInvalid, got %s", license.CodeOf(err))
	}
}

func TestLoadRevocationListDedupesDuplicateIDs(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	env, err := buildRevocation(t, s, "dup", "dup", "other", "")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(env)
	ring := ringWith(t, "k1", pub)
	rp, err := license.LoadRevocationList(ring, data, time.Now().UTC())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !rp.IsRevoked("dup") || !rp.IsRevoked("other") {
		t.Fatal("expected dup and other to be revoked")
	}
	if rp.IsRevoked("") {
		t.Fatal("empty id should never be revoked")
	}
	if rp.IsRevoked("absent") {
		t.Fatal("absent id must not be revoked")
	}
}

func TestStaticRevocationNilSafe(t *testing.T) {
	var s *license.StaticRevocation
	if s.IsRevoked("anything") {
		t.Fatal("nil StaticRevocation must report not revoked")
	}
	r := license.NewStaticRevocation("a", "b")
	if !r.IsRevoked("a") || r.IsRevoked("c") {
		t.Fatal("StaticRevocation membership incorrect")
	}
}

// ---------------------------------------------------------------------------
// Facade defensive copies
// ---------------------------------------------------------------------------

func TestResultFeaturesDefensiveCopy(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	req := baseRequest()
	req.Edition = license.EditionEnterprise // rich default feature set
	data := issueBytes(t, s, req)
	mgr := newTestManager(ringWith(t, "k1", pub), license.WithClock(license.FixedClock{T: time.Now().UTC()}))
	res, err := mgr.Validate(data, license.ValidationContext{ProductID: "acme-app"})
	if err != nil {
		t.Fatal(err)
	}
	feats := res.Features()
	if len(feats) == 0 {
		t.Fatal("expected features")
	}
	original := feats[0]
	feats[0] = "MUTATED"
	again := res.Features()
	if again[0] != original {
		t.Fatalf("Features() is not a defensive copy: leaked mutation %q", again[0])
	}
}

func TestResultLimitsDefensiveCopy(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	req := baseRequest()
	req.Limits = map[string]int64{"seats": 10}
	data := issueBytes(t, s, req)
	mgr := newTestManager(ringWith(t, "k1", pub), license.WithClock(license.FixedClock{T: time.Now().UTC()}))
	res, err := mgr.Validate(data, license.ValidationContext{ProductID: "acme-app"})
	if err != nil {
		t.Fatal(err)
	}
	limits := res.Limits()
	limits["seats"] = 99999
	if again := res.Limits(); again["seats"] != 10 {
		t.Fatalf("Limits() is not a defensive copy: leaked mutation %d", again["seats"])
	}
}

func TestResultTimeAccessorsDefensiveCopy(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	data := issueBytes(t, s, baseRequest())
	mgr := newTestManager(ringWith(t, "k1", pub), license.WithClock(license.FixedClock{T: time.Now().UTC()}))
	res, err := mgr.Validate(data, license.ValidationContext{ProductID: "acme-app"})
	if err != nil {
		t.Fatal(err)
	}
	exp := res.ExpiresAt()
	if exp == nil {
		t.Fatal("expected an expiry for a subscription license")
	}
	*exp = exp.Add(1000 * time.Hour)
	if again := res.ExpiresAt(); again.Equal(*exp) {
		t.Fatal("ExpiresAt() must return a defensive copy, not the internal pointer")
	}
}

// ---------------------------------------------------------------------------
// Version fail-closed through the public Manager.Validate path
// ---------------------------------------------------------------------------

func TestValidateVersionFailClosedMissingProductVersion(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	req := baseRequest()
	req.VersionConstraint = license.VersionConstraint{MinVersion: "1.0.0"}
	data := issueBytes(t, s, req)
	mgr := newTestManager(ringWith(t, "k1", pub), license.WithClock(license.FixedClock{T: time.Now().UTC()}))
	// A declared constraint with NO running version must fail closed.
	_, err := mgr.Validate(data, license.ValidationContext{ProductID: "acme-app"})
	if license.CodeOf(err) != license.CodeVersionUnsupported {
		t.Fatalf("missing product version: want LICENSE_VERSION_UNSUPPORTED, got %s", license.CodeOf(err))
	}
	// Supplying a covered version passes.
	res, err := mgr.Validate(data, license.ValidationContext{ProductID: "acme-app", ProductVersion: "1.2.0"})
	if err != nil || !res.Valid() {
		t.Fatalf("covered version should pass: err=%v code=%s", err, res.Code())
	}
}

func TestValidateVersionPrereleaseAndUnparsable(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	req := baseRequest()
	req.VersionConstraint = license.VersionConstraint{MinVersion: "1.0.0", MaxVersion: "2.0.0"}
	data := issueBytes(t, s, req)
	mgr := newTestManager(ringWith(t, "k1", pub), license.WithClock(license.FixedClock{T: time.Now().UTC()}))

	// Prerelease suffix is stripped, so 1.5.0-rc1 is treated as 1.5.0 (in range).
	res, err := mgr.Validate(data, license.ValidationContext{ProductID: "acme-app", ProductVersion: "1.5.0-rc1"})
	if err != nil || !res.Valid() {
		t.Fatalf("prerelease in-range should pass: err=%v code=%s", err, res.Code())
	}
	// An unparsable running version is rejected rather than silently passing.
	_, err = mgr.Validate(data, license.ValidationContext{ProductID: "acme-app", ProductVersion: "not-a-version"})
	if license.CodeOf(err) != license.CodeVersionUnsupported {
		t.Fatalf("unparsable version: want LICENSE_VERSION_UNSUPPORTED, got %s", license.CodeOf(err))
	}
}
