package license_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/soulteary/grantseal/pkg/license"
)

// 23. Clock rollback detected via integrity-protected state.
func TestClockRollbackDetected(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "rollback.state")
	key := license.DeriveRollbackKey([]byte("builtin-secret"), "sha256:device")

	store, err := license.NewRollbackStore(statePath, key, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Establish a "future" high-water mark.
	future := time.Now().UTC().Add(48 * time.Hour)
	st, err := store.CheckRollback(nil, future)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}

	s, pub := testKeyPair(t, "k1")
	data := issueBytes(t, s, baseRequest())
	mgr := newTestManager(ringWith(t, "k1", pub),
		license.WithRollbackStore(mustStore(t, statePath, key)),
		license.WithClock(license.FixedClock{T: time.Now().UTC()}), // "now" < future
	)
	_, verr := mgr.Validate(data, license.ValidationContext{})
	if license.CodeOf(verr) != license.CodeClockRollback {
		t.Fatalf("expected LICENSE_CLOCK_ROLLBACK, got %s", license.CodeOf(verr))
	}
}

// 24. Tampered rollback state fails its integrity (HMAC) check.
func TestRollbackStateTampering(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "rollback.state")
	key := license.DeriveRollbackKey([]byte("s"), "fp")
	store, err := license.NewRollbackStore(statePath, key, 0)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := store.CheckRollback(nil, time.Now().UTC())
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}
	// Corrupt the stored MAC.
	raw, _ := os.ReadFile(statePath)
	corrupt := strings.Replace(string(raw), st.MAC, strings.Repeat("0", len(st.MAC)), 1)
	if err := os.WriteFile(statePath, []byte(corrupt), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, lerr := store.Load(); license.CodeOf(lerr) != license.CodeStateIntegrityFailure {
		t.Fatalf("expected LICENSE_STATE_INTEGRITY_FAILURE, got %v", lerr)
	}
}

// 25. Missing required fields rejected as malformed.
func TestMissingRequiredFields(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	// Sign a payload missing product_id by using a raw payload path.
	p := &license.Payload{
		SchemaVersion: license.SchemaVersion,
		LicenseID:     "l1",
		// ProductID missing on purpose
		KeyID:         "k1",
		IssuedAt:      time.Now().UTC(),
		Edition:       license.EditionBasic,
		LicenseType:   license.LicenseTypeSubscription,
		DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
	}
	env, err := s.SignPayload(p)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := env.MarshalJSONIndent()
	mgr := newTestManager(ringWith(t, "k1", pub))
	_, verr := mgr.Validate(data, license.ValidationContext{})
	if license.CodeOf(verr) != license.CodeMalformed {
		t.Fatalf("expected LICENSE_MALFORMED, got %s", license.CodeOf(verr))
	}
}

// 26. Oversized license file rejected.
func TestOversizedFileRejected(t *testing.T) {
	big := make([]byte, license.MaxLicenseFileSize+1)
	for i := range big {
		big[i] = 'x'
	}
	s, pub := testKeyPair(t, "k1")
	mgr := newTestManager(ringWith(t, "k1", pub))
	_, err := mgr.Validate(big, license.ValidationContext{})
	if license.CodeOf(err) != license.CodeFileTooLarge {
		t.Fatalf("expected LICENSE_FILE_TOO_LARGE, got %s", license.CodeOf(err))
	}
	_ = s
}

// 27. Invalid Base64 payload rejected as malformed (not panic).
func TestInvalidBase64Rejected(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	data := issueBytes(t, s, baseRequest())
	var env license.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	env.Payload = "!!!not-base64!!!"
	mut, _ := json.Marshal(env)
	mgr := newTestManager(ringWith(t, "k1", pub))
	_, err := mgr.Validate(mut, license.ValidationContext{})
	if license.CodeOf(err) != license.CodeMalformed {
		t.Fatalf("expected LICENSE_MALFORMED, got %s", license.CodeOf(err))
	}
}

// 28a. Unsupported algorithm rejected.
func TestUnsupportedAlgorithm(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	data := issueBytes(t, s, baseRequest())
	var env license.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	env.Algorithm = "RS256"
	mut, _ := json.Marshal(env)
	mgr := newTestManager(ringWith(t, "k1", pub))
	_, err := mgr.Validate(mut, license.ValidationContext{})
	if license.CodeOf(err) != license.CodeUnsupportedAlgorithm {
		t.Fatalf("expected LICENSE_UNSUPPORTED_ALGORITHM, got %s", license.CodeOf(err))
	}
}

// 28b. Unsupported schema version rejected.
func TestUnsupportedSchema(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	p := &license.Payload{
		SchemaVersion: 999,
		LicenseID:     "l1", ProductID: "p", KeyID: "k1",
		IssuedAt:      time.Now().UTC(),
		Edition:       license.EditionBasic,
		LicenseType:   license.LicenseTypeSubscription,
		DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
	}
	env, err := signRaw(t, s, p)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := env.MarshalJSONIndent()
	mgr := newTestManager(ringWith(t, "k1", pub))
	_, verr := mgr.Validate(data, license.ValidationContext{})
	if license.CodeOf(verr) != license.CodeUnsupportedSchema {
		t.Fatalf("expected LICENSE_UNSUPPORTED_SCHEMA, got %s", license.CodeOf(verr))
	}
}

// 28c. Unknown enum (edition) rejected.
func TestUnknownEnumRejected(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	p := &license.Payload{
		SchemaVersion: license.SchemaVersion,
		LicenseID:     "l1", ProductID: "p", KeyID: "k1",
		IssuedAt:      time.Now().UTC(),
		Edition:       license.Edition("platinum"), // not on whitelist
		LicenseType:   license.LicenseTypeSubscription,
		DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
	}
	env, err := signRaw(t, s, p)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := env.MarshalJSONIndent()
	mgr := newTestManager(ringWith(t, "k1", pub))
	_, verr := mgr.Validate(data, license.ValidationContext{})
	if license.CodeOf(verr) != license.CodeInvalidEnum {
		t.Fatalf("expected LICENSE_INVALID_ENUM, got %s", license.CodeOf(verr))
	}
}

// 28d. Revocation: signed revocation list revokes a license by id.
func TestRevocationList(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	req := baseRequest()
	req.LicenseID = "lic_revokeme"
	data := issueBytes(t, s, req)

	revEnv, err := buildRevocation(t, s, "lic_revokeme")
	if err != nil {
		t.Fatal(err)
	}
	revData, _ := json.Marshal(revEnv)
	ring := ringWith(t, "k1", pub)
	rp, err := license.LoadRevocationList(ring, revData, time.Now().UTC())
	if err != nil {
		t.Fatalf("load revocation: %v", err)
	}
	mgr := newTestManager(ring, license.WithRevocation(rp))
	_, verr := mgr.Validate(data, license.ValidationContext{})
	if license.CodeOf(verr) != license.CodeRevoked {
		t.Fatalf("expected LICENSE_REVOKED, got %s", license.CodeOf(verr))
	}
}

// 28e. LoadAndValidate on a missing file returns file-not-found.
func TestFileNotFound(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	_ = s
	mgr := newTestManager(ringWith(t, "k1", pub))
	_, err := mgr.LoadAndValidate(filepath.Join(t.TempDir(), "nope.lic"), license.ValidationContext{})
	if license.CodeOf(err) != license.CodeFileNotFound {
		t.Fatalf("expected LICENSE_FILE_NOT_FOUND, got %s", license.CodeOf(err))
	}
}

func mustStore(t *testing.T, path string, key []byte) *license.RollbackStore {
	t.Helper()
	s, err := license.NewRollbackStore(path, key, 0)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
