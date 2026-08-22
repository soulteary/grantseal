package license_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/soulteary/grantseal/pkg/license"
)

// #1: Trial license without expires_at is rejected as malformed.
func TestTrialRequiresExpiry(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	p := &license.Payload{
		SchemaVersion: license.SchemaVersion,
		LicenseID:     "l1", ProductID: "p", KeyID: "k1",
		IssuedAt:    time.Now().UTC(),
		Edition:     license.EditionTrial,
		LicenseType: license.LicenseTypeTrial,
		// ExpiresAt intentionally omitted.
		DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
	}
	env, err := signRaw(t, s, p)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := env.MarshalJSONIndent()
	mgr := newTestManager(ringWith(t, "k1", pub))
	_, verr := mgr.Validate(data, license.ValidationContext{})
	if license.CodeOf(verr) != license.CodeMalformed {
		t.Fatalf("expected LICENSE_MALFORMED for trial without expiry, got %s", license.CodeOf(verr))
	}
}

// #1: Subscription without expires_at is rejected as malformed (must not
// silently become perpetual).
func TestSubscriptionRequiresExpiry(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	p := &license.Payload{
		SchemaVersion: license.SchemaVersion,
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
	if license.CodeOf(verr) != license.CodeMalformed {
		t.Fatalf("expected LICENSE_MALFORMED for subscription without expiry, got %s", license.CodeOf(verr))
	}
}

// #1: A lifetime license that carries expires_at is rejected as malformed.
func TestLifetimeRejectsExpiry(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	now := time.Now().UTC()
	exp := now.Add(24 * time.Hour)
	p := &license.Payload{
		SchemaVersion: license.SchemaVersion,
		LicenseID:     "l1", ProductID: "p", KeyID: "k1",
		IssuedAt:      now,
		ExpiresAt:     &exp,
		Edition:       license.EditionEnterprise,
		LicenseType:   license.LicenseTypeLifetime,
		DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
	}
	env, err := signRaw(t, s, p)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := env.MarshalJSONIndent()
	mgr := newTestManager(ringWith(t, "k1", pub))
	_, verr := mgr.Validate(data, license.ValidationContext{})
	if license.CodeOf(verr) != license.CodeMalformed {
		t.Fatalf("expected LICENSE_MALFORMED for lifetime with expiry, got %s", license.CodeOf(verr))
	}
}

// #1: A lifetime license is perpetual and still enforces device binding. Even
// if a (rule-bypassing) lifetime payload somehow reached validate() with a past
// expires_at, it must not expire — but device mismatch must still be rejected.
func TestLifetimeStillChecksDevice(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	req := baseRequest()
	req.LicenseType = license.LicenseTypeLifetime
	req.Edition = license.EditionEnterprise
	req.ExpiresAt = nil
	req.DeviceBinding = license.DeviceBinding{Mode: license.DeviceModeSingle, DeviceIDs: []string{devFPA}}
	data := issueBytes(t, s, req)
	mgr := newTestManager(ringWith(t, "k1", pub))

	// Wrong device -> still rejected.
	if _, err := mgr.Validate(data, license.ValidationContext{DeviceFingerprint: devFPOther}); license.CodeOf(err) != license.CodeDeviceMismatch {
		t.Fatalf("lifetime must still enforce device: got %s", license.CodeOf(err))
	}
	// Right device -> valid and never expires.
	res, err := mgr.Validate(data, license.ValidationContext{DeviceFingerprint: devFPA})
	if err != nil || !res.Valid() {
		t.Fatalf("lifetime with matching device should validate: %v", err)
	}
	if res.GetRemainingDays() != license.PerpetualRemainingDays {
		t.Fatalf("lifetime remaining days should be perpetual sentinel, got %d", res.GetRemainingDays())
	}
	if !res.DeviceMatched() {
		t.Fatalf("device should be reported matched")
	}
}

// #10: expires_at before issued_at is malformed.
func TestExpiresBeforeIssued(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-time.Hour)
	p := &license.Payload{
		SchemaVersion: license.SchemaVersion,
		LicenseID:     "l1", ProductID: "p", KeyID: "k1",
		IssuedAt:      now,
		ExpiresAt:     &past,
		Edition:       license.EditionBasic,
		LicenseType:   license.LicenseTypeSubscription,
		DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
	}
	if license.CodeOf(license.ValidatePayloadStatic(p)) != license.CodeMalformed {
		t.Fatal("expected malformed for expires_at before issued_at")
	}
}

// #10: not_before before issued_at is malformed.
func TestNotBeforeBeforeIssued(t *testing.T) {
	now := time.Now().UTC()
	nb := now.Add(-time.Hour)
	exp := now.Add(24 * time.Hour)
	p := &license.Payload{
		SchemaVersion: license.SchemaVersion,
		LicenseID:     "l1", ProductID: "p", KeyID: "k1",
		IssuedAt:      now,
		NotBefore:     &nb,
		ExpiresAt:     &exp,
		Edition:       license.EditionBasic,
		LicenseType:   license.LicenseTypeSubscription,
		DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
	}
	if license.CodeOf(license.ValidatePayloadStatic(p)) != license.CodeMalformed {
		t.Fatal("expected malformed for not_before before issued_at")
	}
}

// #2/#3: RequireFeature and CheckLimit facade behavior + error codes.
func TestRequireFeatureAndCheckLimit(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	req := baseRequest()
	req.Edition = license.EditionProfessional // grants api
	req.Limits = map[string]int64{"max_seats": 10}
	data := issueBytes(t, s, req)
	mgr := newTestManager(ringWith(t, "k1", pub))
	res, err := mgr.Validate(data, license.ValidationContext{})
	if err != nil {
		t.Fatal(err)
	}

	if err := res.RequireFeature("api"); err != nil {
		t.Fatalf("api should be granted: %v", err)
	}
	if err := res.RequireFeature("audit"); license.CodeOf(err) != license.CodeFeatureUnavailable {
		t.Fatalf("expected LICENSE_FEATURE_UNAVAILABLE for audit, got %s", license.CodeOf(err))
	}

	if err := res.CheckLimit("max_seats", 10); err != nil {
		t.Fatalf("10 seats within limit 10 should pass: %v", err)
	}
	if err := res.CheckLimit("max_seats", 11); license.CodeOf(err) != license.CodeLimitExceeded {
		t.Fatalf("expected LICENSE_LIMIT_EXCEEDED, got %s", license.CodeOf(err))
	}
	// Missing key -> unlimited (nil).
	if err := res.CheckLimit("unknown_key", 1_000_000); err != nil {
		t.Fatalf("missing limit key should be unlimited: %v", err)
	}
	if v, ok := res.GetLimit("max_seats"); !ok || v != 10 {
		t.Fatalf("GetLimit mismatch: %d %v", v, ok)
	}
	if res.GetEdition() != license.EditionProfessional {
		t.Fatalf("GetEdition mismatch: %s", res.GetEdition())
	}
}

// #2: Subscription remaining time / expiration accessors.
func TestRemainingAccessors(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	now := time.Now().UTC()
	req := baseRequest()
	req.ExpiresAt = ptr(now.Add(10 * 24 * time.Hour))
	data := issueBytes(t, s, req)
	mgr := newTestManager(ringWith(t, "k1", pub))
	res, err := mgr.Validate(data, license.ValidationContext{})
	if err != nil {
		t.Fatal(err)
	}
	if res.GetExpiration() == nil {
		t.Fatal("subscription should have expiration")
	}
	if d := res.GetRemainingDays(); d < 8 || d > 10 {
		t.Fatalf("remaining days ~10, got %d", d)
	}
	if res.RemainingTime() <= 0 {
		t.Fatalf("remaining time should be positive, got %v", res.RemainingTime())
	}
	if res.KeyID() != "k1" {
		t.Fatalf("KeyID should be k1, got %q", res.KeyID())
	}
	if !res.DeviceMatched() {
		t.Fatal("device-none should report matched")
	}
}

// #2: Manager caching + invalidation.
func TestManagerCaching(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	data := issueBytes(t, s, baseRequest())
	mgr := newTestManager(ringWith(t, "k1", pub))

	if _, ok := mgr.CachedResult(); ok {
		t.Fatal("no cache should exist before validation")
	}
	res, err := mgr.Validate(data, license.ValidationContext{})
	if err != nil {
		t.Fatal(err)
	}
	cached, ok := mgr.CachedResult()
	if !ok {
		t.Fatal("expected cached result after successful validation")
	}
	if cached.LicenseID() != res.LicenseID() {
		t.Fatalf("cached license id mismatch: %q vs %q", cached.LicenseID(), res.LicenseID())
	}
	mgr.InvalidateCache()
	if _, ok := mgr.CachedResult(); ok {
		t.Fatal("cache should be empty after InvalidateCache")
	}
}

// #4/#5: Malformed/forged input must not create or corrupt the rollback state
// (verify-before-rollback). A garbage file should never write the state file.
func TestGarbageDoesNotPolluteRollbackState(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "rollback.state")
	key := license.DeriveRollbackKey([]byte("secret"), "fp")
	store := mustStore(t, statePath, key)

	s, pub := testKeyPair(t, "k1")
	_ = s
	mgr := newTestManager(ringWith(t, "k1", pub), license.WithRollbackStore(store))

	_, err := mgr.Validate([]byte("not a license at all"), license.ValidationContext{})
	if err == nil {
		t.Fatal("garbage input should fail")
	}
	if _, statErr := os.Stat(statePath); statErr == nil {
		t.Fatal("rollback state file must not be written from unverified/garbage input")
	}
}

// #5: A corrupt rollback state is FATAL for a time-limited (subscription)
// license (fail-closed) but tolerated for a lifetime license.
func TestCorruptStateFailClosedByType(t *testing.T) {
	writeCorruptState := func(t *testing.T, path string, key []byte) {
		t.Helper()
		store := mustStore(t, path, key)
		st, _ := store.CheckRollback(nil, time.Now().UTC())
		if err := store.Save(st); err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(path)
		// Corrupt the stored MAC so the integrity check fails on Load.
		corrupt := strings.Replace(string(raw), st.MAC, strings.Repeat("0", len(st.MAC)), 1)
		if err := os.WriteFile(path, []byte(corrupt), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// Subscription -> fail-closed.
	{
		dir := t.TempDir()
		statePath := filepath.Join(dir, "rollback.state")
		key := license.DeriveRollbackKey([]byte("secret"), "fp")
		writeCorruptState(t, statePath, key)
		s, pub := testKeyPair(t, "k1")
		data := issueBytes(t, s, baseRequest()) // subscription
		mgr := newTestManager(ringWith(t, "k1", pub), license.WithRollbackStore(mustStore(t, statePath, key)))
		_, err := mgr.Validate(data, license.ValidationContext{})
		if license.CodeOf(err) != license.CodeStateIntegrityFailure {
			t.Fatalf("subscription with corrupt state should fail closed, got %s", license.CodeOf(err))
		}
	}

	// Lifetime -> tolerated (validates).
	{
		dir := t.TempDir()
		statePath := filepath.Join(dir, "rollback.state")
		key := license.DeriveRollbackKey([]byte("secret"), "fp")
		writeCorruptState(t, statePath, key)
		s, pub := testKeyPair(t, "k1")
		req := baseRequest()
		req.LicenseType = license.LicenseTypeLifetime
		req.Edition = license.EditionEnterprise
		req.ExpiresAt = nil
		data := issueBytes(t, s, req)
		mgr := newTestManager(ringWith(t, "k1", pub), license.WithRollbackStore(mustStore(t, statePath, key)))
		res, err := mgr.Validate(data, license.ValidationContext{})
		if err != nil || !res.Valid() {
			t.Fatalf("lifetime with corrupt state should tolerate and validate: %v", err)
		}
	}
}

// #6: Maintenance window semantics — within window a newer version is covered;
// after the window a newer version than the baseline is not.
func TestMaintenanceWindow(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	now := time.Now().UTC()

	// Maintenance still active: newer version covered.
	reqIn := baseRequest()
	reqIn.LicenseType = license.LicenseTypeLifetime
	reqIn.Edition = license.EditionEnterprise
	reqIn.ExpiresAt = nil
	reqIn.VersionConstraint = license.VersionConstraint{
		MinVersion:       "1.0.0",
		MaintenanceUntil: ptr(now.Add(24 * time.Hour)),
	}
	dataIn := issueBytes(t, s, reqIn)
	mgr := newTestManager(ringWith(t, "k1", pub))
	if res, err := mgr.Validate(dataIn, license.ValidationContext{ProductVersion: "2.0.0"}); err != nil || !res.Valid() {
		t.Fatalf("newer version within maintenance should validate: %v", err)
	}

	// Maintenance lapsed: newer-than-baseline version not covered.
	reqOut := baseRequest()
	reqOut.LicenseType = license.LicenseTypeLifetime
	reqOut.Edition = license.EditionEnterprise
	reqOut.ExpiresAt = nil
	reqOut.VersionConstraint = license.VersionConstraint{
		MinVersion:       "1.0.0",
		MaintenanceUntil: ptr(now.Add(-24 * time.Hour)),
	}
	dataOut := issueBytes(t, s, reqOut)
	if _, err := mgr.Validate(dataOut, license.ValidationContext{ProductVersion: "2.0.0"}); license.CodeOf(err) != license.CodeVersionUnsupported {
		t.Fatalf("newer version after lapsed maintenance should be unsupported, got %s", license.CodeOf(err))
	}
	// But the maintained baseline itself keeps working after lapse.
	if res, err := mgr.Validate(dataOut, license.ValidationContext{ProductVersion: "1.0.0"}); err != nil || !res.Valid() {
		t.Fatalf("baseline version after lapsed maintenance should still validate: %v", err)
	}
}

// #6b: CoveredMaxVersion semantics — the explicit maintenance ceiling.
func TestMaintenanceCoveredMaxVersion(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	mgr := newTestManager(ringWith(t, "k1", pub))
	now := time.Now().UTC()

	// Maintenance still active: the ceiling is not applied, so a build higher
	// than covered_max_version is still covered.
	reqActive := baseRequest()
	reqActive.LicenseType = license.LicenseTypeLifetime
	reqActive.Edition = license.EditionEnterprise
	reqActive.ExpiresAt = nil
	reqActive.VersionConstraint = license.VersionConstraint{
		MinVersion:        "1.0.0",
		MaintenanceUntil:  ptr(now.Add(24 * time.Hour)),
		CoveredMaxVersion: "1.9.0",
	}
	dataActive := issueBytes(t, s, reqActive)
	if res, err := mgr.Validate(dataActive, license.ValidationContext{ProductVersion: "2.5.0"}); err != nil || !res.Valid() {
		t.Fatalf("within maintenance, version above ceiling should still validate: %v", err)
	}

	// Maintenance lapsed + version <= covered_max_version -> covered.
	reqLapsed := baseRequest()
	reqLapsed.LicenseType = license.LicenseTypeLifetime
	reqLapsed.Edition = license.EditionEnterprise
	reqLapsed.ExpiresAt = nil
	reqLapsed.VersionConstraint = license.VersionConstraint{
		MinVersion:        "1.0.0",
		MaintenanceUntil:  ptr(now.Add(-24 * time.Hour)),
		CoveredMaxVersion: "1.9.0",
	}
	dataLapsed := issueBytes(t, s, reqLapsed)
	if res, err := mgr.Validate(dataLapsed, license.ValidationContext{ProductVersion: "1.9.0"}); err != nil || !res.Valid() {
		t.Fatalf("lapsed maintenance, version at ceiling should validate: %v", err)
	}
	if res, err := mgr.Validate(dataLapsed, license.ValidationContext{ProductVersion: "1.5.0"}); err != nil || !res.Valid() {
		t.Fatalf("lapsed maintenance, version below ceiling should validate: %v", err)
	}

	// Maintenance lapsed + version > covered_max_version -> unsupported.
	if _, err := mgr.Validate(dataLapsed, license.ValidationContext{ProductVersion: "2.0.0"}); license.CodeOf(err) != license.CodeVersionUnsupported {
		t.Fatalf("lapsed maintenance, version above ceiling should be unsupported, got %s", license.CodeOf(err))
	}
}

// #6c: legacy licenses without CoveredMaxVersion take the backward-compatible
// downgrade path (MinVersion baseline), and skip the gate when MinVersion is
// also absent.
func TestMaintenanceLegacyFallback(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	mgr := newTestManager(ringWith(t, "k1", pub))
	now := time.Now().UTC()

	// No CoveredMaxVersion, maintenance lapsed, MinVersion baseline present.
	reqLegacy := baseRequest()
	reqLegacy.LicenseType = license.LicenseTypeLifetime
	reqLegacy.Edition = license.EditionEnterprise
	reqLegacy.ExpiresAt = nil
	reqLegacy.VersionConstraint = license.VersionConstraint{
		MinVersion:       "1.0.0",
		MaintenanceUntil: ptr(now.Add(-24 * time.Hour)),
	}
	dataLegacy := issueBytes(t, s, reqLegacy)
	// Baseline still covered.
	if res, err := mgr.Validate(dataLegacy, license.ValidationContext{ProductVersion: "1.0.0"}); err != nil || !res.Valid() {
		t.Fatalf("legacy: baseline after lapse should validate: %v", err)
	}
	// Newer than baseline rejected.
	if _, err := mgr.Validate(dataLegacy, license.ValidationContext{ProductVersion: "2.0.0"}); license.CodeOf(err) != license.CodeVersionUnsupported {
		t.Fatalf("legacy: newer than baseline should be unsupported, got %s", license.CodeOf(err))
	}

	// Within the maintenance window, legacy path does not gate.
	reqLegacyActive := baseRequest()
	reqLegacyActive.LicenseType = license.LicenseTypeLifetime
	reqLegacyActive.Edition = license.EditionEnterprise
	reqLegacyActive.ExpiresAt = nil
	reqLegacyActive.VersionConstraint = license.VersionConstraint{
		MinVersion:       "1.0.0",
		MaintenanceUntil: ptr(now.Add(24 * time.Hour)),
	}
	dataLegacyActive := issueBytes(t, s, reqLegacyActive)
	if res, err := mgr.Validate(dataLegacyActive, license.ValidationContext{ProductVersion: "2.0.0"}); err != nil || !res.Valid() {
		t.Fatalf("legacy: newer version within maintenance should validate: %v", err)
	}

	// No CoveredMaxVersion and no MinVersion: maintenance gate is skipped even
	// after lapse (never falsely reject).
	reqNoBaseline := baseRequest()
	reqNoBaseline.LicenseType = license.LicenseTypeLifetime
	reqNoBaseline.Edition = license.EditionEnterprise
	reqNoBaseline.ExpiresAt = nil
	reqNoBaseline.VersionConstraint = license.VersionConstraint{
		MaintenanceUntil: ptr(now.Add(-24 * time.Hour)),
	}
	dataNoBaseline := issueBytes(t, s, reqNoBaseline)
	if res, err := mgr.Validate(dataNoBaseline, license.ValidationContext{ProductVersion: "9.9.9"}); err != nil || !res.Valid() {
		t.Fatalf("no baseline: maintenance gate should be skipped, got err=%v valid=%v", err, res.Valid())
	}
}

// #6d: regression — min/max range checks are unaffected by the maintenance
// ceiling and still reject out-of-range versions.
func TestVersionRangeUnaffectedByCoveredMax(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	mgr := newTestManager(ringWith(t, "k1", pub))

	req := baseRequest()
	req.VersionConstraint = license.VersionConstraint{
		MinVersion:        "1.0.0",
		MaxVersion:        "2.0.0",
		CoveredMaxVersion: "1.5.0",
	}
	data := issueBytes(t, s, req)
	// In range, no maintenance deadline -> ceiling never applies.
	if res, err := mgr.Validate(data, license.ValidationContext{ProductVersion: "1.9.0"}); err != nil || !res.Valid() {
		t.Fatalf("in-range version should validate regardless of ceiling: %v", err)
	}
	// Below min still rejected.
	if _, err := mgr.Validate(data, license.ValidationContext{ProductVersion: "0.9.0"}); license.CodeOf(err) != license.CodeVersionUnsupported {
		t.Fatalf("below min should be unsupported, got %s", license.CodeOf(err))
	}
	// Above max still rejected.
	if _, err := mgr.Validate(data, license.ValidationContext{ProductVersion: "3.0.0"}); license.CodeOf(err) != license.CodeVersionUnsupported {
		t.Fatalf("above max should be unsupported, got %s", license.CodeOf(err))
	}
}

// #3: backward-compatible alias now resolves to the same wire code as the
// canonical CodeFeatureUnavailable (they are two Go identifiers for one string).
func TestFeatureCodeAlias(t *testing.T) {
	if license.CodeFeatureUnavailable != license.CodeFeatureDenied {
		t.Fatal("CodeFeatureDenied must be a Go alias of CodeFeatureUnavailable (same string)")
	}
	if license.CodeFeatureUnavailable != "LICENSE_FEATURE_UNAVAILABLE" {
		t.Fatalf("unexpected feature-unavailable code: %s", license.CodeFeatureUnavailable)
	}
	if license.CodeFeatureDenied != "LICENSE_FEATURE_UNAVAILABLE" {
		t.Fatalf("alias must resolve to LICENSE_FEATURE_UNAVAILABLE, got: %s", license.CodeFeatureDenied)
	}
	if license.CodeLimitExceeded != "LICENSE_LIMIT_EXCEEDED" {
		t.Fatalf("unexpected limit-exceeded code: %s", license.CodeLimitExceeded)
	}
}
