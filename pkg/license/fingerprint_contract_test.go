package license_test

import (
	"errors"
	"testing"

	"github.com/soulteary/grantseal/pkg/fingerprint"
	"github.com/soulteary/grantseal/pkg/license"
)

// TestDeviceBindingEndToEndRealFingerprint is the Scheme A contract test: it
// takes a REAL pkg/fingerprint output (fingerprint.ComputeVersion), binds a
// license to it through the issuer path, then validates the license with the
// same fingerprint and asserts it matches. This proves the value emitted by the
// fingerprint package is accepted verbatim by the license layer's Scheme A
// format enforcement (validateStatic -> fingerprint.Parse) and by device
// matching, closing the fingerprint -> issue -> validate loop.
//
// The test computes against the real system collector; on a host with no usable
// hardware identifier (some CI sandboxes) ComputeVersion fails closed with
// ErrInsufficientInfo, in which case there is nothing to bind and the test is
// skipped rather than asserting on a fabricated value.
func TestDeviceBindingEndToEndRealFingerprint(t *testing.T) {
	const ns = "grantseal-contract-test"
	fp, err := fingerprint.ComputeVersion(ns, fingerprint.FingerprintVersionV2)
	if errors.Is(err, fingerprint.ErrInsufficientInfo) {
		t.Skip("no usable hardware identifier on this host; cannot compute a real fingerprint")
	}
	if err != nil {
		t.Fatalf("compute real fingerprint: %v", err)
	}

	// A real fingerprint value must satisfy the same strict parser the license
	// layer enforces on persisted device_ids.
	if _, perr := fingerprint.Parse(fp.Fingerprint); perr != nil {
		t.Fatalf("real fingerprint %q must be parseable by Scheme A, got %v", fp.Fingerprint, perr)
	}

	s, pub := testKeyPair(t, "k1")
	req := baseRequest()
	req.DeviceBinding = license.DeviceBinding{
		Mode:      license.DeviceModeSingle,
		DeviceIDs: []string{fp.Fingerprint},
	}
	data := issueBytes(t, s, req)
	mgr := newTestManager(ringWith(t, "k1", pub))

	// Same device -> matches.
	res, err := mgr.Validate(data, license.ValidationContext{DeviceFingerprint: fp.Fingerprint})
	if err != nil || !res.Valid() {
		t.Fatalf("license bound to real fingerprint should validate on the same device: %v", err)
	}
	if !res.DeviceMatched() {
		t.Fatal("device should be reported as matched")
	}

	// A valid-but-different fingerprint must not match.
	other := devFPOther
	if other == fp.Fingerprint {
		other = devFPA
	}
	if _, err := mgr.Validate(data, license.ValidationContext{DeviceFingerprint: other}); license.CodeOf(err) != license.CodeDeviceMismatch {
		t.Fatalf("different fingerprint must mismatch, got %s", license.CodeOf(err))
	}
}

// TestDeviceBindingVersionPinnedRecomputationMatches emulates the default
// scheme advancing (e.g. a future v3 becoming the version-agnostic default)
// while an already-issued license stays pinned to v2. It binds a license to
// ComputeVersion(ns, 2) output, then shows that an explicit
// ComputeVersion(ns, 2) recomputation still matches the stored binding — the
// version prefix records which algorithm produced the value, so pinning that
// specific version keeps an old binding matchable even if ComputeDefault would
// now emit a different (higher-version) value.
func TestDeviceBindingVersionPinnedRecomputationMatches(t *testing.T) {
	const ns = "grantseal-contract-test"
	bound, err := fingerprint.ComputeVersion(ns, fingerprint.FingerprintVersionV2)
	if errors.Is(err, fingerprint.ErrInsufficientInfo) {
		t.Skip("no usable hardware identifier on this host; cannot compute a real fingerprint")
	}
	if err != nil {
		t.Fatalf("compute bound fingerprint: %v", err)
	}

	s, pub := testKeyPair(t, "k1")
	req := baseRequest()
	req.DeviceBinding = license.DeviceBinding{
		Mode:      license.DeviceModeSingle,
		DeviceIDs: []string{bound.Fingerprint},
	}
	data := issueBytes(t, s, req)
	mgr := newTestManager(ringWith(t, "k1", pub))

	// Later, the caller recomputes explicitly against the SAME pinned version
	// (v2). This simulates "default advanced to v3, but we recompute v2 for an
	// old v2 license": the recomputed value is byte-identical to the stored
	// binding, so it still matches.
	recomputed, err := fingerprint.ComputeVersion(ns, fingerprint.FingerprintVersionV2)
	if err != nil {
		t.Fatalf("recompute pinned v2 fingerprint: %v", err)
	}
	if recomputed.Fingerprint != bound.Fingerprint {
		t.Fatalf("pinned v2 recomputation must be deterministic: %q != %q", recomputed.Fingerprint, bound.Fingerprint)
	}
	res, err := mgr.Validate(data, license.ValidationContext{DeviceFingerprint: recomputed.Fingerprint})
	if err != nil || !res.Valid() {
		t.Fatalf("explicit v2 recomputation should still match an old v2 license: %v", err)
	}

	// Sanity: a DIFFERENT scheme version over the same namespace produces a
	// different value (different fp:v<N>: prefix and/or digest), so it would NOT
	// match the stored v2 binding — which is exactly why matching an old binding
	// requires recomputing the specific pinned version rather than trusting the
	// current default. v1 is used here as the stand-in for "a different default".
	v1, err := fingerprint.ComputeVersion(ns, fingerprint.FingerprintVersion)
	if err != nil {
		t.Fatalf("compute v1 fingerprint: %v", err)
	}
	if v1.Fingerprint == bound.Fingerprint {
		// Extremely unlikely (different scheme prefix), but guard the intent.
		t.Skip("v1 and v2 fingerprints coincided on this host; cannot demonstrate cross-version divergence")
	}
	if _, err := mgr.Validate(data, license.ValidationContext{DeviceFingerprint: v1.Fingerprint}); license.CodeOf(err) != license.CodeDeviceMismatch {
		t.Fatalf("a different-version fingerprint must not match the pinned v2 binding, got %s", license.CodeOf(err))
	}
}
