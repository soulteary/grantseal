package license_test

import (
	"testing"
	"time"

	"github.com/soulteary/grantseal/pkg/license"
)

// 11. Device binding: matching fingerprint passes.
func TestDeviceBindingMatch(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	req := baseRequest()
	req.DeviceBinding = license.DeviceBinding{Mode: license.DeviceModeSingle, DeviceIDs: []string{devFPA}}
	data := issueBytes(t, s, req)
	mgr := newTestManager(ringWith(t, "k1", pub))
	res, err := mgr.Validate(data, license.ValidationContext{DeviceFingerprint: devFPA})
	if err != nil || !res.Valid() {
		t.Fatalf("device match should validate: %v", err)
	}
}

// 12. Device binding: mismatch rejected.
func TestDeviceBindingMismatch(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	req := baseRequest()
	req.DeviceBinding = license.DeviceBinding{Mode: license.DeviceModeSingle, DeviceIDs: []string{devFPA}}
	data := issueBytes(t, s, req)
	mgr := newTestManager(ringWith(t, "k1", pub))
	_, err := mgr.Validate(data, license.ValidationContext{DeviceFingerprint: devFPOther})
	if license.CodeOf(err) != license.CodeDeviceMismatch {
		t.Fatalf("expected LICENSE_DEVICE_MISMATCH, got %s", license.CodeOf(err))
	}
}

// 13. Multi-device binding accepts any listed device.
func TestDeviceBindingMulti(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	req := baseRequest()
	req.DeviceBinding = license.DeviceBinding{Mode: license.DeviceModeMulti, DeviceIDs: []string{devFPA, devFPB}}
	data := issueBytes(t, s, req)
	mgr := newTestManager(ringWith(t, "k1", pub))
	res, err := mgr.Validate(data, license.ValidationContext{DeviceFingerprint: devFPB})
	if err != nil || !res.Valid() {
		t.Fatalf("multi device should validate: %v", err)
	}
}

// 14. Product mismatch rejected.
func TestProductMismatch(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	data := issueBytes(t, s, baseRequest())
	mgr := newTestManager(ringWith(t, "k1", pub))
	_, err := mgr.Validate(data, license.ValidationContext{ProductID: "other-app"})
	if license.CodeOf(err) != license.CodeProductMismatch {
		t.Fatalf("expected LICENSE_PRODUCT_MISMATCH, got %s", license.CodeOf(err))
	}
}

// 15. Version below min rejected.
func TestVersionBelowMin(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	req := baseRequest()
	req.VersionConstraint = license.VersionConstraint{MinVersion: "2.0.0"}
	data := issueBytes(t, s, req)
	mgr := newTestManager(ringWith(t, "k1", pub))
	_, err := mgr.Validate(data, license.ValidationContext{ProductVersion: "1.5.0"})
	if license.CodeOf(err) != license.CodeVersionUnsupported {
		t.Fatalf("expected LICENSE_VERSION_UNSUPPORTED, got %s", license.CodeOf(err))
	}
}

// 16. Version within range passes.
func TestVersionWithinRange(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	req := baseRequest()
	req.VersionConstraint = license.VersionConstraint{MinVersion: "1.0.0", MaxVersion: "2.0.0"}
	data := issueBytes(t, s, req)
	mgr := newTestManager(ringWith(t, "k1", pub))
	res, err := mgr.Validate(data, license.ValidationContext{ProductVersion: "1.5.0"})
	if err != nil || !res.Valid() {
		t.Fatalf("version in range should validate: %v", err)
	}
}

// 17. Version above max rejected.
func TestVersionAboveMax(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	req := baseRequest()
	req.VersionConstraint = license.VersionConstraint{MaxVersion: "2.0.0"}
	data := issueBytes(t, s, req)
	mgr := newTestManager(ringWith(t, "k1", pub))
	_, err := mgr.Validate(data, license.ValidationContext{ProductVersion: "3.1.0"})
	if license.CodeOf(err) != license.CodeVersionUnsupported {
		t.Fatalf("expected LICENSE_VERSION_UNSUPPORTED, got %s", license.CodeOf(err))
	}
}

// 18. Feature gating: edition defaults + explicit features.
func TestFeatureGating(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	req := baseRequest()
	req.Edition = license.EditionProfessional // grants core,reports,api,sso
	req.Features = []string{"custom_x"}
	data := issueBytes(t, s, req)
	mgr := newTestManager(ringWith(t, "k1", pub))
	res, err := mgr.Validate(data, license.ValidationContext{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.HasFeature("api") || !res.HasFeature("custom_x") {
		t.Fatalf("expected api + custom_x features, got %v", res.Features())
	}
	if res.HasFeature("audit") {
		t.Fatalf("professional should not have enterprise 'audit' feature")
	}
}

// 19. Limits are surfaced and range-validated at issue time.
func TestLimits(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	req := baseRequest()
	req.Limits = map[string]int64{"max_seats": 25}
	data := issueBytes(t, s, req)
	mgr := newTestManager(ringWith(t, "k1", pub))
	res, err := mgr.Validate(data, license.ValidationContext{})
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := res.Limit("max_seats"); !ok || v != 25 {
		t.Fatalf("expected max_seats=25, got %d ok=%v", v, ok)
	}
}

// 20. Negative limit rejected at issue time.
func TestNegativeLimitRejectedAtIssue(t *testing.T) {
	p := &license.Payload{
		SchemaVersion: license.SchemaVersion,
		LicenseID:     "l1", ProductID: "p", KeyID: "k1",
		IssuedAt:      time.Now().UTC(),
		Edition:       license.EditionBasic,
		LicenseType:   license.LicenseTypeSubscription,
		DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
		Limits:        map[string]int64{"x": -1},
	}
	if err := license.ValidatePayloadStatic(p); license.CodeOf(err) != license.CodeInvalidLimits {
		t.Fatalf("expected LICENSE_INVALID_LIMITS, got %v", err)
	}
}

// 21. not_before in the future rejected.
func TestNotYetValid(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	req := baseRequest()
	now := time.Now().UTC()
	req.NotBefore = ptr(now.Add(48 * time.Hour))
	data := issueBytes(t, s, req)
	mgr := newTestManager(ringWith(t, "k1", pub))
	_, err := mgr.Validate(data, license.ValidationContext{})
	if license.CodeOf(err) != license.CodeNotYetValid {
		t.Fatalf("expected LICENSE_NOT_YET_VALID, got %s", license.CodeOf(err))
	}
}

// 22. Expired beyond grace rejected; within grace -> grace status.
func TestExpiryAndGrace(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	now := time.Now().UTC()

	// Expired 3 days ago, no grace -> expired. IssuedAt precedes ExpiresAt so
	// the license is internally consistent (issued in the past, since expired).
	req := baseRequest()
	req.IssuedAt = ptr(now.Add(-96 * time.Hour))
	req.ExpiresAt = ptr(now.Add(-72 * time.Hour))
	req.GracePeriodDays = 0
	data := issueBytes(t, s, req)
	mgr := newTestManager(ringWith(t, "k1", pub))
	_, err := mgr.Validate(data, license.ValidationContext{})
	if license.CodeOf(err) != license.CodeExpired {
		t.Fatalf("expected LICENSE_EXPIRED, got %s", license.CodeOf(err))
	}

	// Expired 1 day ago, 7-day grace -> grace status, still usable.
	req2 := baseRequest()
	req2.IssuedAt = ptr(now.Add(-96 * time.Hour))
	req2.ExpiresAt = ptr(now.Add(-24 * time.Hour))
	req2.GracePeriodDays = 7
	data2 := issueBytes(t, s, req2)
	res, err := mgr.Validate(data2, license.ValidationContext{})
	if err != nil {
		t.Fatalf("grace license should not error: %v", err)
	}
	if res.Status() != license.StatusGrace || !res.Valid() {
		t.Fatalf("expected grace status usable, got %s", res.Status())
	}
}
