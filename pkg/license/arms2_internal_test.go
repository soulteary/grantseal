package license

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestParseVersionAndNumericArms drives the remaining parse error arms directly.
func TestParseVersionAndNumericArms(t *testing.T) {
	// Too many prerelease components: 3 core + >29 identifiers exceeds the cap
	// (maxVersionComponents = 32).
	many := "1.2.3-a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a"
	if _, ok := parseVersion(many); ok {
		t.Fatal("expected parseVersion to reject too many prerelease components")
	}
	// Non-digit numeric identifier.
	if _, ok := parseNumericID("12a"); ok {
		t.Fatal("expected parseNumericID to reject non-digit")
	}
	// Overflow uint64.
	if _, ok := parseNumericID("99999999999999999999999999"); ok {
		t.Fatal("expected parseNumericID to reject overflow")
	}
	if _, ok := parseNumericID(""); ok {
		t.Fatal("expected empty numeric id rejected")
	}
	if _, ok := parseNumericID("01"); ok {
		t.Fatal("expected leading-zero rejected")
	}
}

// TestStrictJSONDirectArms drives decodeStrictJSON/walk* error arms.
func TestStrictJSONDirectArms(t *testing.T) {
	var dst map[string]any
	// Trailing data after a value.
	if err := decodeStrictJSON([]byte(`{"a":1} garbage`), &dst, 0); err == nil {
		t.Fatal("expected trailing-data rejection")
	}
	// Bare closing delimiter is malformed.
	if err := rejectDuplicateKeys([]byte(`}`)); err == nil {
		t.Fatal("expected bare-delimiter rejection")
	}
	// Duplicate keys anywhere.
	if err := rejectDuplicateKeys([]byte(`{"a":1,"a":2}`)); err == nil {
		t.Fatal("expected duplicate-key rejection")
	}
	// Nested array/object walk success.
	if err := rejectDuplicateKeys([]byte(`{"a":[1,{"b":2}],"c":3}`)); err != nil {
		t.Fatalf("valid nested json should pass: %v", err)
	}
	// Empty input.
	if err := decodeStrictJSON([]byte(``), &dst, 0); err == nil {
		t.Fatal("expected empty-input rejection")
	}
	// Over size cap.
	if err := decodeStrictJSON([]byte(`{"a":1}`), &dst, 3); err == nil {
		t.Fatal("expected size-cap rejection")
	}
}

// TestCheckDeviceArms drives the empty-fingerprint and invalid-mode arms.
func TestCheckDeviceArms(t *testing.T) {
	pSingle := &Payload{DeviceBinding: DeviceBinding{Mode: DeviceModeSingle, DeviceIDs: []string{"dev-1"}}}
	if code := checkDevice(pSingle, ""); code != CodeDeviceMismatch {
		t.Fatalf("empty fingerprint: want CodeDeviceMismatch, got %v", code)
	}
	if code := checkDevice(pSingle, "dev-1"); code != CodeOK {
		t.Fatalf("matching fingerprint: want CodeOK, got %v", code)
	}
	if code := checkDevice(pSingle, "other"); code != CodeDeviceMismatch {
		t.Fatalf("non-matching fingerprint: want CodeDeviceMismatch, got %v", code)
	}
	pNone := &Payload{DeviceBinding: DeviceBinding{Mode: DeviceModeNone}}
	if code := checkDevice(pNone, ""); code != CodeOK {
		t.Fatalf("none mode: want CodeOK, got %v", code)
	}
	pBad := &Payload{DeviceBinding: DeviceBinding{Mode: DeviceMode("weird")}}
	if code := checkDevice(pBad, "x"); code != CodeInvalidEnum {
		t.Fatalf("invalid mode: want CodeInvalidEnum, got %v", code)
	}
}

// TestCheckRevocationFreshnessArms drives the freshness validation arms.
func TestCheckRevocationFreshnessArms(t *testing.T) {
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	pol := RevocationPolicy{}

	if err := checkRevocationFreshness(&RevocationList{}, now, pol); CodeOf(err) != CodeMalformed {
		t.Fatalf("missing expires_at: want CodeMalformed, got %v", err)
	}
	exp := now.Add(time.Hour)
	if err := checkRevocationFreshness(&RevocationList{ExpiresAt: &exp}, now, pol); CodeOf(err) != CodeMalformed {
		t.Fatalf("zero issued_at: want CodeMalformed, got %v", err)
	}
	before := now.Add(-time.Hour)
	if err := checkRevocationFreshness(&RevocationList{IssuedAt: now, ExpiresAt: &before}, now, pol); CodeOf(err) != CodeMalformed {
		t.Fatalf("expires<=issued: want CodeMalformed, got %v", err)
	}
	// Issued in the future.
	future := now.Add(2 * time.Hour)
	fexp := now.Add(3 * time.Hour)
	if err := checkRevocationFreshness(&RevocationList{IssuedAt: future, ExpiresAt: &fexp}, now, pol); CodeOf(err) != CodeRevocationFromFuture {
		t.Fatalf("future issued: want CodeRevocationFromFuture, got %v", err)
	}
	// Expired.
	pastIssue := now.Add(-3 * time.Hour)
	pastExp := now.Add(-time.Hour)
	if err := checkRevocationFreshness(&RevocationList{IssuedAt: pastIssue, ExpiresAt: &pastExp}, now, pol); CodeOf(err) != CodeRevocationExpired {
		t.Fatalf("expired: want CodeRevocationExpired, got %v", err)
	}
	// MaxAge exceeded.
	polMax := RevocationPolicy{MaxAge: 30 * time.Minute}
	oldIssue := now.Add(-time.Hour)
	okExp := now.Add(time.Hour)
	if err := checkRevocationFreshness(&RevocationList{IssuedAt: oldIssue, ExpiresAt: &okExp}, now, polMax); CodeOf(err) != CodeRevocationExpired {
		t.Fatalf("MaxAge: want CodeRevocationExpired, got %v", err)
	}
	// Fresh & valid.
	if err := checkRevocationFreshness(&RevocationList{IssuedAt: now.Add(-time.Minute), ExpiresAt: &exp}, now, pol); err != nil {
		t.Fatalf("fresh list should pass, got %v", err)
	}
}

// TestLoadAndValidateArms drives the LoadAndValidate size-cap, not-found, and
// success (delegates to Validate) arms.
func TestLoadAndValidateArms(t *testing.T) {
	ring := NewKeyRing()
	mgr := NewManager(ring)

	// Not found.
	res, err := mgr.LoadAndValidate(filepath.Join(t.TempDir(), "missing.json"), ValidationContext{ProductID: "p"})
	if CodeOf(err) != CodeFileNotFound || res.Code() != CodeFileNotFound {
		t.Fatalf("missing file: want CodeFileNotFound, got %v / %v", err, res.Code())
	}

	// Too large.
	dir := t.TempDir()
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, make([]byte, MaxLicenseFileSize+1), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err = mgr.LoadAndValidate(big, ValidationContext{ProductID: "p"})
	if CodeOf(err) != CodeFileTooLarge {
		t.Fatalf("too large: want CodeFileTooLarge, got %v", err)
	}

	// Valid file present but bogus content: exercises the success delegation to
	// Validate (which then reports a malformed/parse code). The point is that
	// LoadAndValidate reaches its final return path.
	small := filepath.Join(dir, "small.json")
	if err := os.WriteFile(small, []byte("{not-json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.LoadAndValidate(small, ValidationContext{ProductID: "p"}); err == nil {
		t.Fatal("expected a validation error for bogus content")
	}
}
