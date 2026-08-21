package license

import (
	"strings"
	"testing"
	"time"
)

// #2/#3 Version fail-closed & strict parsing, tested directly against the
// unexported checkVersion / parseVersion / compareVersionsStrict helpers.

// declaredConstraintRejectsEmptyVersion asserts that when a license declares
// ANY version constraint but the caller supplies no running version, the gate
// fails closed with CodeVersionUnsupported (it cannot prove coverage).
func TestCheckVersionFailClosedOnEmptyVersion(t *testing.T) {
	now := time.Now().UTC()
	skew := DefaultClockSkew
	maint := now.Add(-24 * time.Hour)

	cases := []struct {
		name string
		vc   VersionConstraint
	}{
		{"min", VersionConstraint{MinVersion: "1.0.0"}},
		{"max", VersionConstraint{MaxVersion: "2.0.0"}},
		{"maintenance", VersionConstraint{MaintenanceUntil: &maint}},
		{"coveredMax", VersionConstraint{CoveredMaxVersion: "1.9.0"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Payload{VersionConstraint: tc.vc}
			if code := checkVersion(p, "", now, skew); code != CodeVersionUnsupported {
				t.Fatalf("empty version with %s constraint: want CodeVersionUnsupported, got %s", tc.name, code)
			}
		})
	}
}

// TestCheckVersionNoConstraintAllowsEmpty asserts that with NO declared
// constraint the gate is a no-op and passes even for an empty running version.
func TestCheckVersionNoConstraintAllowsEmpty(t *testing.T) {
	now := time.Now().UTC()
	p := &Payload{VersionConstraint: VersionConstraint{}}
	if code := checkVersion(p, "", now, DefaultClockSkew); code != CodeOK {
		t.Fatalf("no constraint + empty version: want CodeOK, got %s", code)
	}
	// A garbage running version is also fine when there is nothing to check.
	if code := checkVersion(p, "not-a-version", now, DefaultClockSkew); code != CodeOK {
		t.Fatalf("no constraint + junk version: want CodeOK, got %s", code)
	}
}

// TestCheckVersionRejectsUnparsableRunningVersion asserts that a supplied but
// unparsable running version is rejected rather than silently passing.
func TestCheckVersionRejectsUnparsableRunningVersion(t *testing.T) {
	now := time.Now().UTC()
	p := &Payload{VersionConstraint: VersionConstraint{MinVersion: "1.0.0", MaxVersion: "5.0.0"}}
	for _, v := range []string{"abc", "1.x", "1..2", "1.-1.0", "", "  "} {
		if code := checkVersion(p, v, now, DefaultClockSkew); code != CodeVersionUnsupported {
			t.Fatalf("unparsable running version %q: want CodeVersionUnsupported, got %s", v, code)
		}
	}
}

// TestCheckVersionMinMaxBoundaries covers normal in-range / boundary / out-of
// -range behavior for min & max.
func TestCheckVersionMinMaxBoundaries(t *testing.T) {
	now := time.Now().UTC()
	p := &Payload{VersionConstraint: VersionConstraint{MinVersion: "1.0.0", MaxVersion: "2.0.0"}}

	ok := []string{"1.0.0", "1.5.0", "2.0.0", "v1.2.3", "1.2"}
	for _, v := range ok {
		if code := checkVersion(p, v, now, DefaultClockSkew); code != CodeOK {
			t.Fatalf("version %q should be in range: want CodeOK, got %s", v, code)
		}
	}
	bad := []string{"0.9.9", "2.0.1", "3.0.0"}
	for _, v := range bad {
		if code := checkVersion(p, v, now, DefaultClockSkew); code != CodeVersionUnsupported {
			t.Fatalf("version %q should be out of range: want CodeVersionUnsupported, got %s", v, code)
		}
	}
}

// TestParseVersion covers strict parsing: valid decomposition and rejection of
// ambiguous/negative/empty input.
func TestParseVersion(t *testing.T) {
	valid := map[string][]int{
		"1.2.3":       {1, 2, 3},
		"v1.2.3":      {1, 2, 3},
		"1.2":         {1, 2},
		"1":           {1},
		"1.2.3-rc1":   {1, 2, 3},
		"1.2.3+build": {1, 2, 3},
		" 1.2.3 ":     {1, 2, 3},
	}
	for in, want := range valid {
		got, ok := parseVersion(in)
		if !ok {
			t.Fatalf("parseVersion(%q): want ok, got !ok", in)
		}
		if len(got) != len(want) {
			t.Fatalf("parseVersion(%q): want %v, got %v", in, want, got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("parseVersion(%q): want %v, got %v", in, want, got)
			}
		}
	}
	invalid := []string{"", "  ", "abc", "1.x", "1..2", "1.-1", "-1", "1.2.3.abc"}
	for _, in := range invalid {
		if _, ok := parseVersion(in); ok {
			t.Fatalf("parseVersion(%q): want !ok, got ok", in)
		}
	}
}

// TestCompareVersionsStrict covers ordering plus fail-closed on bad input.
func TestCompareVersionsStrict(t *testing.T) {
	type c struct {
		a, b string
		cmp  int
		ok   bool
	}
	cases := []c{
		{"1.0.0", "1.0.0", 0, true},
		{"1.2", "1.2.0", 0, true},
		{"1.0.0", "1.0.1", -1, true},
		{"2.0.0", "1.9.9", 1, true},
		{"v1.2.3", "1.2.3", 0, true},
		{"abc", "1.0.0", 0, false},
		{"1.0.0", "1.x", 0, false},
		{"", "1.0.0", 0, false},
	}
	for _, tc := range cases {
		cmp, ok := compareVersionsStrict(tc.a, tc.b)
		if ok != tc.ok {
			t.Fatalf("compareVersionsStrict(%q,%q): want ok=%v, got ok=%v", tc.a, tc.b, tc.ok, ok)
		}
		if ok && cmp != tc.cmp {
			t.Fatalf("compareVersionsStrict(%q,%q): want cmp=%d, got %d", tc.a, tc.b, tc.cmp, cmp)
		}
	}
}

// #4 Entry-count and length caps enforced by validateStatic.

// basePayload returns a minimally valid subscription payload for cap tests.
func basePayload() *Payload {
	now := time.Now().UTC()
	exp := now.Add(365 * 24 * time.Hour)
	return &Payload{
		SchemaVersion: SchemaVersion,
		LicenseID:     "l1",
		ProductID:     "p",
		KeyID:         "k1",
		IssuedAt:      now,
		ExpiresAt:     &exp,
		Edition:       EditionBasic,
		LicenseType:   LicenseTypeSubscription,
		DeviceBinding: DeviceBinding{Mode: DeviceModeNone},
	}
}

func TestValidateStaticEntryCountCaps(t *testing.T) {
	t.Run("features", func(t *testing.T) {
		p := basePayload()
		p.Features = make([]string, MaxFeatures+1)
		for i := range p.Features {
			p.Features[i] = "f"
		}
		if err := p.validateStatic(); CodeOf(err) != CodeInvalidLimits {
			t.Fatalf("too many features: want CodeInvalidLimits, got %v", err)
		}
	})

	t.Run("limits", func(t *testing.T) {
		p := basePayload()
		p.Limits = make(map[string]int64, MaxLimits+1)
		for i := 0; i < MaxLimits+1; i++ {
			p.Limits["k"+strings.Repeat("x", i%3)+itoa(i)] = 1
		}
		if err := p.validateStatic(); CodeOf(err) != CodeInvalidLimits {
			t.Fatalf("too many limits: want CodeInvalidLimits, got %v", err)
		}
	})

	t.Run("device_ids", func(t *testing.T) {
		p := basePayload()
		p.DeviceBinding = DeviceBinding{Mode: DeviceModeMulti}
		p.DeviceBinding.DeviceIDs = make([]string, MaxDeviceIDs+1)
		for i := range p.DeviceBinding.DeviceIDs {
			p.DeviceBinding.DeviceIDs[i] = "d" + itoa(i)
		}
		if err := p.validateStatic(); CodeOf(err) != CodeInvalidLimits {
			t.Fatalf("too many device_ids: want CodeInvalidLimits, got %v", err)
		}
	})

	t.Run("metadata_entries", func(t *testing.T) {
		p := basePayload()
		p.Metadata = make(map[string]string, MaxMetadataEntries+1)
		for i := 0; i < MaxMetadataEntries+1; i++ {
			p.Metadata["k"+itoa(i)] = "v"
		}
		if err := p.validateStatic(); CodeOf(err) != CodeInvalidLimits {
			t.Fatalf("too many metadata entries: want CodeInvalidLimits, got %v", err)
		}
	})

	t.Run("metadata_key_len", func(t *testing.T) {
		p := basePayload()
		p.Metadata = map[string]string{strings.Repeat("k", MaxMetadataKeyLen+1): "v"}
		if err := p.validateStatic(); CodeOf(err) != CodeInvalidLimits {
			t.Fatalf("overlong metadata key: want CodeInvalidLimits, got %v", err)
		}
	})

	t.Run("metadata_val_len", func(t *testing.T) {
		p := basePayload()
		p.Metadata = map[string]string{"k": strings.Repeat("v", MaxMetadataValLen+1)}
		if err := p.validateStatic(); CodeOf(err) != CodeInvalidLimits {
			t.Fatalf("overlong metadata value: want CodeInvalidLimits, got %v", err)
		}
	})

	t.Run("at_cap_ok", func(t *testing.T) {
		// Exactly at the cap must still be accepted.
		p := basePayload()
		p.Features = make([]string, MaxFeatures)
		for i := range p.Features {
			p.Features[i] = "f" + itoa(i)
		}
		if err := p.validateStatic(); err != nil {
			t.Fatalf("features exactly at cap should pass, got %v", err)
		}
	})
}

// itoa is a tiny local helper to avoid importing strconv just for tests.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
