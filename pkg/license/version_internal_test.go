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

	ok := []string{"1.0.0", "1.5.0", "2.0.0", "v1.2.3"}
	for _, v := range ok {
		if code := checkVersion(p, v, now, DefaultClockSkew); code != CodeOK {
			t.Fatalf("version %q should be in range: want CodeOK, got %s", v, code)
		}
	}
	bad := []string{"0.9.9", "2.0.1", "3.0.0", "1.2"}
	for _, v := range bad {
		if code := checkVersion(p, v, now, DefaultClockSkew); code != CodeVersionUnsupported {
			t.Fatalf("version %q should be out of range/invalid: want CodeVersionUnsupported, got %s", v, code)
		}
	}
}

// TestParseVersion covers strict SemVer 2.0.0 parsing: valid decomposition and
// rejection of ambiguous/negative/empty/non-three-part input.
func TestParseVersion(t *testing.T) {
	valid := map[string]semver{
		"1.2.3":            {major: 1, minor: 2, patch: 3},
		"v1.2.3":           {major: 1, minor: 2, patch: 3},
		"0.0.0":            {major: 0, minor: 0, patch: 0},
		"1.2.3-rc1":        {major: 1, minor: 2, patch: 3, prerelease: []string{"rc1"}},
		"1.2.3-alpha.1":    {major: 1, minor: 2, patch: 3, prerelease: []string{"alpha", "1"}},
		"1.2.3+build":      {major: 1, minor: 2, patch: 3},
		"1.2.3-rc.1+build": {major: 1, minor: 2, patch: 3, prerelease: []string{"rc", "1"}},
		" 1.2.3 ":          {major: 1, minor: 2, patch: 3},
	}
	for in, want := range valid {
		got, ok := parseVersion(in)
		if !ok {
			t.Fatalf("parseVersion(%q): want ok, got !ok", in)
		}
		if got.major != want.major || got.minor != want.minor || got.patch != want.patch {
			t.Fatalf("parseVersion(%q): core = %d.%d.%d, want %d.%d.%d", in, got.major, got.minor, got.patch, want.major, want.minor, want.patch)
		}
		if len(got.prerelease) != len(want.prerelease) {
			t.Fatalf("parseVersion(%q): prerelease %v, want %v", in, got.prerelease, want.prerelease)
		}
		for i := range want.prerelease {
			if got.prerelease[i] != want.prerelease[i] {
				t.Fatalf("parseVersion(%q): prerelease %v, want %v", in, got.prerelease, want.prerelease)
			}
		}
	}
	invalid := []string{
		"", "  ", "abc", "1.x", "1..2", "1.-1", "-1", "1.2.3.abc",
		"1.2", "1", // not three-part
		"01.2.3",     // leading zero in core
		"1.2.3-",     // empty prerelease
		"1.2.3-01",   // leading zero in numeric prerelease id
		"1.2.3-a..b", // empty prerelease id
		"1.2.3+",     // empty build
	}
	for _, in := range invalid {
		if _, ok := parseVersion(in); ok {
			t.Fatalf("parseVersion(%q): want !ok, got ok", in)
		}
	}
}

// TestCompareVersionsStrict covers SemVer 2.0.0 ordering (including prerelease
// precedence) plus fail-closed on bad input.
func TestCompareVersionsStrict(t *testing.T) {
	type c struct {
		a, b string
		cmp  int
		ok   bool
	}
	cases := []c{
		{"1.0.0", "1.0.0", 0, true},
		{"1.0.0", "1.0.1", -1, true},
		{"2.0.0", "1.9.9", 1, true},
		{"v1.2.3", "1.2.3", 0, true},
		// Prerelease precedence: prerelease < release.
		{"1.0.0-alpha", "1.0.0", -1, true},
		{"1.0.0", "1.0.0-alpha", 1, true},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1, true},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1, true},
		{"1.0.0-alpha.beta", "1.0.0-beta", -1, true},
		{"1.0.0-beta", "1.0.0-beta.2", -1, true},
		{"1.0.0-beta.2", "1.0.0-beta.11", -1, true},
		{"1.0.0-beta.11", "1.0.0-rc.1", -1, true},
		{"1.0.0-rc.1", "1.0.0", -1, true},
		// Build metadata is ignored for precedence.
		{"1.0.0+build.1", "1.0.0+build.2", 0, true},
		// Fail-closed on bad input.
		{"abc", "1.0.0", 0, false},
		{"1.0.0", "1.x", 0, false},
		{"", "1.0.0", 0, false},
		{"1.2", "1.2.0", 0, false},
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

// TestComparePrereleaseBoundaries exercises comparePrerelease's empty-vs-empty,
// empty-vs-nonempty (normal release outranks prerelease), shared-prefix, and
// differing-length arms directly.
func TestComparePrereleaseBoundaries(t *testing.T) {
	cases := []struct {
		name string
		a, b []string
		want int
	}{
		{"both_empty", nil, nil, 0},
		{"a_empty_release_higher", nil, []string{"alpha"}, 1},
		{"b_empty_release_higher", []string{"alpha"}, nil, -1},
		{"equal_single", []string{"alpha"}, []string{"alpha"}, 0},
		{"first_id_differs", []string{"alpha"}, []string{"beta"}, -1},
		{"shorter_lower", []string{"alpha"}, []string{"alpha", "1"}, -1},
		{"longer_higher", []string{"alpha", "1"}, []string{"alpha"}, 1},
		{"equal_multi", []string{"alpha", "1"}, []string{"alpha", "1"}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := comparePrerelease(tc.a, tc.b); got != tc.want {
				t.Fatalf("comparePrerelease(%v,%v): want %d, got %d", tc.a, tc.b, tc.want, got)
			}
		})
	}
}

// TestComparePrereleaseIDBoundaries covers the numeric/numeric, numeric/alpha,
// alpha/numeric, and alpha/alpha arms of comparePrereleaseID.
func TestComparePrereleaseIDBoundaries(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1", "1", 0},
		{"1", "2", -1},
		{"11", "2", 1},     // numeric compared numerically, not lexically
		{"1", "alpha", -1}, // numeric < alphanumeric
		{"alpha", "1", 1},  // alphanumeric > numeric
		{"alpha", "beta", -1},
		{"beta", "alpha", 1},
		{"alpha", "alpha", 0},
	}
	for _, tc := range cases {
		if got := comparePrereleaseID(tc.a, tc.b); got != tc.want {
			t.Fatalf("comparePrereleaseID(%q,%q): want %d, got %d", tc.a, tc.b, tc.want, got)
		}
	}
}

// TestIsNumericIDBoundaries covers empty, digit-only, and non-digit inputs.
func TestIsNumericIDBoundaries(t *testing.T) {
	yes := []string{"0", "1", "42", "007"} // isNumericID does not reject leading zeros
	for _, s := range yes {
		if !isNumericID(s) {
			t.Fatalf("isNumericID(%q): want true", s)
		}
	}
	no := []string{"", "a", "1a", "1.2", "-1", " 1"}
	for _, s := range no {
		if isNumericID(s) {
			t.Fatalf("isNumericID(%q): want false", s)
		}
	}
}

// TestIsAlphanumericIDBoundaries covers the [0-9A-Za-z-] character class,
// including the empty and illegal-character rejections.
func TestIsAlphanumericIDBoundaries(t *testing.T) {
	yes := []string{"a", "Z", "0", "-", "alpha-1", "A-9z"}
	for _, s := range yes {
		if !isAlphanumericID(s) {
			t.Fatalf("isAlphanumericID(%q): want true", s)
		}
	}
	no := []string{"", "a.b", "a_b", "a b", "a+b", "π"}
	for _, s := range no {
		if isAlphanumericID(s) {
			t.Fatalf("isAlphanumericID(%q): want false", s)
		}
	}
}

// TestIsValidDotSeparatedBoundaries covers empty input, empty segments, illegal
// characters, and the allowLeadingZero toggle for numeric segments.
func TestIsValidDotSeparatedBoundaries(t *testing.T) {
	// allowLeadingZero = false (prerelease-style).
	if !isValidDotSeparated("alpha.1.beta", false) {
		t.Fatal("valid dotted identifiers should pass")
	}
	if isValidDotSeparated("", false) {
		t.Fatal("empty string must be rejected")
	}
	if isValidDotSeparated("a..b", false) {
		t.Fatal("empty segment must be rejected")
	}
	if isValidDotSeparated("a.b_c", false) {
		t.Fatal("illegal character must be rejected")
	}
	if isValidDotSeparated("a.01", false) {
		t.Fatal("leading-zero numeric segment must be rejected when disallowed")
	}
	// allowLeadingZero = true (build-metadata-style): leading zeros permitted.
	if !isValidDotSeparated("a.01", true) {
		t.Fatal("leading-zero numeric segment should pass when allowed")
	}
	if !isValidDotSeparated("build.001.x", true) {
		t.Fatal("build metadata with leading zeros should pass")
	}
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
