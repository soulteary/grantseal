package license

import (
	"strconv"
	"strings"
)

// Version bounds. These cap the work and memory a single comparison can incur
// and reject absurd input rather than attempting to compare it.
const (
	// maxVersionComponents bounds the numeric core plus any dotted prerelease
	// identifiers considered during comparison.
	maxVersionComponents = 32
	// maxVersionLength bounds the raw version string length.
	maxVersionLength = 256
)

// semver is a parsed Semantic Versioning 2.0.0 value: a three-part numeric core
// plus optional dot-separated prerelease identifiers. Build metadata (after
// '+') is parsed but ignored for precedence, per the SemVer spec.
type semver struct {
	major, minor, patch uint64
	prerelease          []string // empty means a normal (non-prerelease) version
}

// parseVersion strictly parses a version string into a semver. It accepts an
// optional leading 'v'. The numeric core must be MAJOR.MINOR.PATCH with
// non-negative integers and no leading zeros (except "0" itself). A trailing
// "-<prerelease>" and/or "+<build>" are parsed per SemVer 2.0.0; build metadata
// is discarded. It fails closed (ok=false) on any ambiguity rather than
// coercing or stripping, returning a stable ok=false rather than panicking.
//
// Compatibility note: unlike the previous lenient parser, this REQUIRES the
// full three-part core. Two-part inputs like "1.2" are rejected. Issuers/tests
// must use canonical MAJOR.MINOR.PATCH strings.
func parseVersion(v string) (semver, bool) {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > maxVersionLength {
		return semver{}, false
	}
	v = strings.TrimPrefix(v, "v")

	// Split off build metadata (ignored for precedence) then prerelease.
	if i := strings.IndexByte(v, '+'); i >= 0 {
		build := v[i+1:]
		if !isValidDotSeparated(build, true) {
			return semver{}, false
		}
		v = v[:i]
	}
	var pre string
	hasPre := false
	if i := strings.IndexByte(v, '-'); i >= 0 {
		pre = v[i+1:]
		v = v[:i]
		hasPre = true
	}

	core := strings.Split(v, ".")
	if len(core) != 3 {
		return semver{}, false
	}
	nums := make([]uint64, 3)
	for i, p := range core {
		n, ok := parseNumericID(p)
		if !ok {
			return semver{}, false
		}
		nums[i] = n
	}

	sv := semver{major: nums[0], minor: nums[1], patch: nums[2]}
	if hasPre {
		if pre == "" {
			return semver{}, false // trailing '-' with empty prerelease
		}
		ids := strings.Split(pre, ".")
		if len(ids) == 0 || 3+len(ids) > maxVersionComponents {
			return semver{}, false
		}
		for _, id := range ids {
			if id == "" || !isValidPrereleaseID(id) {
				return semver{}, false
			}
		}
		sv.prerelease = ids
	}
	return sv, true
}

// parseNumericID parses a SemVer numeric identifier: digits only, no leading
// zeros unless the value is exactly "0".
func parseNumericID(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, false // no leading zeros
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// isNumericID reports whether s is composed solely of ASCII digits.
func isNumericID(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isValidPrereleaseID reports whether id is a valid SemVer prerelease
// identifier: either a numeric identifier (no leading zeros) or an
// alphanumeric identifier of [0-9A-Za-z-].
func isValidPrereleaseID(id string) bool {
	if isNumericID(id) {
		// Numeric identifiers must not have leading zeros.
		return !(len(id) > 1 && id[0] == '0')
	}
	return isAlphanumericID(id)
}

// isAlphanumericID reports whether s consists only of [0-9A-Za-z-].
func isAlphanumericID(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-') {
			return false
		}
	}
	return true
}

// isValidDotSeparated validates a dot-separated series of identifiers. When
// allowLeadingZero is true (build metadata), numeric identifiers may have
// leading zeros.
func isValidDotSeparated(s string, allowLeadingZero bool) bool {
	if s == "" {
		return false
	}
	for _, id := range strings.Split(s, ".") {
		if id == "" || !isAlphanumericID(id) {
			return false
		}
		if !allowLeadingZero && isNumericID(id) && len(id) > 1 && id[0] == '0' {
			return false
		}
	}
	return true
}

// compareVersionsStrict compares two version strings per SemVer 2.0.0
// precedence and fails closed: if either side cannot be strictly parsed it
// returns ok=false and the integer result must be ignored. Returns -1, 0, or 1.
//
// Precedence: numeric core compared field-by-field; then a version WITH a
// prerelease has LOWER precedence than the same core WITHOUT one
// (1.0.0-alpha < 1.0.0). Prerelease identifiers are compared per spec: numeric
// identifiers numerically, alphanumeric lexically (ASCII), numeric < alphanumeric,
// and a larger set of identifiers wins when all preceding are equal.
func compareVersionsStrict(a, b string) (int, bool) {
	as, aok := parseVersion(a)
	if !aok {
		return 0, false
	}
	bs, bok := parseVersion(b)
	if !bok {
		return 0, false
	}
	return as.compare(bs), true
}

// compare implements SemVer 2.0.0 precedence between two parsed versions.
func (a semver) compare(b semver) int {
	if c := cmpUint(a.major, b.major); c != 0 {
		return c
	}
	if c := cmpUint(a.minor, b.minor); c != 0 {
		return c
	}
	if c := cmpUint(a.patch, b.patch); c != 0 {
		return c
	}
	return comparePrerelease(a.prerelease, b.prerelease)
}

// comparePrerelease compares two prerelease identifier lists per SemVer 2.0.0.
// An empty list (normal release) has HIGHER precedence than any non-empty list.
func comparePrerelease(a, b []string) int {
	aEmpty, bEmpty := len(a) == 0, len(b) == 0
	switch {
	case aEmpty && bEmpty:
		return 0
	case aEmpty:
		return 1 // a is a normal release, b is prerelease -> a > b
	case bEmpty:
		return -1
	}
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if c := comparePrereleaseID(a[i], b[i]); c != 0 {
			return c
		}
	}
	// All shared identifiers equal: the longer list has higher precedence.
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

// comparePrereleaseID compares one prerelease identifier pair per spec.
func comparePrereleaseID(a, b string) int {
	aNum, bNum := isNumericID(a), isNumericID(b)
	switch {
	case aNum && bNum:
		// Compare numerically; both are already validated (no leading zeros).
		av, _ := strconv.ParseUint(a, 10, 64)
		bv, _ := strconv.ParseUint(b, 10, 64)
		return cmpUint(av, bv)
	case aNum:
		return -1 // numeric identifiers have lower precedence than alphanumeric
	case bNum:
		return 1
	default:
		return strings.Compare(a, b)
	}
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
