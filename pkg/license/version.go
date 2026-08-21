package license

import (
	"strconv"
	"strings"
)

// parseVersion strictly parses a dotted numeric version into its integer
// components. It strips a leading 'v' and any pre-release/build suffix after
// '-' or '+'. It does not silently coerce bad input: if any component fails to
// parse as a non-negative integer (or the version has no components), ok is
// false so the caller can fail closed on ambiguous input.
func parseVersion(v string) ([]int, bool) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		return nil, false
	}
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 0 {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

// compareVersionsStrict compares two dotted numeric version strings and fails
// closed: if either side cannot be strictly parsed it returns ok=false and the
// integer result must be ignored. Missing trailing components are treated as 0
// so "1.2" == "1.2.0". Returns -1, 0, or 1.
func compareVersionsStrict(a, b string) (int, bool) {
	as, aok := parseVersion(a)
	if !aok {
		return 0, false
	}
	bs, bok := parseVersion(b)
	if !bok {
		return 0, false
	}
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var av, bv int
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		switch {
		case av < bv:
			return -1, true
		case av > bv:
			return 1, true
		}
	}
	return 0, true
}
