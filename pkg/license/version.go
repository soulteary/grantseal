package license

import (
	"strconv"
	"strings"
)

// compareVersions compares two dotted numeric version strings (e.g. "1.2.0").
// Non-numeric or empty components are treated as 0. Missing trailing
// components are treated as 0 so "1.2" == "1.2.0". Returns -1, 0, or 1.
// Any parse ambiguity fails closed at the call site (validator rejects).
func compareVersions(a, b string) int {
	as := splitVersion(a)
	bs := splitVersion(b)
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
			return -1
		case av > bv:
			return 1
		}
	}
	return 0
}

// splitVersion parses a dotted version into integer components. It strips a
// leading 'v' and any pre-release/build suffix after '-' or '+'.
func splitVersion(v string) []int {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 0 {
			n = 0
		}
		out = append(out, n)
	}
	return out
}
