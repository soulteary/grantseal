// Package fingerprint computes a cross-platform, privacy-respecting device
// fingerprint from stable hardware identifiers.
//
// The package is fail-closed: it never fabricates a random identifier. If it
// cannot gather any usable hardware information it returns ErrInsufficientInfo.
// Raw hardware values are never exported, returned, or logged; only hashed
// output and category names ever leave the package.
package fingerprint

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
)

// FingerprintVersion is the current version of the fingerprint scheme. It is
// embedded in the produced Fingerprint so that consumers can detect changes to
// the hashing/normalization algorithm.
const FingerprintVersion = 1

// Category constants identify the class of a hardware identifier. Only these
// category names are ever exposed; the underlying raw values are kept private.
const (
	CategoryMachineID    = "machine_id"
	CategoryBoardUUID    = "board_uuid"
	CategoryPlatformUUID = "platform_uuid"
	CategoryMachineGUID  = "machine_guid"
	CategoryProductUUID  = "product_uuid"
)

// Component is a single collected hardware identifier. The raw value is stored
// in an unexported field so it can never be marshalled, exported, or logged.
type Component struct {
	// Category identifies the kind of identifier (see the Category* constants).
	Category string
	// value is the raw hardware value. It is intentionally unexported so that
	// raw identifiers cannot leak through reflection-based logging or JSON.
	value string
}

// Fingerprint is the privacy-respecting result of a fingerprint computation.
// It contains only derived, non-reversible data plus the category names used.
type Fingerprint struct {
	FingerprintVersion int      `json:"fingerprint_version"`
	ProductNamespace   string   `json:"product_namespace"`
	Fingerprint        string   `json:"fingerprint"`
	ComponentsUsed     []string `json:"components_used"`
}

// Sentinel errors returned by this package.
var (
	// ErrInsufficientInfo is returned when no usable hardware identifier could
	// be collected. The package never falls back to a random identifier.
	ErrInsufficientInfo = errors.New("fingerprint: insufficient hardware information to build a stable fingerprint")
	// ErrEmptyNamespace is returned when the caller passes an empty product
	// namespace.
	ErrEmptyNamespace = errors.New("fingerprint: product namespace must not be empty")
)

// normalize trims surrounding whitespace, lowercases the value, and collapses
// any run of internal whitespace into a single space. This makes fingerprints
// stable across trivial formatting differences in hardware sources.
func normalize(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)
	return strings.Join(strings.Fields(s), " ")
}

// buildComponent constructs a Component, trimming the raw value. Callers should
// skip components whose trimmed raw value is empty.
func buildComponent(category, raw string) Component {
	return Component{Category: category, value: strings.TrimSpace(raw)}
}

// canonicalForm normalizes and deterministically serializes the given
// components, returning the canonical string and the sorted unique set of
// category names. It also reports whether any usable component remained.
func canonicalForm(productNamespace string, components []Component) (canonical string, categories []string, ok bool) {
	type nc struct {
		category string
		value    string
	}
	var norm []nc
	seen := make(map[string]struct{})
	for _, c := range components {
		v := normalize(c.value)
		if v == "" {
			continue
		}
		norm = append(norm, nc{category: c.Category, value: v})
		if _, dup := seen[c.Category]; !dup {
			seen[c.Category] = struct{}{}
			categories = append(categories, c.Category)
		}
	}
	if len(norm) == 0 {
		return "", nil, false
	}

	sort.Slice(norm, func(i, j int) bool {
		if norm[i].category != norm[j].category {
			return norm[i].category < norm[j].category
		}
		return norm[i].value < norm[j].value
	})
	sort.Strings(categories)

	var b strings.Builder
	b.WriteString(productNamespace)
	b.WriteByte('\x00')
	for i, n := range norm {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(n.category)
		b.WriteByte('=')
		b.WriteString(n.value)
	}
	return b.String(), categories, true
}

// Compute builds a stable device fingerprint scoped to productNamespace using
// plain SHA-256. It returns ErrEmptyNamespace for an empty namespace and
// ErrInsufficientInfo when no usable hardware identifier is available.
func Compute(productNamespace string) (Fingerprint, error) {
	return ComputeHMAC(productNamespace, nil)
}

// ComputeHMAC behaves like Compute but, when len(hmacKey) > 0, derives the
// fingerprint using HMAC-SHA256 keyed with hmacKey. With an empty key it falls
// back to plain SHA-256. The output prefix remains "sha256:".
func ComputeHMAC(productNamespace string, hmacKey []byte) (Fingerprint, error) {
	if productNamespace == "" {
		return Fingerprint{}, ErrEmptyNamespace
	}

	components := collectComponents()
	canonical, categories, ok := canonicalForm(productNamespace, components)
	if !ok {
		return Fingerprint{}, ErrInsufficientInfo
	}

	var sum []byte
	if len(hmacKey) > 0 {
		mac := hmac.New(sha256.New, hmacKey)
		mac.Write([]byte(canonical))
		sum = mac.Sum(nil)
	} else {
		digest := sha256.Sum256([]byte(canonical))
		sum = digest[:]
	}

	return Fingerprint{
		FingerprintVersion: FingerprintVersion,
		ProductNamespace:   productNamespace,
		Fingerprint:        "sha256:" + hex.EncodeToString(sum),
		ComponentsUsed:     categories,
	}, nil
}

// RequestCode computes the fingerprint for productNamespace and returns a
// human-friendly, uppercase, dash-grouped application/request code derived from
// the fingerprint hash. The result is deterministic for a given namespace and
// device.
func RequestCode(productNamespace string) (string, error) {
	fp, err := Compute(productNamespace)
	if err != nil {
		return "", err
	}

	hexPart := strings.TrimPrefix(fp.Fingerprint, "sha256:")
	if len(hexPart) > 20 {
		hexPart = hexPart[:20]
	}
	hexPart = strings.ToUpper(hexPart)

	var groups []string
	for i := 0; i < len(hexPart); i += 4 {
		end := i + 4
		if end > len(hexPart) {
			end = len(hexPart)
		}
		groups = append(groups, hexPart[i:end])
	}
	return strings.Join(groups, "-"), nil
}
