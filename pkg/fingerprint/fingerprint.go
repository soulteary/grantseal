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
	"fmt"
	"sort"
	"strings"
)

// FingerprintVersion is the current version of the default (v1) fingerprint
// scheme. It is embedded in the produced Fingerprint so that consumers can
// detect changes to the hashing/normalization algorithm.
//
// v1 semantics: strict "all collected components" — every stable identifier the
// platform exposes contributes to the canonical form, so adding or losing any
// one component changes the fingerprint. Use ComputeV2 for the more forgiving
// per-platform primary-identifier scheme.
const FingerprintVersion = 1

// FingerprintVersionV2 is the version tag embedded by ComputeV2/ComputeHMACV2.
//
// v2 semantics: a single per-platform PRIMARY identifier is selected by a fixed
// priority order (Linux machine-id, macOS platform_uuid, Windows MachineGUID,
// with documented fallbacks), and obvious placeholder values (all-zero UUIDs,
// "none"/"default"/"to be filled by o.e.m.", etc.) are filtered out. This makes
// the fingerprint resilient to secondary components appearing or disappearing
// while still failing closed when no usable primary identifier exists.
const FingerprintVersionV2 = 2

// Category constants identify the class of a hardware identifier. Only these
// category names are ever exposed; the underlying raw values are kept private.
const (
	CategoryMachineID    = "machine_id"
	CategoryBoardUUID    = "board_uuid"
	CategoryPlatformUUID = "platform_uuid"
	CategoryMachineGUID  = "machine_guid"
	CategoryProductUUID  = "product_uuid"
)

// Collector abstracts the platform-specific step of gathering raw hardware
// identifiers, keeping collection separate from the normalization/hashing that
// turns components into a Fingerprint. Implementations must be fail-closed: on
// any error they return no components (never a fabricated identifier) so the
// caller surfaces ErrInsufficientInfo rather than a bogus fingerprint.
type Collector interface {
	// Collect gathers the stable hardware identifiers available on the current
	// platform. It is best-effort: unreadable sources are skipped.
	Collect() []Component
	// PrimaryPriority returns the per-platform category priority order used to
	// select the single v2 primary identifier (most stable first).
	PrimaryPriority() []string
}

// systemCollector is the default Collector. It delegates to the build-tagged
// collectComponents/primaryCategoryPriority for the current OS, so collection
// stays platform-specific while normalization/hashing remains shared.
type systemCollector struct{}

// Collect implements Collector using the platform collectComponents.
func (systemCollector) Collect() []Component { return collectComponents() }

// PrimaryPriority implements Collector using the platform priority order.
func (systemCollector) PrimaryPriority() []string { return primaryCategoryPriority() }

// defaultCollector is the process-wide Collector used by Compute*/RequestCode*.
// It is a package var (not a const) so tests can substitute a deterministic
// collector; production code never reassigns it.
var defaultCollector Collector = systemCollector{}

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

// isPlaceholderValue reports whether a normalized identifier value is a known
// junk / placeholder that must never contribute to a fingerprint. DMI/SMBIOS
// fields are frequently unset and reported as vendor placeholders or all-zero
// UUIDs; treating them as real identifiers would collapse many distinct devices
// onto one fingerprint. The input is expected to already be normalize()d
// (trimmed, lowercased, whitespace-collapsed).
func isPlaceholderValue(v string) bool {
	if v == "" {
		return true
	}
	switch v {
	case "none",
		"default",
		"default string",
		"to be filled by o.e.m.",
		"to be filled by o.e.m",
		"system serial number",
		"system product name",
		"not specified",
		"not available",
		"unknown",
		"0",
		"00000000-0000-0000-0000-000000000000",
		"ffffffff-ffff-ffff-ffff-ffffffffffff":
		return true
	}
	// All-zero identifiers of any length (e.g. "0000...", "0-0-0") are junk.
	allZero := true
	for _, r := range v {
		if r != '0' && r != '-' {
			allZero = false
			break
		}
	}
	return allZero
}

// primaryComponent selects the single highest-priority, non-placeholder
// component from the collected set, using the supplied platform priority order.
// It returns ok=false when no usable primary identifier remains after
// placeholder filtering.
func primaryComponent(components []Component, priority []string) (Component, bool) {
	rank := make(map[string]int, len(priority))
	for i, cat := range priority {
		rank[cat] = i
	}

	best := -1
	var chosen Component
	for _, c := range components {
		if isPlaceholderValue(normalize(c.value)) {
			continue
		}
		r, ok := rank[c.Category]
		if !ok {
			// Categories outside the platform priority order rank last, in a
			// stable, deterministic way (after all known categories).
			r = len(priority)
		}
		if best == -1 || r < best {
			best = r
			chosen = c
		}
	}
	if best == -1 {
		return Component{}, false
	}
	return chosen, true
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

	components := defaultCollector.Collect()
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

// ComputeV2 builds a v2 device fingerprint scoped to productNamespace using
// plain SHA-256 over the single per-platform PRIMARY identifier (see
// FingerprintVersionV2). It returns ErrEmptyNamespace for an empty namespace
// and ErrInsufficientInfo when no usable, non-placeholder primary identifier is
// available.
func ComputeV2(productNamespace string) (Fingerprint, error) {
	return ComputeHMACV2(productNamespace, nil)
}

// ComputeHMACV2 behaves like ComputeV2 but, when len(hmacKey) > 0, derives the
// fingerprint using HMAC-SHA256 keyed with hmacKey. The output prefix is
// "hmac-sha256:" when keyed and "sha256:" for the plain fallback. The digest is
// computed over the canonical form of the single selected primary component, so
// secondary identifiers appearing or disappearing does not change the result.
func ComputeHMACV2(productNamespace string, hmacKey []byte) (Fingerprint, error) {
	if productNamespace == "" {
		return Fingerprint{}, ErrEmptyNamespace
	}

	primary, ok := primaryComponent(defaultCollector.Collect(), defaultCollector.PrimaryPriority())
	if !ok {
		return Fingerprint{}, ErrInsufficientInfo
	}
	canonical, categories, ok := canonicalForm(productNamespace, []Component{primary})
	if !ok {
		return Fingerprint{}, ErrInsufficientInfo
	}

	var (
		sum    []byte
		prefix string
	)
	if len(hmacKey) > 0 {
		mac := hmac.New(sha256.New, hmacKey)
		mac.Write([]byte(canonical))
		sum = mac.Sum(nil)
		prefix = "hmac-sha256:"
	} else {
		digest := sha256.Sum256([]byte(canonical))
		sum = digest[:]
		prefix = "sha256:"
	}

	return Fingerprint{
		FingerprintVersion: FingerprintVersionV2,
		ProductNamespace:   productNamespace,
		Fingerprint:        prefix + hex.EncodeToString(sum),
		ComponentsUsed:     categories,
	}, nil
}

// requestCodeFromFingerprint derives the grouped, uppercase request code from a
// fingerprint's hex digest, tagging it with the fingerprint scheme version so
// codes from v1 and v2 are visibly distinct (e.g. "V2-XXXX-XXXX-...").
func requestCodeFromFingerprint(fp Fingerprint) string {
	hexPart := fp.Fingerprint
	for _, p := range []string{"hmac-sha256:", "sha256:"} {
		hexPart = strings.TrimPrefix(hexPart, p)
	}
	if len(hexPart) > 20 {
		hexPart = hexPart[:20]
	}
	hexPart = strings.ToUpper(hexPart)

	groups := []string{fmt.Sprintf("V%d", fp.FingerprintVersion)}
	for i := 0; i < len(hexPart); i += 4 {
		end := i + 4
		if end > len(hexPart) {
			end = len(hexPart)
		}
		groups = append(groups, hexPart[i:end])
	}
	return strings.Join(groups, "-")
}

// RequestCode computes the v1 fingerprint for productNamespace and returns a
// human-friendly, uppercase, dash-grouped application/request code derived from
// the fingerprint hash. The result is deterministic for a given namespace and
// device, and is tagged with the fingerprint scheme version (e.g. "V1-...").
func RequestCode(productNamespace string) (string, error) {
	fp, err := Compute(productNamespace)
	if err != nil {
		return "", err
	}
	return requestCodeFromFingerprint(fp), nil
}

// RequestCodeV2 is the v2 counterpart of RequestCode: it derives the request
// code from the v2 (per-platform primary identifier) fingerprint and tags it
// with the "V2" version prefix.
func RequestCodeV2(productNamespace string) (string, error) {
	fp, err := ComputeV2(productNamespace)
	if err != nil {
		return "", err
	}
	return requestCodeFromFingerprint(fp), nil
}
