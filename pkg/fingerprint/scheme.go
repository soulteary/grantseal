package fingerprint

import (
	"crypto/sha256"
	"errors"
	"strconv"
	"strings"
)

// OpaqueVersion is the Scheme.Version value used for explicitly-typed,
// business-custom device identifiers of the form "opaque:<namespace>:<value>".
// It is a dedicated non-fingerprint marker (0) so opaque IDs are never confused
// with a real versioned fingerprint scheme (which start at v1).
const OpaqueVersion = 0

// OpaqueAlgorithm is the Scheme.Algorithm value set for parsed opaque
// identifiers. It marks the Scheme as an explicit opaque form rather than a
// hashed fingerprint so callers can branch on it without string-matching the
// raw value.
const OpaqueAlgorithm = "opaque"

// sha256HexLen is the length, in hex characters, of a SHA-256 / HMAC-SHA256
// digest (32 bytes => 64 hex chars). Every known algorithm in this package
// produces a 32-byte digest, so parsed digests must be exactly this long.
const sha256HexLen = 2 * sha256.Size

// Scheme is the parsed, strongly-typed representation of a persisted device
// binding value. It distinguishes two explicit families:
//
//   - Versioned fingerprints "fp:v<N>:<algorithm>:<digest>", where Version is
//     the scheme version (>= 1), Algorithm is "sha256" or "hmac-sha256", and
//     Digest is the lowercase hex digest.
//   - Opaque business identifiers "opaque:<namespace>:<value>", where
//     Version is OpaqueVersion (0), Algorithm is OpaqueAlgorithm ("opaque"),
//     the namespace is stored in Namespace, and the raw custom value is stored
//     in Digest.
//
// Any value that does not strictly match one of these forms is rejected by
// Parse (fail-closed).
type Scheme struct {
	// Version is the fingerprint scheme version (1 or 2 for versioned
	// fingerprints), or OpaqueVersion (0) for an explicit opaque identifier.
	Version int
	// Algorithm is the digest algorithm tag ("sha256" or "hmac-sha256") for a
	// versioned fingerprint, or OpaqueAlgorithm ("opaque") for an opaque
	// identifier.
	Algorithm string
	// Digest is the lowercase hex digest for a versioned fingerprint, or the
	// raw custom value for an opaque identifier.
	Digest string
	// Namespace is populated only for opaque identifiers and holds the
	// "<namespace>" segment of "opaque:<namespace>:<value>". It is empty for
	// versioned fingerprints.
	Namespace string
}

// IsOpaque reports whether the Scheme is an explicit opaque business
// identifier ("opaque:<namespace>:<value>") rather than a versioned
// fingerprint.
func (s Scheme) IsOpaque() bool { return s.Version == OpaqueVersion && s.Algorithm == OpaqueAlgorithm }

// Sentinel errors returned by Parse. Callers can use errors.Is to classify a
// rejection. Parse is fail-closed: any value that does not strictly match a
// known form is rejected.
var (
	// ErrMalformedScheme is returned when the overall structure does not match
	// either "fp:v<N>:<algorithm>:<digest>" or "opaque:<namespace>:<value>".
	ErrMalformedScheme = errors.New("fingerprint: malformed device binding value")
	// ErrUnknownVersion is returned when the "fp:v<N>:" version segment is not
	// a known fingerprint scheme version (only v1 and v2 are known).
	ErrUnknownVersion = errors.New("fingerprint: unknown fingerprint scheme version")
	// ErrUnknownAlgorithm is returned when the algorithm tag is not a known
	// algorithm ("sha256" or "hmac-sha256").
	ErrUnknownAlgorithm = errors.New("fingerprint: unknown fingerprint algorithm")
	// ErrEmptyDigest is returned when the digest (or opaque value) segment is
	// empty.
	ErrEmptyDigest = errors.New("fingerprint: empty digest")
	// ErrInvalidDigest is returned when the digest is not valid lowercase
	// hexadecimal or does not have the expected length for the algorithm.
	ErrInvalidDigest = errors.New("fingerprint: digest is not valid hex of the expected length")
)

// knownSchemeVersions is the set of versioned fingerprint schemes Parse
// accepts. Anything outside this set fails closed with ErrUnknownVersion.
var knownSchemeVersions = map[int]struct{}{
	FingerprintVersion:   {},
	FingerprintVersionV2: {},
}

// knownAlgorithms is the set of algorithm tags Parse accepts for a versioned
// fingerprint. Anything outside this set fails closed with ErrUnknownAlgorithm.
var knownAlgorithms = map[string]struct{}{
	"sha256":      {},
	"hmac-sha256": {},
}

// Parse strictly parses a persisted device binding value into a Scheme,
// failing closed on anything that does not exactly match a known form.
//
// It accepts two explicit forms:
//
//   - "fp:v<N>:<algorithm>:<digest>" — a versioned fingerprint. The version
//     must be a known scheme (v1 or v2), the algorithm must be "sha256" or
//     "hmac-sha256", and the digest must be non-empty, lowercase hexadecimal,
//     and exactly 64 characters (a 32-byte SHA-256/HMAC-SHA256 digest).
//   - "opaque:<namespace>:<value>" — an explicit, business-custom identifier.
//     The namespace and value must both be non-empty. The value may contain
//     additional colons (only the first two colons are used as separators), so
//     arbitrary opaque payloads are preserved verbatim in Scheme.Digest.
//
// Every other input — a bare hex string, a legacy "sha256:<hex>" without a
// version, an unknown version or algorithm, an empty or malformed digest, a
// non-hex digest, or a digest of the wrong length — is rejected with the
// corresponding sentinel error. Raw device values are never logged; only the
// classification (via the returned error) leaves the package.
func Parse(value string) (Scheme, error) {
	if rest, ok := strings.CutPrefix(value, "opaque:"); ok {
		ns, val, ok := strings.Cut(rest, ":")
		if !ok || ns == "" || val == "" {
			return Scheme{}, ErrMalformedScheme
		}
		return Scheme{
			Version:   OpaqueVersion,
			Algorithm: OpaqueAlgorithm,
			Namespace: ns,
			Digest:    val,
		}, nil
	}

	rest, ok := strings.CutPrefix(value, "fp:v")
	if !ok {
		return Scheme{}, ErrMalformedScheme
	}

	versionStr, afterVersion, ok := strings.Cut(rest, ":")
	if !ok || versionStr == "" {
		return Scheme{}, ErrMalformedScheme
	}
	version, err := strconv.Atoi(versionStr)
	if err != nil || version < 1 {
		return Scheme{}, ErrMalformedScheme
	}
	if _, known := knownSchemeVersions[version]; !known {
		return Scheme{}, ErrUnknownVersion
	}

	algorithm, digest, ok := strings.Cut(afterVersion, ":")
	if !ok {
		return Scheme{}, ErrMalformedScheme
	}
	if _, known := knownAlgorithms[algorithm]; !known {
		return Scheme{}, ErrUnknownAlgorithm
	}
	if digest == "" {
		return Scheme{}, ErrEmptyDigest
	}
	if len(digest) != sha256HexLen || !isLowerHex(digest) {
		return Scheme{}, ErrInvalidDigest
	}

	return Scheme{
		Version:   version,
		Algorithm: algorithm,
		Digest:    digest,
	}, nil
}

// isLowerHex reports whether s is a non-empty string of lowercase hexadecimal
// characters. Fingerprint digests are always emitted lowercase
// (hex.EncodeToString), so the parser rejects uppercase to keep persisted
// values canonical.
func isLowerHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// ComputeVersion builds a device fingerprint for productNamespace using the
// requested scheme version, dispatching to the v1 or v2 computation. It is the
// version-explicit counterpart of ComputeDefault for callers (such as the
// license layer) that must pin a specific, persisted fingerprint version.
//
// Supported versions are FingerprintVersion (v1) and FingerprintVersionV2
// (v2). Any other version fails closed with ErrUnknownVersion. It also returns
// ErrEmptyNamespace for an empty namespace and ErrInsufficientInfo when no
// usable hardware identifier is available.
func ComputeVersion(productNamespace string, version int) (Fingerprint, error) {
	return ComputeHMACVersion(productNamespace, version, nil)
}

// ComputeHMACVersion is the keyed counterpart of ComputeVersion: when
// len(key) > 0 it derives the fingerprint using HMAC-SHA256 keyed with key,
// otherwise it falls back to plain SHA-256. It dispatches to the v1 or v2
// computation based on version.
//
// Supported versions are FingerprintVersion (v1) and FingerprintVersionV2
// (v2). Any other version fails closed with ErrUnknownVersion. It also returns
// ErrEmptyNamespace for an empty namespace and ErrInsufficientInfo when no
// usable hardware identifier is available.
func ComputeHMACVersion(productNamespace string, version int, key []byte) (Fingerprint, error) {
	switch version {
	case FingerprintVersion:
		return ComputeHMAC(productNamespace, key)
	case FingerprintVersionV2:
		return ComputeHMACV2(productNamespace, key)
	default:
		return Fingerprint{}, ErrUnknownVersion
	}
}
