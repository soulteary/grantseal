package license

import (
	"fmt"
	"time"
)

// LicenseSchemaVersion is the only license payload schema version this build
// understands. Unknown schema versions are rejected (no silent downgrade).
// v2 pairs with the grantseal/license/v2 signing domain: legacy v1 payloads
// are rejected as CodeUnsupportedSchema (a breaking, one-time clean upgrade).
const LicenseSchemaVersion = 2

// RevocationSchemaVersion is the current revocation-list schema version. v2 adds
// replay-resistance metadata (list_id, sequence, expires_at) over the legacy v1
// shape. v1 lists are rejected by default and only accepted via an explicit
// RevocationPolicy.AllowLegacyV1 opt-in (see revocation.go).
const RevocationSchemaVersion = 2

// SchemaVersion is a deprecated alias of LicenseSchemaVersion, retained so
// existing callers/tests that reference SchemaVersion keep compiling.
//
// Deprecated: use LicenseSchemaVersion for license payloads or
// RevocationSchemaVersion for revocation lists. This alias refers to the
// LICENSE schema version only.
const SchemaVersion = LicenseSchemaVersion

// MaxLicenseFileSize is the hard cap on a license file's size, in bytes.
// Files larger than this are rejected before any parsing to bound work and
// mitigate resource-exhaustion attacks.
const MaxLicenseFileSize = 64 * 1024

// Independent size and entry caps for the other artifacts this package parses,
// so a large revocation list cannot be constrained by (or constrain) the much
// smaller license/rollback limits. All bound parsing work up front to mitigate
// resource-exhaustion attacks.
const (
	// MaxRevocationFileSize caps a revocation envelope's on-the-wire size.
	MaxRevocationFileSize = 4 * 1024 * 1024
	// MaxRollbackStateSize caps the local anti-rollback state file's size.
	MaxRollbackStateSize = 4 * 1024
	// MaxRevokedIDs caps the number of entries in a parsed revocation list.
	MaxRevokedIDs = 100000
)

// Payload entry-count and length caps. These bound the fan-out of a signed
// payload so an over-large (but validly signed) license cannot force unbounded
// work or memory during validation.
const (
	MaxFeatures        = 256
	MaxLimits          = 256
	MaxDeviceIDs       = 256
	MaxMetadataEntries = 256
	MaxMetadataKeyLen  = 1024
	MaxMetadataValLen  = 1024
)

// Algorithm is the signature algorithm. Only Ed25519 is permitted.
type Algorithm string

const AlgorithmEd25519 Algorithm = "Ed25519"

// Signing domain-separation prefixes. The signature covers the prefix followed
// by the canonical payload bytes, so a signature produced for one artifact
// class (license) can never be replayed as another (revocation), even if an
// attacker could coerce identical canonical bytes. Changing a prefix is a
// breaking protocol change (a fresh signing domain), which is intentional: this
// build performs a one-time clean upgrade and does not accept unprefixed
// (pre-domain-separation) signatures.
const (
	// LicenseSigningDomain is prepended to canonical license payload bytes
	// before signing/verification (schema v2).
	LicenseSigningDomain = "grantseal/license/v2\x00"
	// RevocationSigningDomain is prepended to canonical revocation payload
	// bytes before signing/verification (schema v2).
	RevocationSigningDomain = "grantseal/revocation/v2\x00"
)

// licenseSigningInput returns the exact byte sequence signed/verified for a
// license: the license signing-domain prefix followed by the canonical bytes.
func licenseSigningInput(canonical []byte) []byte {
	out := make([]byte, 0, len(LicenseSigningDomain)+len(canonical))
	out = append(out, LicenseSigningDomain...)
	out = append(out, canonical...)
	return out
}

// revocationSigningInput returns the exact byte sequence signed/verified for a
// revocation list: the revocation signing-domain prefix followed by canonical
// bytes.
func revocationSigningInput(canonical []byte) []byte {
	out := make([]byte, 0, len(RevocationSigningDomain)+len(canonical))
	out = append(out, RevocationSigningDomain...)
	out = append(out, canonical...)
	return out
}

// LicenseSigningInput returns the exact bytes an issuer must sign (and the
// client verifies) for a license: the license signing-domain prefix followed
// by the canonical payload bytes. Exposed so the issuer package can produce
// domain-separated signatures without duplicating the prefix.
func LicenseSigningInput(canonical []byte) []byte { return licenseSigningInput(canonical) }

// RevocationSigningInput returns the exact bytes an issuer must sign (and the
// client verifies) for a revocation list (schema v2): the revocation
// signing-domain prefix followed by the canonical payload bytes.
func RevocationSigningInput(canonical []byte) []byte { return revocationSigningInput(canonical) }

// Valid reports whether the algorithm is the single supported value.
func (a Algorithm) Valid() bool { return a == AlgorithmEd25519 }

// Edition is a product edition. Unknown values are rejected.
type Edition string

const (
	EditionTrial        Edition = "trial"
	EditionBasic        Edition = "basic"
	EditionProfessional Edition = "professional"
	EditionEnterprise   Edition = "enterprise"
)

// Valid reports whether the edition is on the whitelist.
func (e Edition) Valid() bool {
	switch e {
	case EditionTrial, EditionBasic, EditionProfessional, EditionEnterprise:
		return true
	}
	return false
}

// LicenseType is the licensing model. Unknown values are rejected.
type LicenseType string

const (
	LicenseTypeTrial        LicenseType = "trial"
	LicenseTypeSubscription LicenseType = "subscription"
	LicenseTypeLifetime     LicenseType = "lifetime"
)

// Valid reports whether the license type is on the whitelist.
func (t LicenseType) Valid() bool {
	switch t {
	case LicenseTypeTrial, LicenseTypeSubscription, LicenseTypeLifetime:
		return true
	}
	return false
}

// DeviceMode describes how a license binds to devices. Unknown values rejected.
type DeviceMode string

const (
	DeviceModeNone   DeviceMode = "none"
	DeviceModeSingle DeviceMode = "single"
	DeviceModeMulti  DeviceMode = "multi"
)

// Valid reports whether the device mode is on the whitelist.
func (m DeviceMode) Valid() bool {
	switch m {
	case DeviceModeNone, DeviceModeSingle, DeviceModeMulti:
		return true
	}
	return false
}

// maxLimitValue bounds any single limit value to reject absurd/overflow values.
const maxLimitValue = int64(1) << 40 // ~1.09e12, generous but bounded

// DeviceBinding controls device-locking.
type DeviceBinding struct {
	Mode      DeviceMode `json:"mode"`
	DeviceIDs []string   `json:"device_ids,omitempty"`
}

// VersionConstraint restricts which product versions the license covers.
// Versions are opaque dotted strings compared component-wise (see version.go).
type VersionConstraint struct {
	MinVersion       string     `json:"min_version,omitempty"`
	MaxVersion       string     `json:"max_version,omitempty"`
	MaintenanceUntil *time.Time `json:"maintenance_until,omitempty"`
	// CoveredMaxVersion is the highest product version still covered once the
	// maintenance window (MaintenanceUntil) has lapsed. While maintenance is
	// active this field has no effect. After MaintenanceUntil passes, only
	// builds with version <= CoveredMaxVersion remain covered; any newer build
	// is rejected as LICENSE_VERSION_UNSUPPORTED.
	//
	// Offline limitation: this library cannot observe per-release publish
	// dates, so it cannot infer which builds shipped before maintenance
	// lapsed. CoveredMaxVersion makes that boundary explicit as a version
	// ceiling instead of a date, letting an issuer pin the last covered build.
	//
	// Backward compatibility: the field is optional. Licenses issued before
	// this field existed will not carry it; checkVersion falls back to the
	// legacy MinVersion-baseline approximation in that case (see validator.go).
	CoveredMaxVersion string `json:"covered_max_version,omitempty"`
}

// Payload is the signed license body. Field order here is irrelevant; the
// canonical form (canonical.go) is what gets signed.
type Payload struct {
	SchemaVersion     int               `json:"schema_version"`
	LicenseID         string            `json:"license_id"`
	SerialNumber      string            `json:"serial_number"`
	ProductID         string            `json:"product_id"`
	CustomerID        string            `json:"customer_id"`
	CustomerName      string            `json:"customer_name,omitempty"`
	Edition           Edition           `json:"edition"`
	LicenseType       LicenseType       `json:"license_type"`
	IssuedAt          time.Time         `json:"issued_at"`
	NotBefore         *time.Time        `json:"not_before,omitempty"`
	ExpiresAt         *time.Time        `json:"expires_at,omitempty"`
	GracePeriodDays   int               `json:"grace_period_days"`
	Features          []string          `json:"features,omitempty"`
	Limits            map[string]int64  `json:"limits,omitempty"`
	DeviceBinding     DeviceBinding     `json:"device_binding"`
	VersionConstraint VersionConstraint `json:"version_constraint"`
	Metadata          map[string]string `json:"metadata,omitempty"`
	KeyID             string            `json:"key_id"`
}

// ValidatePayloadStatic runs value-level validation (enums, limits, required
// fields) on a payload without any time/device/product context. Issuers use it
// to reject invalid licenses before signing; the client runs it during
// validation. It returns a stable error rather than panicking on malformed
// input (verified by the CI race/fuzz suite).
func ValidatePayloadStatic(p *Payload) error { return p.validateStatic() }

// validateStatic performs value-level validation that does not depend on the
// current time, device or product context. It rejects unknown enums and
// out-of-range limits, returning a stable *Error on any failure (fail-closed)
// rather than panicking on malformed input.
func (p *Payload) validateStatic() error {
	if p == nil {
		return newError(CodeMalformed, "nil payload", nil)
	}
	if err := p.validateIdentity(); err != nil {
		return err
	}
	if err := p.validateEnums(); err != nil {
		return err
	}
	if err := p.validateCaps(); err != nil {
		return err
	}
	if err := p.validateLimitsRange(); err != nil {
		return err
	}
	return p.validateTimeSemantics()
}

// validateIdentity checks schema version and the required identity fields that
// every license must carry.
func (p *Payload) validateIdentity() error {
	if p.SchemaVersion != SchemaVersion {
		return newError(CodeUnsupportedSchema,
			fmt.Sprintf("unsupported schema_version %d (want %d)", p.SchemaVersion, SchemaVersion), nil)
	}
	if p.LicenseID == "" || p.ProductID == "" || p.KeyID == "" {
		return newError(CodeMalformed, "missing required field (license_id/product_id/key_id)", nil)
	}
	if p.IssuedAt.IsZero() {
		return newError(CodeMalformed, "missing issued_at", nil)
	}
	return nil
}

// validateEnums rejects unknown edition / license_type / device-mode enum
// values and enforces the device-binding shape invariant.
func (p *Payload) validateEnums() error {
	if !p.Edition.Valid() {
		return newError(CodeInvalidEnum, fmt.Sprintf("unknown edition %q", p.Edition), nil)
	}
	if !p.LicenseType.Valid() {
		return newError(CodeInvalidEnum, fmt.Sprintf("unknown license_type %q", p.LicenseType), nil)
	}
	if !p.DeviceBinding.Mode.Valid() {
		return newError(CodeInvalidEnum, fmt.Sprintf("unknown device mode %q", p.DeviceBinding.Mode), nil)
	}
	if p.DeviceBinding.Mode != DeviceModeNone && len(p.DeviceBinding.DeviceIDs) == 0 {
		return newError(CodeMalformed, "device binding requires at least one device_id", nil)
	}
	return nil
}

// validateCaps bounds the payload's fan-out so an over-large (but validly
// signed) license cannot force unbounded work/memory during validation.
func (p *Payload) validateCaps() error {
	if p.GracePeriodDays < 0 || p.GracePeriodDays > 3650 {
		return newError(CodeInvalidLimits, "grace_period_days out of range [0,3650]", nil)
	}
	if len(p.Features) > MaxFeatures {
		return newError(CodeInvalidLimits, fmt.Sprintf("too many features (%d > %d)", len(p.Features), MaxFeatures), nil)
	}
	if len(p.Limits) > MaxLimits {
		return newError(CodeInvalidLimits, fmt.Sprintf("too many limits (%d > %d)", len(p.Limits), MaxLimits), nil)
	}
	if len(p.DeviceBinding.DeviceIDs) > MaxDeviceIDs {
		return newError(CodeInvalidLimits, fmt.Sprintf("too many device_ids (%d > %d)", len(p.DeviceBinding.DeviceIDs), MaxDeviceIDs), nil)
	}
	if len(p.Metadata) > MaxMetadataEntries {
		return newError(CodeInvalidLimits, fmt.Sprintf("too many metadata entries (%d > %d)", len(p.Metadata), MaxMetadataEntries), nil)
	}
	for k, v := range p.Metadata {
		if len(k) > MaxMetadataKeyLen {
			return newError(CodeInvalidLimits, "metadata key exceeds maximum length", nil)
		}
		if len(v) > MaxMetadataValLen {
			return newError(CodeInvalidLimits, fmt.Sprintf("metadata value for %q exceeds maximum length", k), nil)
		}
	}
	return nil
}

// validateLimitsRange rejects empty keys and out-of-range limit values.
func (p *Payload) validateLimitsRange() error {
	for k, v := range p.Limits {
		if k == "" {
			return newError(CodeInvalidLimits, "empty limit key", nil)
		}
		if v < 0 {
			return newError(CodeInvalidLimits, fmt.Sprintf("negative limit %q", k), nil)
		}
		if v > maxLimitValue {
			return newError(CodeInvalidLimits, fmt.Sprintf("limit %q exceeds maximum", k), nil)
		}
	}
	return nil
}

// validateTimeSemantics enforces the license_type time invariants and the
// logical ordering of issued_at / not_before / expires_at.
func (p *Payload) validateTimeSemantics() error {
	if p.NotBefore != nil && p.ExpiresAt != nil && p.ExpiresAt.Before(*p.NotBefore) {
		return newError(CodeMalformed, "expires_at before not_before", nil)
	}

	// license_type time semantics (security-critical). Enforcing these at the
	// static layer prevents authorization bypass where a time-limited license
	// silently becomes perpetual by omitting expires_at, or where a lifetime
	// license carries a spurious expires_at that would incorrectly expire it.
	switch p.LicenseType {
	case LicenseTypeTrial:
		// A trial MUST have an explicit expiry; otherwise it would never end.
		if p.ExpiresAt == nil {
			return newError(CodeMalformed, "trial license requires expires_at", nil)
		}
	case LicenseTypeSubscription:
		// A subscription MUST have an explicit expiry; otherwise it would
		// silently behave as perpetual.
		if p.ExpiresAt == nil {
			return newError(CodeMalformed, "subscription license requires expires_at", nil)
		}
	case LicenseTypeLifetime:
		// A lifetime license is perpetual and must NOT carry expires_at. This
		// keeps the perpetual guarantee unambiguous and prevents a mis-issued
		// expires_at from expiring a lifetime license (see validate()).
		if p.ExpiresAt != nil {
			return newError(CodeMalformed, "lifetime license must not carry expires_at", nil)
		}
	}

	// #10 issued_at vs. not_before / expires_at logical relations. Rules are
	// deliberately lenient (allow equality) to avoid rejecting legitimately
	// issued licenses due to sub-second rounding, while still catching clearly
	// inconsistent time windows.
	if p.ExpiresAt != nil && p.ExpiresAt.Before(p.IssuedAt) {
		return newError(CodeMalformed, "expires_at before issued_at", nil)
	}
	if p.NotBefore != nil && p.NotBefore.Before(p.IssuedAt) {
		return newError(CodeMalformed, "not_before before issued_at", nil)
	}
	return nil
}
