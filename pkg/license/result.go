package license

import (
	"sort"
	"time"
)

// Status is the high-level validation status of a license.
type Status string

const (
	StatusValid   Status = "valid"   // active and fully usable
	StatusGrace   Status = "grace"   // expired but within grace period
	StatusInvalid Status = "invalid" // failed validation
)

// ValidationResult is the read-only outcome of validation. All fields are
// returned by value or as copies; there are no setters. Callers must treat it
// as immutable. Accessor methods provide safe queries.
type ValidationResult struct {
	status        Status
	code          Code
	licenseID     string
	serialNumber  string
	productID     string
	edition       Edition
	licenseType   LicenseType
	notBefore     *time.Time
	expiresAt     *time.Time
	graceUntil    *time.Time
	features      []string
	limits        map[string]int64
	checkedAt     time.Time
	keyID         string
	deviceMatched bool
}

// Status returns the high-level status.
func (r ValidationResult) Status() Status { return r.status }

// Code returns the stable error code (CodeOK when valid).
func (r ValidationResult) Code() Code { return r.code }

// Valid reports whether the license is usable (valid or within grace).
func (r ValidationResult) Valid() bool { return r.status == StatusValid || r.status == StatusGrace }

// LicenseID returns the license id.
func (r ValidationResult) LicenseID() string { return r.licenseID }

// SerialNumber returns the serial number.
func (r ValidationResult) SerialNumber() string { return r.serialNumber }

// ProductID returns the product id.
func (r ValidationResult) ProductID() string { return r.productID }

// Edition returns the edition.
func (r ValidationResult) Edition() Edition { return r.edition }

// LicenseType returns the license type.
func (r ValidationResult) LicenseType() LicenseType { return r.licenseType }

// ExpiresAt returns a copy of the expiry instant, or nil for perpetual.
func (r ValidationResult) ExpiresAt() *time.Time { return copyTime(r.expiresAt) }

// NotBefore returns a copy of the not-before instant, or nil.
func (r ValidationResult) NotBefore() *time.Time { return copyTime(r.notBefore) }

// GraceUntil returns a copy of the grace-period end, or nil.
func (r ValidationResult) GraceUntil() *time.Time { return copyTime(r.graceUntil) }

// CheckedAt returns when validation was performed (trusted time).
func (r ValidationResult) CheckedAt() time.Time { return r.checkedAt }

// Features returns a sorted copy of the effective feature list.
func (r ValidationResult) Features() []string {
	out := make([]string, len(r.features))
	copy(out, r.features)
	return out
}

// HasFeature reports whether the given feature is granted. Only meaningful when
// the license is Valid().
//
// Invariant: r.features is always sorted (it originates from EffectiveFeatures,
// which sorts its output). This binary search relies on that ordering; do not
// populate r.features from an unsorted source.
func (r ValidationResult) HasFeature(name string) bool {
	i := sort.SearchStrings(r.features, name)
	return i < len(r.features) && r.features[i] == name
}

// RequireFeature returns nil when the feature is granted, or a *Error with
// CodeFeatureDenied otherwise. It is a convenience for gating code paths:
//
//	if err := res.RequireFeature("api"); err != nil { return err }
//
// A feature is never considered granted on a non-Valid() result.
func (r ValidationResult) RequireFeature(name string) error {
	if !r.Valid() {
		return newError(CodeFeatureDenied, "license not valid", nil)
	}
	if r.HasFeature(name) {
		return nil
	}
	return newError(CodeFeatureDenied, "feature not granted: "+name, nil)
}

// GetLimit returns the numeric limit for key and whether it was set. It is an
// alias of Limit provided to match the requirement's naming; prefer whichever
// reads better at the call site.
func (r ValidationResult) GetLimit(key string) (int64, bool) { return r.Limit(key) }

// CheckLimit returns nil when `current` is within the licensed limit for `key`,
// or a *Error with CodeLimitExceeded when it is exceeded.
//
// MISUSE WARNING (#13) — Missing-key policy: if the license does not declare
// `key`, the resource is treated as UNLIMITED and CheckLimit returns nil. This
// is intentional so that adding a new metered resource does not retroactively
// lock out existing licenses that predate it; issuers must set a limit to
// enforce a cap.
//
// The danger: a TYPO in `key` (e.g. "seat" vs "seats") silently matches no
// declared limit and therefore returns nil (unlimited) — it does NOT error and
// does NOT enforce the intended cap. Never assume a nil return means "within a
// configured limit"; it can also mean "no such limit was declared". If a caller
// needs to distinguish "unlimited/undeclared" from "explicitly limited", it
// must consult Limit(key)/GetLimit(key) (which reports the `ok` flag) BEFORE
// relying on CheckLimit for enforcement. Use a fixed, reviewed set of limit
// keys shared between issuer and client to avoid silent typos.
//
// A non-Valid() result denies everything (returns CodeLimitExceeded).
func (r ValidationResult) CheckLimit(key string, current int64) error {
	if !r.Valid() {
		return newError(CodeLimitExceeded, "license not valid", nil)
	}
	limit, ok := r.limits[key]
	if !ok {
		// No declared limit -> unlimited (see doc comment).
		return nil
	}
	if current > limit {
		return newError(CodeLimitExceeded, "limit exceeded for "+key, nil)
	}
	return nil
}

// GetEdition returns the edition (alias of Edition for requirement parity).
func (r ValidationResult) GetEdition() Edition { return r.edition }

// GetExpiration returns a copy of the expiry instant, or nil for perpetual
// (lifetime) licenses. Alias of ExpiresAt.
func (r ValidationResult) GetExpiration() *time.Time { return copyTime(r.expiresAt) }

// PerpetualRemainingDays is the sentinel returned by GetRemainingDays for a
// perpetual (lifetime / no-expiry) license, indicating "never expires".
const PerpetualRemainingDays = -1

// GetRemainingDays returns the whole days remaining until expiry, measured from
// the time validation was performed (CheckedAt). It returns
// PerpetualRemainingDays (-1) for a perpetual license (lifetime type or no
// expiry). An already-expired license returns 0 (never negative).
func (r ValidationResult) GetRemainingDays() int {
	if r.licenseType == LicenseTypeLifetime || r.expiresAt == nil {
		return PerpetualRemainingDays
	}
	d := r.expiresAt.Sub(r.checkedAt)
	if d <= 0 {
		return 0
	}
	return int(d / (24 * time.Hour))
}

// RemainingTime returns the duration remaining until expiry, measured from
// CheckedAt. For a perpetual license it returns a very large sentinel duration;
// callers that care about perpetual should check LicenseType()/ExpiresAt()
// instead. An expired license returns 0 (never negative).
func (r ValidationResult) RemainingTime() time.Duration {
	if r.licenseType == LicenseTypeLifetime || r.expiresAt == nil {
		// Perpetual: return the maximum representable duration as a sentinel.
		return time.Duration(1<<63 - 1)
	}
	d := r.expiresAt.Sub(r.checkedAt)
	if d < 0 {
		return 0
	}
	return d
}

// KeyID returns the verified signing key id that produced this license, or ""
// if the result is invalid / was not populated.
func (r ValidationResult) KeyID() string { return r.keyID }

// DeviceMatched reports whether the running device satisfied the license's
// device binding. For licenses with device mode "none" this is true (there is
// no device constraint to fail). It is false on invalid results.
func (r ValidationResult) DeviceMatched() bool { return r.deviceMatched }

// Limit returns the numeric limit for key and whether it was set.
func (r ValidationResult) Limit(key string) (int64, bool) {
	v, ok := r.limits[key]
	return v, ok
}

// Limits returns a copy of all limits.
func (r ValidationResult) Limits() map[string]int64 {
	out := make(map[string]int64, len(r.limits))
	for k, v := range r.limits {
		out[k] = v
	}
	return out
}

func copyTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	cp := *t
	return &cp
}

// invalidResult builds a read-only invalid result carrying the failure code.
func invalidResult(code Code, checkedAt time.Time) ValidationResult {
	return ValidationResult{status: StatusInvalid, code: code, checkedAt: checkedAt}
}
