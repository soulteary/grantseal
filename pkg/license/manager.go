package license

import (
	"os"
	"sync"
	"time"

	"github.com/soulteary/grantseal/pkg/fingerprint"
)

// Manager is the client-facing facade for loading and validating licenses. It
// ties together the KeyRing, Verifier, TrustedTimeProvider, optional
// anti-rollback store and revocation provider. It is safe for concurrent use.
type Manager struct {
	verifier   *Verifier
	clock      TrustedTimeProvider
	rollback   *RollbackStore
	revocation RevocationProvider
	skew       time.Duration
	// unscopedProduct, when true, permits Validate with an empty
	// ValidationContext.ProductID (legacy behavior). Default false: validation
	// must be scoped to a product or it fails closed with CodeProductRequired.
	unscopedProduct bool

	mu     sync.RWMutex
	cached *cachedResult
}

type cachedResult struct {
	result    ValidationResult
	expiresAt time.Time // wall-clock instant after which the cache is stale (zero = no time-based expiry)
}

// Option configures a Manager.
type Option func(*Manager)

// WithClock sets the trusted time provider (default SystemClock). A nil
// provider is ignored (the default SystemClock is retained) rather than causing
// a later nil-dereference panic.
func WithClock(c TrustedTimeProvider) Option {
	return func(m *Manager) {
		if c != nil {
			m.clock = c
		}
	}
}

// WithRollbackStore enables anti-rollback checks using the given store. A nil
// store is ignored (anti-rollback stays disabled) rather than panicking later.
func WithRollbackStore(s *RollbackStore) Option {
	return func(m *Manager) {
		if s != nil {
			m.rollback = s
		}
	}
}

// WithRevocation sets a revocation provider consulted during validation. A nil
// provider is ignored.
func WithRevocation(r RevocationProvider) Option {
	return func(m *Manager) {
		if r != nil {
			m.revocation = r
		}
	}
}

// WithClockSkew overrides the tolerated clock skew (default DefaultClockSkew).
// Non-positive values are ignored (the default/env-derived skew is retained).
func WithClockSkew(d time.Duration) Option {
	return func(m *Manager) {
		if d > 0 {
			m.skew = d
		}
	}
}

// WithUnscopedProductValidation OPTS OUT of the default requirement that every
// validation be scoped to a product (a non-empty ValidationContext.ProductID).
//
// DANGER: with this option, Validate will accept a license regardless of which
// product it was issued for when the caller supplies no ProductID. Only use it
// for single-product deployments where product scoping is genuinely irrelevant,
// or diagnostic tooling. Prefer always passing ValidationContext.ProductID.
func WithUnscopedProductValidation() Option {
	return func(m *Manager) { m.unscopedProduct = true }
}

// clockSkewEnvVar lets operators tune the tolerated clock skew without code
// changes (e.g. shorter windows for reproducible demos/tests). An explicit
// WithClockSkew option still takes precedence over the environment value.
const clockSkewEnvVar = "GRANTSEAL_CLOCK_SKEW"

// NewManager builds a Manager verifying against `ring`.
func NewManager(ring *KeyRing, opts ...Option) *Manager {
	m := &Manager{
		verifier: NewVerifier(ring),
		clock:    SystemClock{},
		skew:     clockSkewDefault(),
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// clockSkewDefault returns the baseline clock skew, honoring GRANTSEAL_CLOCK_SKEW
// when it parses to a positive duration; otherwise it falls back to
// DefaultClockSkew. Invalid or non-positive values are ignored (fail-safe to
// the stricter default).
func clockSkewDefault() time.Duration {
	if v := os.Getenv(clockSkewEnvVar); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return DefaultClockSkew
}

// Validate cryptographically verifies and policy-validates raw envelope bytes.
// It returns a read-only ValidationResult. On any failure it returns an invalid
// result plus a stable *Error (fail-closed): every supported entry point
// returns an error instead of panicking (continuously fuzz/race verified in CI).
//
// Order of operations (security-relevant): the envelope is parsed and its
// signature verified BEFORE any anti-rollback state is loaded, checked or
// saved. Anti-rollback state is only advanced AFTER the license passes full
// policy validation (valid or within grace) — a malformed, forged, expired,
// revoked, product-mismatched or device-mismatched license can never pollute
// the trusted last-seen-time high-water mark nor cause a state file to be
// written from rejected data.
func (m *Manager) Validate(data []byte, ctx ValidationContext) (ValidationResult, error) {
	now, err := m.clock.Now()
	if err != nil {
		return invalidResult(CodeClockRollback, time.Now().UTC()), newError(CodeClockRollback, "trusted time unavailable", err)
	}
	now = now.UTC()

	// Fail closed when validation is not scoped to a product, unless the
	// operator explicitly opted out with WithUnscopedProductValidation.
	if ctx.ProductID == "" && !m.unscopedProduct {
		return invalidResult(CodeProductRequired, now), newError(CodeProductRequired,
			"validation must be scoped to a product (set ValidationContext.ProductID or opt out with WithUnscopedProductValidation)", nil)
	}

	// 1. Parse + cryptographically verify first (untrusted input must not
	//    touch rollback state until it is proven authentic).
	if len(data) > MaxLicenseFileSize {
		return invalidResult(CodeFileTooLarge, now), newError(CodeFileTooLarge, "license data too large", nil)
	}
	env, err := ParseEnvelope(data)
	if err != nil {
		return invalidResult(CodeOf(err), now), err
	}
	vr, err := m.verifier.Verify(env, now)
	if err != nil {
		return invalidResult(CodeOf(err), now), err
	}

	if ctx.Revocation == nil {
		ctx.Revocation = m.revocation
	}
	if ctx.ClockSkew <= 0 {
		ctx.ClockSkew = m.skew
	}

	// 2. Full policy validation on the authentic payload.
	result := validate(vr.Payload, now, vr.KeyID, ctx)
	if !result.Valid() {
		return result, newError(result.Code(), "license validation failed", nil)
	}

	// 3. Anti-rollback: only AFTER the license is proven both authentic AND
	//    valid/grace do we advance the trusted-time high-water mark. Rejected
	//    licenses never write state. Lifetime licenses are time-independent and
	//    skip anti-rollback entirely (see checkAndPersistRollback).
	if m.rollback != nil {
		if rerr := m.checkAndPersistRollback(vr.Payload, now); rerr != nil {
			return invalidResult(CodeOf(rerr), now), rerr
		}
	}

	m.storeCache(result)
	return result, nil
}

// checkAndPersistRollback advances the anti-rollback high-water mark for a
// license that has ALREADY passed authentication and full policy validation.
// It is intentionally the LAST step: rejected licenses never reach here, so a
// forged/expired/mismatched license can never advance the trusted-time mark.
//
// license_type governs whether anti-rollback applies at all:
//   - Trial / Subscription (time-limited): the high-water mark is enforced.
//     A corrupt/tampered state file is FATAL (CodeStateIntegrityFailure); we
//     never silently delete the state to bypass detection.
//   - Lifetime (perpetual, time-independent): anti-rollback DOES NOT APPLY.
//     Their authorization decision is time-independent, so we neither read,
//     write, nor reset the state file for a lifetime license. A clock rolled
//     backward cannot deny a lifetime license here — this is BY DESIGN. Do NOT
//     rely on this path to detect clock tampering for lifetime licenses.
//
// The load->check->save sequence is performed atomically under the store's
// mutex via CheckAndSave, so concurrent validations cannot lose updates or
// regress the high-water mark.
func (m *Manager) checkAndPersistRollback(p *Payload, now time.Time) error {
	if p.LicenseType == LicenseTypeLifetime {
		// Lifetime licenses are immune to anti-rollback and must not create,
		// touch, or reset the state file.
		return nil
	}
	return m.rollback.CheckAndSave(now)
}

// LoadAndValidate reads a license file from disk (enforcing the size cap) and
// validates it. Missing files map to CodeFileNotFound.
func (m *Manager) LoadAndValidate(path string, ctx ValidationContext) (ValidationResult, error) {
	now := time.Now().UTC()
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return invalidResult(CodeFileNotFound, now), newError(CodeFileNotFound, "license file not found", err)
		}
		return invalidResult(CodeMalformed, now), newError(CodeMalformed, "stat license file", err)
	}
	if fi.Size() > MaxLicenseFileSize {
		return invalidResult(CodeFileTooLarge, now), newError(CodeFileTooLarge, "license file too large", nil)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return invalidResult(CodeMalformed, now), newError(CodeMalformed, "read license file", err)
	}
	return m.Validate(data, ctx)
}

// Inspect verifies the signature and returns the decoded payload WITHOUT policy
// validation (time/device/product). Intended for diagnostics/tooling only —
// callers must not treat a successful Inspect as an authorization decision.
//
// Clock note (#9): if the trusted clock is unavailable, Inspect DEGRADES to the
// local wall clock (time.Now) purely to obtain a timestamp for key-window
// checks during signature verification. This degradation is acceptable ONLY
// because Inspect is diagnostic and never grants authorization. Do NOT copy
// this fallback into any authorization path — Validate must fail-closed
// (CodeClockRollback) when trusted time is unavailable rather than trust the
// local clock.
func (m *Manager) Inspect(data []byte) (*Payload, error) {
	now, err := m.clock.Now()
	if err != nil {
		now = time.Now().UTC()
	}
	env, err := ParseEnvelope(data)
	if err != nil {
		return nil, err
	}
	vr, err := m.verifier.Verify(env, now.UTC())
	if err != nil {
		return nil, err
	}
	return vr.Payload, nil
}

// storeCache records the most recent successful validation. The cache becomes
// stale at the earliest of the result's grace-until (if any) and expiry (if
// any); a perpetual license caches with no time-based expiry. Callers still get
// a fresh cryptographic validation on every Validate call — the cache exists so
// facade queries (CachedResult) can reflect the last good decision without
// re-reading the license file.
func (m *Manager) storeCache(r ValidationResult) {
	var exp time.Time
	if r.expiresAt != nil {
		exp = *r.expiresAt
	}
	if r.graceUntil != nil {
		// Grace end is the true "usable until" boundary when present.
		exp = *r.graceUntil
	}
	m.mu.Lock()
	m.cached = &cachedResult{result: r, expiresAt: exp}
	m.mu.Unlock()
}

// CachedResult returns the most recent successful ValidationResult and true, or
// a zero result and false when there is no fresh cached decision. A cached
// entry is considered stale (and thus not returned) once the current trusted
// time is past its usable boundary (grace-until or expiry). Perpetual licenses
// never expire from the cache. This never triggers cryptographic work.
func (m *Manager) CachedResult() (ValidationResult, bool) {
	m.mu.RLock()
	c := m.cached
	m.mu.RUnlock()
	if c == nil {
		return ValidationResult{}, false
	}
	if !c.expiresAt.IsZero() {
		now, err := m.clock.Now()
		if err != nil {
			now = time.Now().UTC()
		}
		if now.UTC().After(c.expiresAt) {
			return ValidationResult{}, false
		}
	}
	return c.result, true
}

// InvalidateCache clears any cached validation result. Call this after a
// license file changes on disk, or to force the next facade query to miss.
func (m *Manager) InvalidateCache() {
	m.mu.Lock()
	m.cached = nil
	m.mu.Unlock()
}

// GetDeviceRequestCode computes this device's human-friendly application/request
// code for the given product namespace, delegating to pkg/fingerprint. It is a
// convenience so callers can surface an activation code without importing the
// fingerprint package directly. It returns fingerprint.ErrInsufficientInfo when
// no stable hardware identifier is available.
func (m *Manager) GetDeviceRequestCode(productNamespace string) (string, error) {
	return fingerprint.RequestCode(productNamespace)
}
