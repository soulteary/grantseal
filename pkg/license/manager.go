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

	mu     sync.RWMutex
	cached *cachedResult
}

type cachedResult struct {
	result    ValidationResult
	expiresAt time.Time // wall-clock instant after which the cache is stale (zero = no time-based expiry)
}

// Option configures a Manager.
type Option func(*Manager)

// WithClock sets the trusted time provider (default SystemClock).
func WithClock(c TrustedTimeProvider) Option { return func(m *Manager) { m.clock = c } }

// WithRollbackStore enables anti-rollback checks using the given store.
func WithRollbackStore(s *RollbackStore) Option { return func(m *Manager) { m.rollback = s } }

// WithRevocation sets a revocation provider consulted during validation.
func WithRevocation(r RevocationProvider) Option { return func(m *Manager) { m.revocation = r } }

// WithClockSkew overrides the tolerated clock skew (default DefaultClockSkew).
func WithClockSkew(d time.Duration) Option { return func(m *Manager) { m.skew = d } }

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
// result plus a stable *Error (fail-closed). It never panics.
//
// Order of operations (security-relevant): the envelope is parsed and its
// signature verified BEFORE any anti-rollback state is loaded, checked or
// saved. This ensures malformed or forged input can never pollute the trusted
// last-seen-time high-water mark nor cause a state file to be written from
// untrusted data.
func (m *Manager) Validate(data []byte, ctx ValidationContext) (ValidationResult, error) {
	now, err := m.clock.Now()
	if err != nil {
		return invalidResult(CodeClockRollback, time.Now().UTC()), newError(CodeClockRollback, "trusted time unavailable", err)
	}
	now = now.UTC()

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

	// 2. Anti-rollback, now that we have an authentic payload (and thus its
	//    license_type). Only genuine, signed licenses affect the high-water
	//    mark or are permitted to persist state.
	if m.rollback != nil {
		if rerr := m.checkAndPersistRollback(vr.Payload, now); rerr != nil {
			return invalidResult(CodeOf(rerr), now), rerr
		}
	}

	if ctx.Revocation == nil {
		ctx.Revocation = m.revocation
	}
	if ctx.ClockSkew <= 0 {
		ctx.ClockSkew = m.skew
	}

	result := validate(vr.Payload, now, vr.KeyID, ctx)
	if !result.Valid() {
		return result, newError(result.Code(), "license validation failed", nil)
	}
	m.storeCache(result)
	return result, nil
}

// checkAndPersistRollback loads the anti-rollback state, checks for a backward
// clock jump, and persists the updated high-water mark. State-integrity
// failures are handled per license_type (fail-closed policy, #5):
//   - Trial / Subscription (time-limited): a corrupt/tampered state file is
//     FATAL (CodeStateIntegrityFailure). We never silently delete the state to
//     bypass detection.
//   - Lifetime (perpetual, time-independent): a corrupt state file is
//     tolerated. Lifetime validity does not depend on time or on the
//     high-water mark, so we start fresh rather than deny a legitimate user.
func (m *Manager) checkAndPersistRollback(p *Payload, now time.Time) error {
	prev, lerr := m.rollback.Load()
	if lerr != nil {
		if p.LicenseType == LicenseTypeLifetime {
			// Time-independent license: tolerate corrupt state and reset from a
			// clean slate. This is an explicit, documented recovery path (not a
			// silent bypass): it only applies where time integrity is
			// irrelevant to the authorization decision.
			prev = nil
		} else {
			// Fail-closed for time-limited licenses.
			return lerr
		}
	}
	next, rerr := m.rollback.CheckRollback(prev, now)
	if rerr != nil {
		return rerr
	}
	if serr := m.rollback.Save(next); serr != nil {
		return serr
	}
	return nil
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
