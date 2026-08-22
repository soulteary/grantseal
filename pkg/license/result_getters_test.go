package license

import (
	"testing"
	"time"
)

// TestValidationResultGetters exercises the simple read-only accessors on a
// fully-populated ValidationResult across the perpetual / expiring / grace
// states. Fields are set directly here (internal test) because there are no
// setters on the immutable result type.
func TestValidationResultGetters(t *testing.T) {
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	notBefore := now.Add(-24 * time.Hour)
	expires := now.Add(30 * 24 * time.Hour)
	grace := now.Add(37 * 24 * time.Hour)

	r := ValidationResult{
		status:       StatusValid,
		code:         CodeOK,
		licenseID:    "l1",
		serialNumber: "SN-123",
		productID:    "p1",
		edition:      EditionProfessional,
		licenseType:  LicenseTypeSubscription,
		notBefore:    &notBefore,
		expiresAt:    &expires,
		graceUntil:   &grace,
		checkedAt:    now,
	}

	if got := r.SerialNumber(); got != "SN-123" {
		t.Fatalf("SerialNumber: want SN-123, got %q", got)
	}
	if got := r.ProductID(); got != "p1" {
		t.Fatalf("ProductID: want p1, got %q", got)
	}
	if got := r.LicenseType(); got != LicenseTypeSubscription {
		t.Fatalf("LicenseType: want subscription, got %v", got)
	}
	if got := r.NotBefore(); got == nil || !got.Equal(notBefore) {
		t.Fatalf("NotBefore: want %v, got %v", notBefore, got)
	}
	if got := r.GraceUntil(); got == nil || !got.Equal(grace) {
		t.Fatalf("GraceUntil: want %v, got %v", grace, got)
	}
	if got := r.CheckedAt(); !got.Equal(now) {
		t.Fatalf("CheckedAt: want %v, got %v", now, got)
	}
	if got := r.ExpiresAt(); got == nil || !got.Equal(expires) {
		t.Fatalf("ExpiresAt: want %v, got %v", expires, got)
	}

	// Defensive-copy checks: mutating the returned pointer must not leak back.
	if nb := r.NotBefore(); nb != nil {
		*nb = nb.Add(1000 * time.Hour)
		if again := r.NotBefore(); again.Equal(*nb) {
			t.Fatal("NotBefore must return a defensive copy")
		}
	}
	if gu := r.GraceUntil(); gu != nil {
		*gu = gu.Add(1000 * time.Hour)
		if again := r.GraceUntil(); again.Equal(*gu) {
			t.Fatal("GraceUntil must return a defensive copy")
		}
	}
}

// TestValidationResultGettersNilTimes confirms the *time.Time accessors return
// nil (never panic) when the underlying instants are unset (perpetual license).
func TestValidationResultGettersNilTimes(t *testing.T) {
	r := ValidationResult{
		status:      StatusValid,
		code:        CodeOK,
		licenseType: LicenseTypeLifetime,
	}
	if r.NotBefore() != nil {
		t.Fatal("NotBefore should be nil when unset")
	}
	if r.GraceUntil() != nil {
		t.Fatal("GraceUntil should be nil when unset")
	}
	if r.ExpiresAt() != nil {
		t.Fatal("ExpiresAt should be nil for perpetual license")
	}
	if r.SerialNumber() != "" {
		t.Fatal("SerialNumber should be empty when unset")
	}
}

// TestRemainingTimeAndDays covers RemainingTime / GetRemainingDays across the
// perpetual, expiring, and already-expired states.
func TestRemainingTimeAndDays(t *testing.T) {
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)

	t.Run("perpetual_lifetime", func(t *testing.T) {
		r := ValidationResult{licenseType: LicenseTypeLifetime, checkedAt: now}
		if d := r.RemainingTime(); d != time.Duration(1<<63-1) {
			t.Fatalf("lifetime RemainingTime: want max sentinel, got %v", d)
		}
		if days := r.GetRemainingDays(); days != PerpetualRemainingDays {
			t.Fatalf("lifetime GetRemainingDays: want %d, got %d", PerpetualRemainingDays, days)
		}
	})

	t.Run("perpetual_no_expiry", func(t *testing.T) {
		// Subscription type but no expiresAt is also perpetual.
		r := ValidationResult{licenseType: LicenseTypeSubscription, checkedAt: now}
		if d := r.RemainingTime(); d != time.Duration(1<<63-1) {
			t.Fatalf("no-expiry RemainingTime: want max sentinel, got %v", d)
		}
		if days := r.GetRemainingDays(); days != PerpetualRemainingDays {
			t.Fatalf("no-expiry GetRemainingDays: want %d, got %d", PerpetualRemainingDays, days)
		}
	})

	t.Run("expiring", func(t *testing.T) {
		exp := now.Add(10*24*time.Hour + 5*time.Hour)
		r := ValidationResult{licenseType: LicenseTypeSubscription, expiresAt: &exp, checkedAt: now}
		wantDur := exp.Sub(now)
		if d := r.RemainingTime(); d != wantDur {
			t.Fatalf("expiring RemainingTime: want %v, got %v", wantDur, d)
		}
		// 10 full days (the extra 5h is truncated).
		if days := r.GetRemainingDays(); days != 10 {
			t.Fatalf("expiring GetRemainingDays: want 10, got %d", days)
		}
	})

	t.Run("expired", func(t *testing.T) {
		exp := now.Add(-24 * time.Hour)
		r := ValidationResult{licenseType: LicenseTypeSubscription, expiresAt: &exp, checkedAt: now}
		if d := r.RemainingTime(); d != 0 {
			t.Fatalf("expired RemainingTime: want 0, got %v", d)
		}
		if days := r.GetRemainingDays(); days != 0 {
			t.Fatalf("expired GetRemainingDays: want 0, got %d", days)
		}
	})
}

// TestCheckLimitBranches covers CheckLimit's undeclared-key (unlimited),
// over-limit, within-limit, and non-Valid paths.
func TestCheckLimitBranches(t *testing.T) {
	valid := ValidationResult{status: StatusValid, limits: map[string]int64{"seats": 10}}
	invalid := ValidationResult{status: StatusInvalid, limits: map[string]int64{"seats": 10}}

	if err := valid.CheckLimit("undeclared", 999); err != nil {
		t.Fatalf("undeclared key should be unlimited (nil), got %v", err)
	}
	if err := valid.CheckLimit("seats", 10); err != nil {
		t.Fatalf("within limit should pass, got %v", err)
	}
	if err := valid.CheckLimit("seats", 11); CodeOf(err) != CodeLimitExceeded {
		t.Fatalf("over limit: want CodeLimitExceeded, got %v", err)
	}
	if err := invalid.CheckLimit("seats", 0); CodeOf(err) != CodeLimitExceeded {
		t.Fatalf("non-valid result: want CodeLimitExceeded, got %v", err)
	}
}

// TestCheckLimitStrictBranches covers CheckLimitStrict, including the
// CodeLimitRequired branch for an undeclared key.
func TestCheckLimitStrictBranches(t *testing.T) {
	valid := ValidationResult{status: StatusValid, limits: map[string]int64{"seats": 10}}
	invalid := ValidationResult{status: StatusInvalid, limits: map[string]int64{"seats": 10}}

	if err := valid.CheckLimitStrict("undeclared", 1); CodeOf(err) != CodeLimitRequired {
		t.Fatalf("undeclared key: want CodeLimitRequired, got %v", err)
	}
	if err := valid.CheckLimitStrict("seats", 10); err != nil {
		t.Fatalf("within limit should pass, got %v", err)
	}
	if err := valid.CheckLimitStrict("seats", 11); CodeOf(err) != CodeLimitExceeded {
		t.Fatalf("over limit: want CodeLimitExceeded, got %v", err)
	}
	if err := invalid.CheckLimitStrict("seats", 0); CodeOf(err) != CodeLimitExceeded {
		t.Fatalf("non-valid result: want CodeLimitExceeded, got %v", err)
	}
}

// TestRequireLimitBranches covers every distinguished RequireLimit outcome.
func TestRequireLimitBranches(t *testing.T) {
	valid := ValidationResult{status: StatusValid, limits: map[string]int64{"seats": 10}}
	invalid := ValidationResult{status: StatusInvalid, limits: map[string]int64{"seats": 10}}

	if err := invalid.RequireLimit("seats", 1); CodeOf(err) != CodeLimitRequired {
		t.Fatalf("non-valid: want CodeLimitRequired, got %v", err)
	}
	if err := valid.RequireLimit("", 1); CodeOf(err) != CodeLimitRequired {
		t.Fatalf("empty key: want CodeLimitRequired, got %v", err)
	}
	if err := valid.RequireLimit("undeclared", 1); CodeOf(err) != CodeLimitRequired {
		t.Fatalf("undeclared key: want CodeLimitRequired, got %v", err)
	}
	if err := valid.RequireLimit("seats", -1); CodeOf(err) != CodeInvalidLimits {
		t.Fatalf("negative current: want CodeInvalidLimits, got %v", err)
	}
	if err := valid.RequireLimit("seats", 11); CodeOf(err) != CodeLimitExceeded {
		t.Fatalf("over limit: want CodeLimitExceeded, got %v", err)
	}
	if err := valid.RequireLimit("seats", 10); err != nil {
		t.Fatalf("within cap should pass, got %v", err)
	}
}

// TestRequireFeatureBranches covers RequireFeature's non-Valid, granted, and
// not-granted paths.
func TestRequireFeatureBranches(t *testing.T) {
	// features must be sorted (HasFeature relies on binary search).
	valid := ValidationResult{status: StatusValid, features: []string{"api", "core"}}
	invalid := ValidationResult{status: StatusInvalid, features: []string{"api", "core"}}

	if err := valid.RequireFeature("api"); err != nil {
		t.Fatalf("granted feature should pass, got %v", err)
	}
	if err := valid.RequireFeature("missing"); CodeOf(err) != CodeFeatureUnavailable {
		t.Fatalf("ungranted feature: want CodeFeatureUnavailable, got %v", err)
	}
	if err := invalid.RequireFeature("api"); CodeOf(err) != CodeFeatureUnavailable {
		t.Fatalf("non-valid result: want CodeFeatureUnavailable, got %v", err)
	}
	// The emitted wire code must be the single canonical string, reachable via
	// either Go identifier (CodeFeatureDenied is an alias).
	if got := CodeOf(valid.RequireFeature("missing")); got != "LICENSE_FEATURE_UNAVAILABLE" {
		t.Fatalf("wire code must be LICENSE_FEATURE_UNAVAILABLE, got %s", got)
	}
	if CodeFeatureDenied != CodeFeatureUnavailable {
		t.Fatal("CodeFeatureDenied must alias CodeFeatureUnavailable")
	}
}
