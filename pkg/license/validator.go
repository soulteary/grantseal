package license

import (
	"crypto/subtle"
	"time"
)

// ValidationContext supplies the runtime facts needed to validate a license:
// the expected product, the running product version, the device fingerprint,
// and an optional revocation provider. All fields are optional except where a
// license's own constraints require them.
type ValidationContext struct {
	// ProductID, if non-empty, must match the license's product_id.
	ProductID string
	// ProductVersion, if non-empty, is checked against the version constraint.
	ProductVersion string
	// DeviceFingerprint is the current device fingerprint (e.g. "sha256:...").
	// Required when the license binds to devices (mode != none).
	DeviceFingerprint string
	// Revocation, if set, is consulted for license_id revocation.
	Revocation RevocationProvider
	// ClockSkew tolerated in time comparisons (defaults to DefaultClockSkew).
	ClockSkew time.Duration
}

// validate runs the full policy pipeline against an already cryptographically
// verified payload. It is fail-closed and never panics. `now` is trusted time.
// `keyID` is the verified envelope key id, recorded into the result.
func validate(p *Payload, now time.Time, keyID string, ctx ValidationContext) ValidationResult {
	skew := ctx.ClockSkew
	if skew <= 0 {
		skew = DefaultClockSkew
	}

	// Static value validation (enums, limits, required fields, license_type
	// time semantics).
	if err := p.validateStatic(); err != nil {
		return invalidResult(CodeOf(err), now)
	}

	// Revocation by license_id.
	if ctx.Revocation != nil && ctx.Revocation.IsRevoked(p.LicenseID) {
		return invalidResult(CodeRevoked, now)
	}

	// Product match.
	if ctx.ProductID != "" && p.ProductID != ctx.ProductID {
		return invalidResult(CodeProductMismatch, now)
	}

	// Time window: not_before.
	if p.NotBefore != nil && now.Add(skew).Before(*p.NotBefore) {
		return invalidResult(CodeNotYetValid, now)
	}

	// Version constraint.
	if code := checkVersion(p, ctx.ProductVersion, now, skew); code != CodeOK {
		return invalidResult(code, now)
	}

	// Device binding.
	if code := checkDevice(p, ctx.DeviceFingerprint); code != CodeOK {
		return invalidResult(code, now)
	}
	// Record whether the running device matched the license binding. For
	// mode "none" there is no device constraint, so this is reported true.
	deviceMatched := true

	// Expiry + grace handling determines valid vs grace vs expired.
	//
	// license_type governs whether expiry is even considered:
	//   - Lifetime: perpetual. validateStatic already rejects a lifetime
	//     license that carries expires_at, but we defensively skip the expiry
	//     branch here too so a lifetime license can never be expired.
	//   - Trial / Subscription: expires_at is mandatory (enforced statically)
	//     and is evaluated normally below.
	status := StatusValid
	var graceUntil *time.Time
	if p.LicenseType != LicenseTypeLifetime && p.ExpiresAt != nil {
		exp := *p.ExpiresAt
		if now.Add(-skew).After(exp) {
			// Past hard expiry; check grace window.
			grace := exp.Add(time.Duration(p.GracePeriodDays) * 24 * time.Hour)
			gu := grace
			graceUntil = &gu
			if p.GracePeriodDays > 0 && !now.Add(-skew).After(grace) {
				status = StatusGrace
			} else {
				return invalidResult(CodeExpired, now)
			}
		} else if p.GracePeriodDays > 0 {
			grace := exp.Add(time.Duration(p.GracePeriodDays) * 24 * time.Hour)
			graceUntil = &grace
		}
	}

	feats := EffectiveFeatures(p)
	limits := make(map[string]int64, len(p.Limits))
	for k, v := range p.Limits {
		limits[k] = v
	}

	return ValidationResult{
		status:        status,
		code:          CodeOK,
		licenseID:     p.LicenseID,
		serialNumber:  p.SerialNumber,
		productID:     p.ProductID,
		edition:       p.Edition,
		licenseType:   p.LicenseType,
		notBefore:     copyTime(p.NotBefore),
		expiresAt:     copyTime(p.ExpiresAt),
		graceUntil:    graceUntil,
		features:      feats,
		limits:        limits,
		checkedAt:     now,
		keyID:         keyID,
		deviceMatched: deviceMatched,
	}
}

// checkVersion validates the running product version against the constraint.
//
// MaintenanceUntil models a "maintenance window" (common in perpetual/lifetime
// licensing): the customer may run any covered version released while their
// maintenance was active, but versions released after maintenance lapses are
// not covered. Because we cannot carry per-release dates offline, the boundary
// between "old, covered" and "new, uncovered" builds is expressed as an
// explicit version ceiling, CoveredMaxVersion:
//   - While now is within the maintenance window, the ceiling is not applied.
//   - Once now is past MaintenanceUntil, a running version greater than
//     CoveredMaxVersion is treated as an uncovered newer release and rejected,
//     while versions <= CoveredMaxVersion keep working forever.
//
// Backward compatibility (licenses without CoveredMaxVersion): fall back to the
// legacy approximation that used MinVersion as the maintained baseline — once
// maintenance lapses, a running version strictly greater than MinVersion is
// rejected while versions <= MinVersion keep working. If MinVersion is also
// empty, the maintenance gate is skipped entirely so old licenses are never
// falsely rejected.
//
// Fail-closed semantics:
//   - If the license declares any version constraint (MinVersion, MaxVersion,
//     MaintenanceUntil, or CoveredMaxVersion) but the caller supplies no running
//     version, the license is rejected (CodeVersionUnsupported): we cannot prove
//     the running build is covered, so we refuse rather than pass silently.
//   - If a running version is supplied but cannot be strictly parsed, it is
//     rejected: ambiguous input is never treated as satisfying the constraint.
//   - Constraint-side version strings (MinVersion, MaxVersion, CoveredMaxVersion)
//     are issuer-controlled; if any engaged constraint fails to parse, the
//     license is likewise rejected rather than compared approximately.
//   - When the license declares no version constraint at all, this gate is a
//     no-op and returns CodeOK regardless of the running version.
//
// Limitations of this offline approximation:
//   - It cannot distinguish two versions released on different dates that share
//     the same version string; the version ceiling is the sole covered bound.
func checkVersion(p *Payload, version string, now time.Time, skew time.Duration) Code {
	vc := p.VersionConstraint
	hasConstraint := vc.MinVersion != "" || vc.MaxVersion != "" ||
		vc.MaintenanceUntil != nil || vc.CoveredMaxVersion != ""
	if !hasConstraint {
		return CodeOK
	}
	// Fail-closed: a declared constraint requires a running version to evaluate.
	if version == "" {
		return CodeVersionUnsupported
	}
	if vc.MinVersion != "" {
		cmp, ok := compareVersionsStrict(version, vc.MinVersion)
		if !ok || cmp < 0 {
			return CodeVersionUnsupported
		}
	}
	if vc.MaxVersion != "" {
		cmp, ok := compareVersionsStrict(version, vc.MaxVersion)
		if !ok || cmp > 0 {
			return CodeVersionUnsupported
		}
	}
	// Maintenance gate: only engages with a maintenance deadline once that
	// deadline has lapsed (accounting for skew).
	if vc.MaintenanceUntil != nil && now.Add(-skew).After(*vc.MaintenanceUntil) {
		if vc.CoveredMaxVersion != "" {
			// Explicit ceiling: builds newer than the covered maximum are not
			// covered once maintenance has lapsed.
			cmp, ok := compareVersionsStrict(version, vc.CoveredMaxVersion)
			if !ok || cmp > 0 {
				return CodeVersionUnsupported
			}
		} else if vc.MinVersion != "" {
			// Compatibility path for licenses issued before CoveredMaxVersion
			// existed: use MinVersion as the maintained baseline. Builds newer
			// than the baseline are uncovered after maintenance lapses.
			cmp, ok := compareVersionsStrict(version, vc.MinVersion)
			if !ok || cmp > 0 {
				return CodeVersionUnsupported
			}
		}
		// If neither CoveredMaxVersion nor MinVersion is set, there is no
		// baseline to compare against, so the maintenance gate is skipped
		// rather than rejecting an otherwise valid license.
	}
	return CodeOK
}

// checkDevice validates the device binding using constant-time comparison.
func checkDevice(p *Payload, fingerprint string) Code {
	switch p.DeviceBinding.Mode {
	case DeviceModeNone:
		return CodeOK
	case DeviceModeSingle, DeviceModeMulti:
		if fingerprint == "" {
			return CodeDeviceMismatch
		}
		for _, id := range p.DeviceBinding.DeviceIDs {
			if constantTimeEqualString(id, fingerprint) {
				return CodeOK
			}
		}
		return CodeDeviceMismatch
	default:
		return CodeInvalidEnum
	}
}

// constantTimeEqualString compares two strings without early exit on length or
// content, mitigating timing side-channels on sensitive identifiers.
func constantTimeEqualString(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
