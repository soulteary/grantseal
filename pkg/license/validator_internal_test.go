package license

import (
	"testing"
	"time"
)

// revokedAll is a RevocationProvider that revokes every license_id. Used to
// exercise the revocation gate's priority relative to other gates.
type revokedAll struct{}

func (revokedAll) IsRevoked(string) bool { return true }

// TestValidateGatePriority pins the fixed error-code priority order of validate:
// static → revocation → product → not_before → version → device → expiry.
//
// Each case constructs a payload/context that fails MULTIPLE gates at once and
// asserts which code wins. Splitting validate into per-gate helpers must not
// change this order, so this table is the regression guard.
func TestValidateGatePriority(t *testing.T) {
	now := time.Now().UTC()
	skew := DefaultClockSkew
	past := now.Add(-48 * time.Hour)
	future := now.Add(48 * time.Hour)

	// mutate applies test-specific modifications to a fresh base payload.
	newPayload := func(mut func(*Payload)) *Payload {
		p := basePayload()
		if mut != nil {
			mut(p)
		}
		return p
	}

	cases := []struct {
		name string
		p    *Payload
		ctx  ValidationContext
		want Code
	}{
		{
			// Static invalidity (bad schema) outranks everything, including a
			// revoking provider and a product mismatch.
			name: "static beats revocation+product",
			p: newPayload(func(p *Payload) {
				p.SchemaVersion = 999
			}),
			ctx:  ValidationContext{Revocation: revokedAll{}, ProductID: "other"},
			want: CodeUnsupportedSchema,
		},
		{
			// Revocation outranks product mismatch, not_before, version, device.
			name: "revocation beats product+notyet+version+device",
			p: newPayload(func(p *Payload) {
				p.NotBefore = &future
				p.VersionConstraint = VersionConstraint{MinVersion: "9.0.0"}
				p.DeviceBinding = DeviceBinding{Mode: DeviceModeSingle, DeviceIDs: []string{"sha256:abc"}}
			}),
			ctx: ValidationContext{
				Revocation:     revokedAll{},
				ProductID:      "other",
				ProductVersion: "1.0.0",
			},
			want: CodeRevoked,
		},
		{
			// Product mismatch outranks not_before/version/device.
			name: "product beats notyet+version+device",
			p: newPayload(func(p *Payload) {
				p.NotBefore = &future
				p.VersionConstraint = VersionConstraint{MinVersion: "9.0.0"}
				p.DeviceBinding = DeviceBinding{Mode: DeviceModeSingle, DeviceIDs: []string{"sha256:abc"}}
			}),
			ctx:  ValidationContext{ProductID: "other", ProductVersion: "1.0.0"},
			want: CodeProductMismatch,
		},
		{
			// not_before outranks version + device.
			name: "notyet beats version+device",
			p: newPayload(func(p *Payload) {
				p.NotBefore = &future
				p.VersionConstraint = VersionConstraint{MinVersion: "9.0.0"}
				p.DeviceBinding = DeviceBinding{Mode: DeviceModeSingle, DeviceIDs: []string{"sha256:abc"}}
			}),
			ctx:  ValidationContext{ProductVersion: "1.0.0"},
			want: CodeNotYetValid,
		},
		{
			// version outranks device.
			name: "version beats device",
			p: newPayload(func(p *Payload) {
				p.VersionConstraint = VersionConstraint{MinVersion: "9.0.0"}
				p.DeviceBinding = DeviceBinding{Mode: DeviceModeSingle, DeviceIDs: []string{"sha256:abc"}}
			}),
			ctx:  ValidationContext{ProductVersion: "1.0.0"},
			want: CodeVersionUnsupported,
		},
		{
			// device outranks expiry: an expired license bound to a mismatched
			// device reports the device mismatch first.
			name: "device beats expiry",
			p: newPayload(func(p *Payload) {
				p.IssuedAt = now.Add(-96 * time.Hour)
				p.ExpiresAt = &past
				p.DeviceBinding = DeviceBinding{Mode: DeviceModeSingle, DeviceIDs: []string{"sha256:abc"}}
			}),
			ctx:  ValidationContext{DeviceFingerprint: "sha256:other"},
			want: CodeDeviceMismatch,
		},
		{
			// With all higher gates passing, an expired license reports expiry.
			name: "expiry when all higher gates pass",
			p: newPayload(func(p *Payload) {
				p.IssuedAt = now.Add(-96 * time.Hour)
				p.ExpiresAt = &past
			}),
			ctx:  ValidationContext{},
			want: CodeExpired,
		},
		{
			// Fully valid payload/context yields CodeOK.
			name: "valid",
			p:    newPayload(nil),
			ctx:  ValidationContext{},
			want: CodeOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := validate(tc.p, now, "k1", tc.ctx)
			if res.code != tc.want {
				t.Fatalf("priority mismatch: want %s, got %s", tc.want, res.code)
			}
			_ = skew
		})
	}
}

// TestEvaluateExpiryTable pins the status/grace/expired resolution of
// evaluateExpiry across lifetime, no-expiry, in-window, grace-window, and
// past-grace inputs.
func TestEvaluateExpiryTable(t *testing.T) {
	now := time.Now().UTC()
	skew := time.Minute

	exp := func(d time.Duration) *time.Time { u := now.Add(d); return &u }

	cases := []struct {
		name        string
		lt          LicenseType
		expiresAt   *time.Time
		graceDays   int
		wantStatus  Status
		wantCode    Code
		wantGraceze bool // whether graceUntil should be non-nil
	}{
		{"lifetime ignores expiry", LicenseTypeLifetime, nil, 0, StatusValid, CodeOK, false},
		{"no expires_at", LicenseTypeSubscription, nil, 0, StatusValid, CodeOK, false},
		{"in window no grace", LicenseTypeSubscription, exp(24 * time.Hour), 0, StatusValid, CodeOK, false},
		{"in window with grace sets graceUntil", LicenseTypeSubscription, exp(24 * time.Hour), 7, StatusValid, CodeOK, true},
		{"expired within grace", LicenseTypeSubscription, exp(-24 * time.Hour), 7, StatusGrace, CodeOK, true},
		{"expired past grace", LicenseTypeSubscription, exp(-24 * time.Hour), 0, StatusValid, CodeExpired, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := basePayload()
			p.LicenseType = tc.lt
			p.ExpiresAt = tc.expiresAt
			p.GracePeriodDays = tc.graceDays
			status, graceUntil, code := evaluateExpiry(p, now, skew)
			if code != tc.wantCode {
				t.Fatalf("code: want %s, got %s", tc.wantCode, code)
			}
			if code == CodeOK && status != tc.wantStatus {
				t.Fatalf("status: want %v, got %v", tc.wantStatus, status)
			}
			if (graceUntil != nil) != tc.wantGraceze {
				t.Fatalf("graceUntil presence: want %v, got %v", tc.wantGraceze, graceUntil != nil)
			}
		})
	}
}
