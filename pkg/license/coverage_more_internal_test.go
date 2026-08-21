package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

// errClock is a TrustedTimeProvider that always fails, used to drive the
// clock-unavailable degradation/fail-closed branches on Manager.
type errClock struct{}

func (errClock) Now() (time.Time, error) { return time.Time{}, errors.New("clock unavailable") }

// internalSigner is a minimal in-package signer built directly on ed25519 so
// these internal tests can produce authentic envelopes without importing the
// issuer package (which would create an import cycle).
type internalSigner struct {
	keyID string
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
}

func testInternalSigner(t *testing.T, keyID string) (*internalSigner, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &internalSigner{keyID: keyID, priv: priv, pub: pub}, pub
}

func ringWithInternal(t *testing.T, keyID string, pub ed25519.PublicKey) *KeyRing {
	t.Helper()
	r := NewKeyRing()
	if err := r.AddPublicKey(keyID, pub); err != nil {
		t.Fatalf("add pubkey: %v", err)
	}
	return r
}

// basePayloadFor returns a minimally valid lifetime payload for the product,
// stamped with the signer's key_id.
func basePayloadFor(keyID, product string) *Payload {
	return &Payload{
		SchemaVersion: SchemaVersion,
		LicenseID:     "lic_1",
		SerialNumber:  "SER-1",
		ProductID:     product,
		CustomerID:    "c1",
		KeyID:         keyID,
		Edition:       EditionBasic,
		LicenseType:   LicenseTypeLifetime,
		IssuedAt:      time.Now().UTC(),
		DeviceBinding: DeviceBinding{Mode: DeviceModeNone},
	}
}

func issueInternalEnvelope(t *testing.T, s *internalSigner, product string) *Envelope {
	t.Helper()
	p := basePayloadFor(s.keyID, product)
	canonical, err := CanonicalBytes(p)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	sig := ed25519.Sign(s.priv, licenseSigningInput(canonical))
	return NewEnvelope(AlgorithmEd25519, s.keyID, canonical, sig)
}

func issueInternal(t *testing.T, s *internalSigner, product string) []byte {
	t.Helper()
	data, err := issueInternalEnvelope(t, s, product).MarshalJSONIndent()
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return data
}

// ---------------------------------------------------------------------------
// errors.go: Error(), Unwrap(), Is(), CodeOf edge arms
// ---------------------------------------------------------------------------

func TestErrorErrorString(t *testing.T) {
	var nilErr *Error
	if got := nilErr.Error(); got != "<nil license error>" {
		t.Fatalf("nil Error(): want <nil license error>, got %q", got)
	}
	codeOnly := &Error{Code: CodeMalformed}
	if got := codeOnly.Error(); got != string(CodeMalformed) {
		t.Fatalf("code-only Error(): want %q, got %q", CodeMalformed, got)
	}
	withMsg := &Error{Code: CodeMalformed, Message: "bad"}
	if got := withMsg.Error(); got != string(CodeMalformed)+": bad" {
		t.Fatalf("with-msg Error(): got %q", got)
	}
}

func TestErrorUnwrap(t *testing.T) {
	cause := errors.New("root cause")
	e := newError(CodeMalformed, "wrap", cause)
	if !errors.Is(e, cause) {
		t.Fatal("errors.Is should find the wrapped cause via Unwrap")
	}
	noCause := newError(CodeMalformed, "no cause", nil)
	if noCause.Unwrap() != nil {
		t.Fatal("Unwrap of a causeless error should be nil")
	}
}

func TestErrorIs(t *testing.T) {
	e := newError(CodeExpired, "expired", errors.New("x"))
	if !errors.Is(e, ErrExpired) {
		t.Fatal("errors.Is should match sentinel by Code")
	}
	if errors.Is(e, ErrRevoked) {
		t.Fatal("errors.Is must not match a different Code")
	}
	// Is against a non-*Error target returns false.
	if e.Is(errors.New("plain")) {
		t.Fatal("Is against non-*Error target must be false")
	}
}

func TestCodeOfNonLicenseError(t *testing.T) {
	if got := CodeOf(errors.New("plain")); got != "" {
		t.Fatalf("CodeOf(plain): want empty, got %q", got)
	}
	if got := CodeOf(nil); got != "" {
		t.Fatalf("CodeOf(nil): want empty, got %q", got)
	}
	if got := CodeOf(newError(CodeExpired, "", nil)); got != CodeExpired {
		t.Fatalf("CodeOf(*Error): want %s, got %s", CodeExpired, got)
	}
}

// ---------------------------------------------------------------------------
// model.go: enum Valid() default arms and validate* error arms
// ---------------------------------------------------------------------------

func TestEnumValidDefaultArms(t *testing.T) {
	if LicenseType("bogus").Valid() {
		t.Fatal("unknown LicenseType must be invalid")
	}
	if DeviceMode("bogus").Valid() {
		t.Fatal("unknown DeviceMode must be invalid")
	}
	if Edition("bogus").Valid() {
		t.Fatal("unknown Edition must be invalid")
	}
	if Algorithm("RSA").Valid() {
		t.Fatal("non-Ed25519 algorithm must be invalid")
	}
}

func TestValidateStaticNilPayload(t *testing.T) {
	var p *Payload
	if err := p.validateStatic(); CodeOf(err) != CodeMalformed {
		t.Fatalf("nil payload: want CodeMalformed, got %s", CodeOf(err))
	}
}

func TestValidateIdentityArms(t *testing.T) {
	t.Run("bad_schema", func(t *testing.T) {
		p := basePayload()
		p.SchemaVersion = 999
		if err := p.validateStatic(); CodeOf(err) != CodeUnsupportedSchema {
			t.Fatalf("want CodeUnsupportedSchema, got %s", CodeOf(err))
		}
	})
	t.Run("missing_ids", func(t *testing.T) {
		p := basePayload()
		p.LicenseID = ""
		if err := p.validateStatic(); CodeOf(err) != CodeMalformed {
			t.Fatalf("want CodeMalformed, got %s", CodeOf(err))
		}
	})
	t.Run("zero_issued_at", func(t *testing.T) {
		p := basePayload()
		p.IssuedAt = time.Time{}
		if err := p.validateStatic(); CodeOf(err) != CodeMalformed {
			t.Fatalf("want CodeMalformed, got %s", CodeOf(err))
		}
	})
}

func TestValidateEnumsArms(t *testing.T) {
	t.Run("bad_edition", func(t *testing.T) {
		p := basePayload()
		p.Edition = "bogus"
		if err := p.validateStatic(); CodeOf(err) != CodeInvalidEnum {
			t.Fatalf("want CodeInvalidEnum, got %s", CodeOf(err))
		}
	})
	t.Run("bad_license_type", func(t *testing.T) {
		p := basePayload()
		p.LicenseType = "bogus"
		if err := p.validateStatic(); CodeOf(err) != CodeInvalidEnum {
			t.Fatalf("want CodeInvalidEnum, got %s", CodeOf(err))
		}
	})
	t.Run("bad_device_mode", func(t *testing.T) {
		p := basePayload()
		p.DeviceBinding.Mode = "bogus"
		if err := p.validateStatic(); CodeOf(err) != CodeInvalidEnum {
			t.Fatalf("want CodeInvalidEnum, got %s", CodeOf(err))
		}
	})
	t.Run("device_binding_missing_ids", func(t *testing.T) {
		p := basePayload()
		p.DeviceBinding = DeviceBinding{Mode: DeviceModeSingle}
		if err := p.validateStatic(); CodeOf(err) != CodeMalformed {
			t.Fatalf("want CodeMalformed, got %s", CodeOf(err))
		}
	})
}

func TestValidateLimitsRangeArms(t *testing.T) {
	t.Run("empty_key", func(t *testing.T) {
		p := basePayload()
		p.Limits = map[string]int64{"": 1}
		if err := p.validateStatic(); CodeOf(err) != CodeInvalidLimits {
			t.Fatalf("want CodeInvalidLimits, got %s", CodeOf(err))
		}
	})
	t.Run("negative", func(t *testing.T) {
		p := basePayload()
		p.Limits = map[string]int64{"seats": -1}
		if err := p.validateStatic(); CodeOf(err) != CodeInvalidLimits {
			t.Fatalf("want CodeInvalidLimits, got %s", CodeOf(err))
		}
	})
	t.Run("over_max", func(t *testing.T) {
		p := basePayload()
		p.Limits = map[string]int64{"seats": maxLimitValue + 1}
		if err := p.validateStatic(); CodeOf(err) != CodeInvalidLimits {
			t.Fatalf("want CodeInvalidLimits, got %s", CodeOf(err))
		}
	})
	t.Run("grace_out_of_range", func(t *testing.T) {
		p := basePayload()
		p.GracePeriodDays = -1
		if err := p.validateStatic(); CodeOf(err) != CodeInvalidLimits {
			t.Fatalf("want CodeInvalidLimits, got %s", CodeOf(err))
		}
	})
}

func TestValidateTimeSemanticsArms(t *testing.T) {
	now := time.Now().UTC()
	t.Run("expires_before_not_before", func(t *testing.T) {
		p := basePayload()
		nb := now.Add(48 * time.Hour)
		exp := now.Add(24 * time.Hour)
		p.NotBefore = &nb
		p.ExpiresAt = &exp
		if err := p.validateStatic(); CodeOf(err) != CodeMalformed {
			t.Fatalf("want CodeMalformed, got %s", CodeOf(err))
		}
	})
	t.Run("trial_requires_expiry", func(t *testing.T) {
		p := basePayload()
		p.LicenseType = LicenseTypeTrial
		p.ExpiresAt = nil
		if err := p.validateStatic(); CodeOf(err) != CodeMalformed {
			t.Fatalf("want CodeMalformed, got %s", CodeOf(err))
		}
	})
	t.Run("lifetime_must_not_carry_expiry", func(t *testing.T) {
		p := basePayload()
		p.LicenseType = LicenseTypeLifetime
		exp := now.Add(24 * time.Hour)
		p.ExpiresAt = &exp
		if err := p.validateStatic(); CodeOf(err) != CodeMalformed {
			t.Fatalf("want CodeMalformed, got %s", CodeOf(err))
		}
	})
	t.Run("expires_before_issued", func(t *testing.T) {
		p := basePayload()
		p.IssuedAt = now
		exp := now.Add(-24 * time.Hour)
		p.ExpiresAt = &exp
		if err := p.validateStatic(); CodeOf(err) != CodeMalformed {
			t.Fatalf("want CodeMalformed, got %s", CodeOf(err))
		}
	})
	t.Run("not_before_before_issued", func(t *testing.T) {
		p := basePayload()
		p.IssuedAt = now
		nb := now.Add(-24 * time.Hour)
		p.NotBefore = &nb
		if err := p.validateStatic(); CodeOf(err) != CodeMalformed {
			t.Fatalf("want CodeMalformed, got %s", CodeOf(err))
		}
	})
}

// ---------------------------------------------------------------------------
// manager.go: WithClockSkew ignore-arm, clockSkewDefault env arm, clock-unavailable
// degradation on Inspect/CachedResult, and Validate fail-closed on bad clock.
// ---------------------------------------------------------------------------

func TestWithClockSkewIgnoresNonPositive(t *testing.T) {
	m := NewManager(NewKeyRing(), WithClockSkew(-time.Second))
	if m.skew != clockSkewDefault() {
		t.Fatalf("non-positive skew should be ignored, got %v", m.skew)
	}
	m2 := NewManager(NewKeyRing(), WithClockSkew(42*time.Second))
	if m2.skew != 42*time.Second {
		t.Fatalf("positive skew should apply, got %v", m2.skew)
	}
}

func TestClockSkewDefaultEnv(t *testing.T) {
	t.Setenv(clockSkewEnvVar, "30s")
	if got := clockSkewDefault(); got != 30*time.Second {
		t.Fatalf("env skew: want 30s, got %v", got)
	}
	t.Setenv(clockSkewEnvVar, "not-a-duration")
	if got := clockSkewDefault(); got != DefaultClockSkew {
		t.Fatalf("invalid env skew should fall back to default, got %v", got)
	}
	t.Setenv(clockSkewEnvVar, "-5s")
	if got := clockSkewDefault(); got != DefaultClockSkew {
		t.Fatalf("non-positive env skew should fall back to default, got %v", got)
	}
}

func TestValidateFailsClosedOnClockError(t *testing.T) {
	m := NewManager(NewKeyRing(), WithClock(errClock{}), WithUnscopedProductValidation())
	res, err := m.Validate([]byte("{}"), ValidationContext{})
	if CodeOf(err) != CodeClockRollback {
		t.Fatalf("clock error: want CodeClockRollback, got %s", CodeOf(err))
	}
	if res.Valid() {
		t.Fatal("clock error must not produce a valid result")
	}
}

func TestInspectDegradesOnClockError(t *testing.T) {
	// Inspect degrades to wall clock when the trusted clock fails, then fails on
	// the empty envelope parse (proving it reached ParseEnvelope past the clock).
	m := NewManager(NewKeyRing(), WithClock(errClock{}))
	if _, err := m.Inspect([]byte("")); CodeOf(err) != CodeMalformed {
		t.Fatalf("Inspect empty data: want CodeMalformed, got %s", CodeOf(err))
	}
}

func TestInspectParseAndVerifyErrors(t *testing.T) {
	s, pub := testInternalSigner(t, "k1")
	m := NewManager(ringWithInternal(t, "k1", pub))
	// Bad envelope bytes -> parse error.
	if _, err := m.Inspect([]byte(`{"algorithm":"Ed25519"}`)); CodeOf(err) != CodeMalformed {
		t.Fatalf("Inspect malformed envelope: want CodeMalformed, got %s", CodeOf(err))
	}
	// A valid envelope but signed by an unknown key -> verify error.
	_ = s
	env := issueInternal(t, s, "acme")
	m2 := NewManager(NewKeyRing()) // empty ring: key unknown
	if _, err := m2.Inspect(env); CodeOf(err) != CodeKeyUnknown {
		t.Fatalf("Inspect unknown key: want CodeKeyUnknown, got %s", CodeOf(err))
	}
}

func TestCachedResultClockDegradationAndStale(t *testing.T) {
	// A cached result with a time-based expiry in the past becomes stale.
	m := NewManager(NewKeyRing(), WithClock(FixedClock{T: time.Now().UTC()}))
	past := time.Now().UTC().Add(-time.Hour)
	m.cached = &cachedResult{result: ValidationResult{status: StatusValid}, expiresAt: past}
	if _, ok := m.CachedResult(); ok {
		t.Fatal("expired cache entry should be reported stale")
	}
	// With a failing clock, CachedResult degrades to wall clock (still stale here).
	m.clock = errClock{}
	m.cached = &cachedResult{result: ValidationResult{status: StatusValid}, expiresAt: past}
	if _, ok := m.CachedResult(); ok {
		t.Fatal("expired cache entry (degraded clock) should be reported stale")
	}
	// A fresh (future) entry is returned.
	m.clock = FixedClock{T: time.Now().UTC()}
	future := time.Now().UTC().Add(time.Hour)
	m.cached = &cachedResult{result: ValidationResult{status: StatusValid}, expiresAt: future}
	if _, ok := m.CachedResult(); !ok {
		t.Fatal("fresh cache entry should be returned")
	}
}

// ---------------------------------------------------------------------------
// verifier.go: nil-verifier, nil-ring, nil-envelope, bad sig length, keyID mismatch
// ---------------------------------------------------------------------------

func TestVerifyNilAndConfigErrors(t *testing.T) {
	var v *Verifier
	if _, err := v.Verify(nil, time.Now()); CodeOf(err) != CodeSignatureInvalid {
		t.Fatalf("nil verifier: want CodeSignatureInvalid, got %s", CodeOf(err))
	}
	vNoRing := &Verifier{}
	if _, err := vNoRing.Verify(nil, time.Now()); CodeOf(err) != CodeSignatureInvalid {
		t.Fatalf("nil ring: want CodeSignatureInvalid, got %s", CodeOf(err))
	}
	v2 := NewVerifier(NewKeyRing())
	if _, err := v2.Verify(nil, time.Now()); CodeOf(err) != CodeMalformed {
		t.Fatalf("nil envelope: want CodeMalformed, got %s", CodeOf(err))
	}
	if _, err := v2.Verify(&Envelope{Algorithm: "RSA"}, time.Now()); CodeOf(err) != CodeUnsupportedAlgorithm {
		t.Fatalf("bad alg: want CodeUnsupportedAlgorithm, got %s", CodeOf(err))
	}
}

func TestVerifyBadSignatureLength(t *testing.T) {
	s, pub := testInternalSigner(t, "k1")
	ring := ringWithInternal(t, "k1", pub)
	env := issueInternalEnvelope(t, s, "acme")
	// Replace signature with a short one.
	env.Signature = b64.EncodeToString([]byte("short"))
	if _, err := NewVerifier(ring).Verify(env, time.Now().UTC()); CodeOf(err) != CodeSignatureInvalid {
		t.Fatalf("short sig: want CodeSignatureInvalid, got %s", CodeOf(err))
	}
}

// ---------------------------------------------------------------------------
// keyring.go: CheckKeyPolicy revoked/disabled/window arms
// ---------------------------------------------------------------------------

func TestCheckKeyPolicyArms(t *testing.T) {
	now := time.Now().UTC()
	before := now.Add(-time.Hour)
	after := now.Add(time.Hour)
	r := NewKeyRing()

	revoked := KeyEntry{KeyID: "k", Enabled: true, Revoked: true}
	if err := r.CheckKeyPolicy(revoked, now); CodeOf(err) != CodeKeyRevoked {
		t.Fatalf("revoked: want CodeKeyRevoked, got %s", CodeOf(err))
	}
	disabled := KeyEntry{KeyID: "k", Enabled: false}
	if err := r.CheckKeyPolicy(disabled, now); CodeOf(err) != CodeKeyDisabled {
		t.Fatalf("disabled: want CodeKeyDisabled, got %s", CodeOf(err))
	}
	notYet := KeyEntry{KeyID: "k", Enabled: true, NotBefore: &after}
	if err := r.CheckKeyPolicy(notYet, now); CodeOf(err) != CodeKeyDisabled {
		t.Fatalf("not-yet-active: want CodeKeyDisabled, got %s", CodeOf(err))
	}
	past := KeyEntry{KeyID: "k", Enabled: true, NotAfter: &before}
	if err := r.CheckKeyPolicy(past, now); CodeOf(err) != CodeKeyDisabled {
		t.Fatalf("past-window: want CodeKeyDisabled, got %s", CodeOf(err))
	}
	ok := KeyEntry{KeyID: "k", Enabled: true, NotBefore: &before, NotAfter: &after}
	if err := r.CheckKeyPolicy(ok, now); err != nil {
		t.Fatalf("in-window key should pass, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// strictjson.go: trailing token, bare '[' delimiter, non-string key, array-close
// ---------------------------------------------------------------------------

func TestStrictJSONArmsDirect(t *testing.T) {
	// bare array -> walkArray path with a scalar element (no dup keys).
	var dst any
	if err := DecodeStrictJSON([]byte(`[1,2,3]`), &dst, 0); err != nil {
		t.Fatalf("valid array should decode: %v", err)
	}
	// object nested in array exercising walkArray -> walkObject.
	if err := DecodeStrictJSON([]byte(`[{"a":1},{"b":2}]`), &dst, 0); err != nil {
		t.Fatalf("array of objects should decode: %v", err)
	}
	// non-string object key is impossible in JSON, but a malformed key stream via
	// truncation triggers the scan-object-key error arm.
	if err := DecodeStrictJSON([]byte(`{"a":1,`), &dst, 0); CodeOf(err) != CodeMalformed {
		t.Fatalf("truncated object: want CodeMalformed, got %s", CodeOf(err))
	}
	// duplicate key nested inside an array element.
	if err := DecodeStrictJSON([]byte(`[{"a":1,"a":2}]`), &dst, 0); CodeOf(err) != CodeMalformed {
		t.Fatalf("nested dup key: want CodeMalformed, got %s", CodeOf(err))
	}
}
