package license_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/soulteary/grantseal/pkg/license"
)

// 1. Issue + verify happy path.
func TestIssueAndValidate(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	data := issueBytes(t, s, baseRequest())
	mgr := newTestManager(ringWith(t, "k1", pub))
	res, err := mgr.Validate(data, license.ValidationContext{ProductID: "acme-app"})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !res.Valid() || res.Status() != license.StatusValid {
		t.Fatalf("expected valid, got %s/%s", res.Status(), res.Code())
	}
	if res.Edition() != license.EditionProfessional {
		t.Fatalf("edition mismatch: %s", res.Edition())
	}
}

// 2. Tampered payload fails signature verification.
func TestTamperedPayloadRejected(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	data := issueBytes(t, s, baseRequest())
	var env license.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the base64 payload.
	b := []byte(env.Payload)
	if b[10] == 'A' {
		b[10] = 'B'
	} else {
		b[10] = 'A'
	}
	env.Payload = string(b)
	mut, _ := json.Marshal(env)
	mgr := newTestManager(ringWith(t, "k1", pub))
	_, err := mgr.Validate(mut, license.ValidationContext{})
	if code := license.CodeOf(err); code != license.CodeSignatureInvalid && code != license.CodeMalformed {
		t.Fatalf("expected signature/malformed failure, got %s", code)
	}
}

// 3. Wrong key rejects the license.
func TestWrongKeyRejected(t *testing.T) {
	s, _ := testKeyPair(t, "k1")
	_, otherPub := testKeyPair(t, "k1")
	data := issueBytes(t, s, baseRequest())
	mgr := newTestManager(ringWith(t, "k1", otherPub))
	_, err := mgr.Validate(data, license.ValidationContext{})
	if license.CodeOf(err) != license.CodeSignatureInvalid {
		t.Fatalf("expected LICENSE_SIGNATURE_INVALID, got %s", license.CodeOf(err))
	}
}

// 4. Unknown key_id rejected.
func TestUnknownKeyIDRejected(t *testing.T) {
	s, pub := testKeyPair(t, "k2")
	data := issueBytes(t, s, baseRequest())
	// Ring only knows k1, license signed by k2.
	mgr := newTestManager(ringWith(t, "k1", pub))
	_, err := mgr.Validate(data, license.ValidationContext{})
	if license.CodeOf(err) != license.CodeKeyUnknown {
		t.Fatalf("expected LICENSE_KEY_UNKNOWN, got %s", license.CodeOf(err))
	}
}

// 5. Key rotation: old license still validates while old key remains in ring.
func TestKeyRotationOldLicenseStillValid(t *testing.T) {
	sOld, pubOld := testKeyPair(t, "k1")
	_, pubNew := testKeyPair(t, "k2")
	oldData := issueBytes(t, sOld, baseRequest())

	ring := license.NewKeyRing()
	if err := ring.AddPublicKey("k1", pubOld); err != nil {
		t.Fatal(err)
	}
	if err := ring.AddPublicKey("k2", pubNew); err != nil {
		t.Fatal(err)
	}
	mgr := newTestManager(ring)
	res, err := mgr.Validate(oldData, license.ValidationContext{})
	if err != nil || !res.Valid() {
		t.Fatalf("old license should still validate: %v code=%s", err, res.Code())
	}
}

// 6. Disabled key rejected.
func TestDisabledKeyRejected(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	data := issueBytes(t, s, baseRequest())
	ring := license.NewKeyRing()
	if err := ring.Add(license.KeyEntry{KeyID: "k1", PublicKey: pub, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	mgr := newTestManager(ring)
	_, err := mgr.Validate(data, license.ValidationContext{})
	if license.CodeOf(err) != license.CodeKeyDisabled {
		t.Fatalf("expected LICENSE_KEY_DISABLED, got %s", license.CodeOf(err))
	}
}

// 7. Revoked key rejected.
func TestRevokedKeyRejected(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	data := issueBytes(t, s, baseRequest())
	ring := license.NewKeyRing()
	if err := ring.Add(license.KeyEntry{KeyID: "k1", PublicKey: pub, Enabled: true, Revoked: true}); err != nil {
		t.Fatal(err)
	}
	mgr := newTestManager(ring)
	_, err := mgr.Validate(data, license.ValidationContext{})
	if license.CodeOf(err) != license.CodeKeyRevoked {
		t.Fatalf("expected LICENSE_KEY_REVOKED, got %s", license.CodeOf(err))
	}
}

// 8. key_id substitution (payload vs envelope mismatch) rejected.
func TestKeyIDMismatchRejected(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	data := issueBytes(t, s, baseRequest())
	var env license.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	// Change only the envelope key_id, keep valid signature over payload with k1.
	env.KeyID = "k9"
	mut, _ := json.Marshal(env)
	ring := license.NewKeyRing()
	// Register the same public key under k9 so the signature would verify.
	if err := ring.AddPublicKey("k9", pub); err != nil {
		t.Fatal(err)
	}
	mgr := newTestManager(ring)
	_, err := mgr.Validate(mut, license.ValidationContext{})
	if license.CodeOf(err) != license.CodeKeyIDMismatch {
		t.Fatalf("expected LICENSE_KEY_ID_MISMATCH, got %s", license.CodeOf(err))
	}
}

// 9. Lifetime license (no expiry) is perpetually valid.
func TestLifetimeLicense(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	req := baseRequest()
	req.LicenseType = license.LicenseTypeLifetime
	req.Edition = license.EditionEnterprise
	req.ExpiresAt = nil
	data := issueBytes(t, s, req)
	mgr := newTestManager(ringWith(t, "k1", pub))
	res, err := mgr.Validate(data, license.ValidationContext{})
	if err != nil || !res.Valid() {
		t.Fatalf("lifetime should validate: %v", err)
	}
	if res.ExpiresAt() != nil {
		t.Fatalf("lifetime should have no expiry")
	}
}

// 10. Trial license type validates.
func TestTrialLicense(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	req := baseRequest()
	req.LicenseType = license.LicenseTypeTrial
	req.Edition = license.EditionTrial
	now := time.Now().UTC()
	req.ExpiresAt = ptr(now.Add(7 * 24 * time.Hour))
	data := issueBytes(t, s, req)
	mgr := newTestManager(ringWith(t, "k1", pub))
	res, err := mgr.Validate(data, license.ValidationContext{})
	if err != nil || !res.Valid() {
		t.Fatalf("trial should validate: %v", err)
	}
}
