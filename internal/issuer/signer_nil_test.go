package issuer_test

import (
	"testing"
	"time"

	"github.com/soulteary/grantseal/internal/issuer"
	"github.com/soulteary/grantseal/pkg/license"
)

// A nil *Signer is nil-safe on both KeyID and SignPayload rather than panicking.
func TestNilSignerIsSafe(t *testing.T) {
	var s *issuer.Signer
	if got := s.KeyID(); got != "" {
		t.Fatalf("nil signer KeyID = %q, want empty", got)
	}
	if _, err := s.SignPayload(&license.Payload{}); err == nil {
		t.Fatal("expected an error signing with a nil signer")
	}
}

// SignPayload runs full static validation before signing, so a structurally
// invalid payload (subscription without an expiry) is rejected on this path.
func TestSignPayloadRejectsInvalid(t *testing.T) {
	kp, err := issuer.GenerateKeyPair("k1")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := issuer.NewSigner("k1", kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	p := &license.Payload{
		LicenseID:     "lic_1",
		SerialNumber:  "SER",
		ProductID:     "p",
		CustomerID:    "c",
		Edition:       license.EditionBasic,
		LicenseType:   license.LicenseTypeSubscription, // requires ExpiresAt
		IssuedAt:      time.Now().UTC(),
		DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
	}
	if _, err := signer.SignPayload(p); err == nil {
		t.Fatal("expected SignPayload to reject a subscription without an expiry")
	}
}

// Issue rejects a nil signer before doing any work.
func TestIssueNilSigner(t *testing.T) {
	_, err := issuer.Issue(nil, issuer.IssueRequest{
		ProductID:     "p",
		Edition:       license.EditionBasic,
		LicenseType:   license.LicenseTypeLifetime,
		DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
	})
	if err == nil {
		t.Fatal("expected Issue to reject a nil signer")
	}
}
