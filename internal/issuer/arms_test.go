package issuer

import (
	"errors"
	"testing"
	"time"

	"github.com/soulteary/grantseal/pkg/license"
)

func TestBuildRevocationListNilSigner(t *testing.T) {
	if _, err := BuildRevocationList(nil, []string{"a"}); err == nil {
		t.Fatal("want error on nil signer")
	}
}

func TestBuildRevocationListV2Arms(t *testing.T) {
	if _, err := BuildRevocationListV2(nil, RevocationListOptions{}); err == nil {
		t.Fatal("nil signer: want error")
	}
	s := newTestSigner(t)
	if _, err := BuildRevocationListV2(s, RevocationListOptions{Sequence: 0}); err == nil {
		t.Fatal("zero sequence: want error")
	}
	if _, err := BuildRevocationListV2(s, RevocationListOptions{Sequence: 1}); err == nil {
		t.Fatal("zero issued_at: want error")
	}
	now := time.Now().UTC()
	if _, err := BuildRevocationListV2(s, RevocationListOptions{Sequence: 1, IssuedAt: now, ExpiresAt: now.Add(-time.Hour)}); err == nil {
		t.Fatal("expires before issued: want error")
	}
}

// TestIssueBuildPayloadRandError drives Issue -> BuildPayload rand-failure arm.
func TestIssueBuildPayloadRandError(t *testing.T) {
	orig := randRead
	randRead = func([]byte) (int, error) { return 0, errors.New("no entropy") }
	t.Cleanup(func() { randRead = orig })
	s := newTestSigner(t)
	if _, err := Issue(s, IssueRequest{}); err == nil {
		t.Fatal("want error when BuildPayload fails")
	}
}

// TestIssueStaticValidationError drives Issue's ValidatePayloadStatic error arm
// by supplying an invalid edition/type that static validation rejects.
func TestIssueStaticValidationError(t *testing.T) {
	s := newTestSigner(t)
	req := IssueRequest{
		LicenseID:    "lic_x",
		SerialNumber: "SER-1",
		ProductID:    "prod",
		Edition:      license.Edition("bogus-edition"),
		LicenseType:  license.LicenseType("bogus-type"),
	}
	if _, err := Issue(s, req); err == nil {
		t.Fatal("want static validation error for invalid enums")
	}
}

func newTestSigner(t *testing.T) *Signer {
	t.Helper()
	kp, err := GenerateKeyPair("test-key")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(kp.KeyID, kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
