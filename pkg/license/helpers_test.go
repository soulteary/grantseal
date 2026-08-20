package license_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/soulteary/grantseal/internal/issuer"
	"github.com/soulteary/grantseal/pkg/license"
)

// testKeyPair generates an ephemeral Ed25519 key pair for tests. Private keys
// are NEVER committed; they are created at runtime here.
func testKeyPair(t *testing.T, keyID string) (*issuer.Signer, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s, err := issuer.NewSigner(keyID, priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return s, pub
}

// ringWith builds a KeyRing containing the given key.
func ringWith(t *testing.T, keyID string, pub ed25519.PublicKey) *license.KeyRing {
	t.Helper()
	r := license.NewKeyRing()
	if err := r.AddPublicKey(keyID, pub); err != nil {
		t.Fatalf("add pubkey: %v", err)
	}
	return r
}

// ptr returns a pointer to t.
func ptr(t time.Time) *time.Time { return &t }

// baseRequest returns a minimal valid issue request for `keyID`.
func baseRequest() issuer.IssueRequest {
	now := time.Now().UTC()
	return issuer.IssueRequest{
		ProductID:   "acme-app",
		CustomerID:  "cust_1",
		Edition:     license.EditionProfessional,
		LicenseType: license.LicenseTypeSubscription,
		IssuedAt:    &now,
		ExpiresAt:   ptr(now.Add(365 * 24 * time.Hour)),
		DeviceBinding: license.DeviceBinding{
			Mode: license.DeviceModeNone,
		},
	}
}

// issueBytes issues a license and returns its envelope JSON bytes.
func issueBytes(t *testing.T, s *issuer.Signer, req issuer.IssueRequest) []byte {
	t.Helper()
	env, err := issuer.Issue(s, req)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	data, err := env.MarshalJSONIndent()
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return data
}

// signRaw signs a caller-provided payload WITHOUT running BuildPayload's static
// validation, so tests can craft deliberately invalid payloads (bad schema,
// unknown enum) that still carry a valid signature.
func signRaw(t *testing.T, s *issuer.Signer, p *license.Payload) (*license.Envelope, error) {
	t.Helper()
	return s.SignPayload(p)
}

// buildRevocation signs a revocation list for the given license IDs.
func buildRevocation(t *testing.T, s *issuer.Signer, ids ...string) (*license.RevocationEnvelope, error) {
	t.Helper()
	return issuer.BuildRevocationList(s, ids)
}

// testKeyPairF is the *testing.F variant of testKeyPair for fuzz seeds.
func testKeyPairF(f *testing.F, keyID string) (*issuer.Signer, ed25519.PublicKey) {
	f.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	s, err := issuer.NewSigner(keyID, priv)
	if err != nil {
		f.Fatalf("new signer: %v", err)
	}
	return s, pub
}

// issueBytesF issues a base license for fuzz seeding.
func issueBytesF(f *testing.F, s *issuer.Signer) []byte {
	f.Helper()
	env, err := issuer.Issue(s, baseRequest())
	if err != nil {
		f.Fatalf("issue: %v", err)
	}
	data, err := env.MarshalJSONIndent()
	if err != nil {
		f.Fatalf("marshal: %v", err)
	}
	return data
}
