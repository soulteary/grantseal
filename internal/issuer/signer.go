package issuer

import (
	"crypto/ed25519"
	"fmt"

	"github.com/soulteary/grantseal/pkg/license"
)

// Signer signs canonical payloads with an Ed25519 private key. The private key
// stays in memory here and is never exposed to callers or logs.
type Signer struct {
	keyID string
	priv  ed25519.PrivateKey
}

// NewSigner constructs a Signer from a key_id and private key.
func NewSigner(keyID string, priv ed25519.PrivateKey) (*Signer, error) {
	if keyID == "" {
		return nil, fmt.Errorf("issuer: signer key_id empty")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("issuer: invalid private key size")
	}
	return &Signer{keyID: keyID, priv: priv}, nil
}

// SignPayload canonicalizes and signs a license payload, returning an envelope.
// It sets payload.KeyID to the signer's key_id and payload.SchemaVersion to the
// supported version, then runs full static validation (ValidatePayloadStatic)
// before signing so a structurally invalid license can never be signed via this
// path. This matches BuildPayload's contract that full validation runs here.
func (s *Signer) SignPayload(p *license.Payload) (*license.Envelope, error) {
	if s == nil {
		return nil, fmt.Errorf("issuer: nil signer")
	}
	if p == nil {
		return nil, fmt.Errorf("issuer: nil payload")
	}
	p.KeyID = s.keyID
	if p.SchemaVersion == 0 {
		p.SchemaVersion = license.SchemaVersion
	}
	if err := license.ValidatePayloadStatic(p); err != nil {
		return nil, fmt.Errorf("issuer: invalid license: %w", err)
	}
	canonical, err := license.CanonicalBytes(p)
	if err != nil {
		return nil, fmt.Errorf("issuer: canonicalize: %w", err)
	}
	sig := ed25519.Sign(s.priv, license.LicenseSigningInput(canonical))
	return license.NewEnvelope(license.AlgorithmEd25519, s.keyID, canonical, sig), nil
}

// SignCanonical signs arbitrary canonical bytes WITHOUT any domain-separation
// prefix. It is retained for the legacy v1 revocation path (see revoke.go);
// new revocation signing uses the v2 domain via BuildRevocationListV2.
func (s *Signer) SignCanonical(canonical []byte) []byte {
	return ed25519.Sign(s.priv, canonical)
}

// SignLicenseBytes signs caller-provided license payload bytes using the
// license signing domain, matching what the client verifier checks. It exists
// for advanced issuers and tests that need to sign bytes that are not
// necessarily canonical (e.g. to exercise the client's canonical-equality
// rejection). Normal issuance should use SignPayload.
func SignLicenseBytes(s *Signer, payloadBytes []byte) []byte {
	return ed25519.Sign(s.priv, license.LicenseSigningInput(payloadBytes))
}

// SignRevocationBytes signs caller-provided revocation payload bytes using the
// revocation v2 signing domain. Used by BuildRevocationListV2 and tests.
func SignRevocationBytes(s *Signer, payloadBytes []byte) []byte {
	return ed25519.Sign(s.priv, license.RevocationSigningInput(payloadBytes))
}

// KeyID returns the signer's key id, or "" for a nil signer.
func (s *Signer) KeyID() string {
	if s == nil {
		return ""
	}
	return s.keyID
}
