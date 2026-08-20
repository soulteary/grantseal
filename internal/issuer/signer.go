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
// supported version before signing, so the signed bytes are self-consistent.
func (s *Signer) SignPayload(p *license.Payload) (*license.Envelope, error) {
	if p == nil {
		return nil, fmt.Errorf("issuer: nil payload")
	}
	p.KeyID = s.keyID
	if p.SchemaVersion == 0 {
		p.SchemaVersion = license.SchemaVersion
	}
	canonical, err := license.CanonicalBytes(p)
	if err != nil {
		return nil, fmt.Errorf("issuer: canonicalize: %w", err)
	}
	sig := ed25519.Sign(s.priv, canonical)
	return license.NewEnvelope(license.AlgorithmEd25519, s.keyID, canonical, sig), nil
}

// SignCanonical signs arbitrary canonical bytes (used for revocation lists).
func (s *Signer) SignCanonical(canonical []byte) []byte {
	return ed25519.Sign(s.priv, canonical)
}

// KeyID returns the signer's key id.
func (s *Signer) KeyID() string { return s.keyID }
