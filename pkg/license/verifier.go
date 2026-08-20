package license

import (
	"crypto/ed25519"
	"time"
)

// Verifier checks a license envelope against a KeyRing. It verifies that:
//   - the algorithm is Ed25519 (the only supported algorithm),
//   - the key_id resolves to an enabled, non-revoked, in-window public key,
//   - the Ed25519 signature covers the exact canonical payload bytes,
//   - the payload's embedded key_id matches the envelope key_id.
//
// It performs no time/device/product policy checks — that is the validator's
// job. The verifier is fail-closed and never panics.
type Verifier struct {
	ring *KeyRing
}

// NewVerifier returns a Verifier bound to the given key ring.
func NewVerifier(ring *KeyRing) *Verifier {
	return &Verifier{ring: ring}
}

// VerifyResult holds the outcome of a successful cryptographic verification.
type VerifyResult struct {
	Payload   *Payload
	KeyID     string
	Canonical []byte
}

// Verify validates the envelope signature and returns the decoded payload on
// success. `now` selects the key-window used for key lookup.
func (v *Verifier) Verify(env *Envelope, now time.Time) (*VerifyResult, error) {
	if v == nil || v.ring == nil {
		return nil, newError(CodeSignatureInvalid, "verifier not configured", nil)
	}
	if env == nil {
		return nil, newError(CodeMalformed, "nil envelope", nil)
	}
	if !env.Algorithm.Valid() {
		return nil, newError(CodeUnsupportedAlgorithm, "unsupported algorithm "+string(env.Algorithm), nil)
	}

	entry, err := v.ring.Lookup(env.KeyID, now)
	if err != nil {
		return nil, err
	}

	canonical, err := env.DecodeCanonical()
	if err != nil {
		return nil, err
	}
	sig, err := env.DecodeSignature()
	if err != nil {
		return nil, err
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, newError(CodeSignatureInvalid, "bad signature length", nil)
	}

	// ed25519.Verify is constant-time in the crypto sense and returns a bool.
	if !ed25519.Verify(entry.PublicKey, canonical, sig) {
		return nil, newError(CodeSignatureInvalid, "signature does not match", nil)
	}

	payload, err := env.DecodePayload()
	if err != nil {
		return nil, err
	}
	// The signed payload must reference the same key_id as the envelope,
	// preventing key_id substitution across a valid signature.
	if payload.KeyID != env.KeyID {
		return nil, newError(CodeKeyIDMismatch, "payload key_id does not match envelope", nil)
	}

	return &VerifyResult{Payload: payload, KeyID: env.KeyID, Canonical: canonical}, nil
}
