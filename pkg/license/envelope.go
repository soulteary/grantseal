package license

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
)

// Envelope is the on-the-wire license container. The Payload field holds the
// Base64URL-encoded canonical payload bytes (exactly what was signed), and
// Signature is the Base64URL-encoded Ed25519 signature over those bytes.
//
// Encoding the canonical payload verbatim (rather than re-serializing on the
// client) guarantees the verifier checks the signature against the identical
// bytes the issuer signed.
type Envelope struct {
	Algorithm Algorithm `json:"algorithm"`
	KeyID     string    `json:"key_id"`
	Payload   string    `json:"payload"`   // Base64URL(canonical payload)
	Signature string    `json:"signature"` // Base64URL(ed25519 signature)
}

var b64 = base64.URLEncoding

// NewEnvelope builds an envelope from canonical payload bytes and a raw
// signature. It does not itself perform signing (that lives in internal/issuer).
func NewEnvelope(alg Algorithm, keyID string, canonical, signature []byte) *Envelope {
	return &Envelope{
		Algorithm: alg,
		KeyID:     keyID,
		Payload:   b64.EncodeToString(canonical),
		Signature: b64.EncodeToString(signature),
	}
}

// MarshalJSONIndent returns the envelope as pretty-printed JSON for files.
func (e *Envelope) MarshalJSONIndent() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(e); err != nil {
		return nil, newError(CodeMalformed, "marshal envelope", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// ParseEnvelope decodes an envelope from JSON bytes. It enforces the file-size
// cap, rejects trailing garbage, and returns a stable error rather than
// panicking on malformed input (continuously fuzz/race verified in CI). It does
// NOT verify the signature (see Verifier).
func ParseEnvelope(data []byte) (*Envelope, error) {
	if len(data) == 0 {
		return nil, newError(CodeMalformed, "empty license data", nil)
	}
	if len(data) > MaxLicenseFileSize {
		return nil, newError(CodeFileTooLarge, "license data exceeds size cap", nil)
	}
	var env Envelope
	if err := decodeStrictJSON(data, &env, MaxLicenseFileSize); err != nil {
		return nil, err
	}
	if env.Algorithm == "" || env.KeyID == "" || env.Payload == "" || env.Signature == "" {
		return nil, newError(CodeMalformed, "envelope missing required fields", nil)
	}
	return &env, nil
}

// DecodeCanonical returns the raw canonical payload bytes carried by the
// envelope, validating Base64URL.
func (e *Envelope) DecodeCanonical() ([]byte, error) {
	b, err := b64.DecodeString(e.Payload)
	if err != nil {
		return nil, newError(CodeMalformed, "invalid base64 payload", err)
	}
	if len(b) == 0 {
		return nil, newError(CodeMalformed, "empty payload", nil)
	}
	return b, nil
}

// DecodeSignature returns the raw Ed25519 signature bytes.
func (e *Envelope) DecodeSignature() ([]byte, error) {
	b, err := b64.DecodeString(e.Signature)
	if err != nil {
		return nil, newError(CodeMalformed, "invalid base64 signature", err)
	}
	return b, nil
}

// DecodePayload parses the canonical payload bytes back into a Payload struct.
func (e *Envelope) DecodePayload() (*Payload, error) {
	raw, err := e.DecodeCanonical()
	if err != nil {
		return nil, err
	}
	var p Payload
	// The canonical payload is bounded by the license file size cap; reuse it
	// here so an over-large embedded payload is rejected before struct decode.
	if err := decodeStrictJSON(raw, &p, MaxLicenseFileSize); err != nil {
		return nil, err
	}
	return &p, nil
}
