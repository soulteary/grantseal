package license

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"
)

// RevocationProvider reports whether a given license_id has been revoked. It is
// consulted during validation; a nil provider means "nothing revoked".
type RevocationProvider interface {
	IsRevoked(licenseID string) bool
}

// RevocationList is the signed body of an offline revocation list. It is
// authenticated exactly like a license: canonicalized, signed with the issuer's
// Ed25519 private key, and verified client-side against the KeyRing.
type RevocationList struct {
	SchemaVersion int       `json:"schema_version"`
	IssuedAt      time.Time `json:"issued_at"`
	KeyID         string    `json:"key_id"`
	RevokedIDs    []string  `json:"revoked_license_ids"`
}

// RevocationEnvelope wraps a signed revocation list on the wire.
type RevocationEnvelope struct {
	Algorithm Algorithm `json:"algorithm"`
	KeyID     string    `json:"key_id"`
	Payload   string    `json:"payload"`   // Base64URL(canonical revocation list)
	Signature string    `json:"signature"` // Base64URL(ed25519 signature)
}

// signedRevocation is the concrete RevocationProvider produced after verifying
// a RevocationEnvelope. Its lookup set is immutable after construction.
type signedRevocation struct {
	set map[string]struct{}
}

// IsRevoked reports whether licenseID is present in the verified list.
func (s *signedRevocation) IsRevoked(licenseID string) bool {
	if s == nil {
		return false
	}
	_, ok := s.set[licenseID]
	return ok
}

// CanonicalRevocationBytes returns the deterministic canonical bytes of a
// revocation list, used by issuers for signing and by the client for
// verification.
func CanonicalRevocationBytes(rl *RevocationList) ([]byte, error) { return canonicalRevocation(rl) }

// canonicalRevocation returns deterministic bytes for signing/verification.
func canonicalRevocation(rl *RevocationList) ([]byte, error) {
	raw, err := json.Marshal(rl)
	if err != nil {
		return nil, newError(CodeMalformed, "marshal revocation list", err)
	}
	var tree any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&tree); err != nil {
		return nil, newError(CodeMalformed, "decode revocation tree", err)
	}
	var buf bytes.Buffer
	if err := encodeCanonical(&buf, tree); err != nil {
		return nil, newError(CodeMalformed, "encode canonical revocation", err)
	}
	return buf.Bytes(), nil
}

// ParseRevocationEnvelope decodes a revocation envelope from JSON.
func ParseRevocationEnvelope(data []byte) (*RevocationEnvelope, error) {
	if len(data) == 0 {
		return nil, newError(CodeMalformed, "empty revocation data", nil)
	}
	if len(data) > MaxLicenseFileSize {
		return nil, newError(CodeFileTooLarge, "revocation data exceeds size cap", nil)
	}
	var env RevocationEnvelope
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return nil, newError(CodeMalformed, "decode revocation envelope", err)
	}
	if dec.More() {
		return nil, newError(CodeMalformed, "trailing data after revocation envelope", nil)
	}
	if env.Algorithm == "" || env.KeyID == "" || env.Payload == "" || env.Signature == "" {
		return nil, newError(CodeMalformed, "revocation envelope missing fields", nil)
	}
	return &env, nil
}

// LoadRevocationList verifies a revocation envelope against the ring and returns
// a RevocationProvider. Signature verification uses the same rules as licenses:
// Ed25519 only, key must be known/enabled, signature covers canonical bytes.
func LoadRevocationList(ring *KeyRing, data []byte, now time.Time) (RevocationProvider, error) {
	env, err := ParseRevocationEnvelope(data)
	if err != nil {
		return nil, err
	}
	if !env.Algorithm.Valid() {
		return nil, newError(CodeUnsupportedAlgorithm, "unsupported algorithm "+string(env.Algorithm), nil)
	}
	entry, err := ring.Lookup(env.KeyID, now)
	if err != nil {
		return nil, err
	}
	canonical, err := base64.URLEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, newError(CodeMalformed, "invalid base64 revocation payload", err)
	}
	sig, err := base64.URLEncoding.DecodeString(env.Signature)
	if err != nil {
		return nil, newError(CodeMalformed, "invalid base64 revocation signature", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, newError(CodeSignatureInvalid, "bad revocation signature length", nil)
	}
	if !ed25519.Verify(entry.PublicKey, canonical, sig) {
		return nil, newError(CodeSignatureInvalid, "revocation signature does not match", nil)
	}
	var rl RevocationList
	dec := json.NewDecoder(bytes.NewReader(canonical))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rl); err != nil {
		return nil, newError(CodeMalformed, "decode revocation list", err)
	}
	if rl.SchemaVersion != SchemaVersion {
		return nil, newError(CodeUnsupportedSchema, "unsupported revocation schema", nil)
	}
	if rl.KeyID != env.KeyID {
		return nil, newError(CodeKeyIDMismatch, "revocation payload key_id mismatch", nil)
	}
	set := make(map[string]struct{}, len(rl.RevokedIDs))
	for _, id := range rl.RevokedIDs {
		if id != "" {
			set[id] = struct{}{}
		}
	}
	return &signedRevocation{set: set}, nil
}

// StaticRevocation is a simple in-memory RevocationProvider for tests/embedding.
type StaticRevocation struct{ IDs map[string]struct{} }

// NewStaticRevocation builds a StaticRevocation from a list of license IDs.
func NewStaticRevocation(ids ...string) *StaticRevocation {
	m := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		m[id] = struct{}{}
	}
	return &StaticRevocation{IDs: m}
}

// IsRevoked reports membership in the static set.
func (s *StaticRevocation) IsRevoked(licenseID string) bool {
	if s == nil {
		return false
	}
	_, ok := s.IDs[licenseID]
	return ok
}
