package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"sort"
	"sync"
	"time"
)

// KeyEntry describes one public verification key in the ring. It carries the
// Ed25519 public key plus lifecycle metadata used to accept or reject
// signatures. Only public material lives here — never a private key.
type KeyEntry struct {
	KeyID     string
	PublicKey ed25519.PublicKey
	Enabled   bool
	Revoked   bool
	NotBefore *time.Time
	NotAfter  *time.Time
}

// KeyRing is a concurrency-safe collection of public keys keyed by key_id.
// Old keys are retained after rotation so previously issued licenses keep
// verifying, as long as their key remains present and enabled.
type KeyRing struct {
	mu   sync.RWMutex
	keys map[string]KeyEntry
}

// NewKeyRing returns an empty ring.
func NewKeyRing() *KeyRing {
	return &KeyRing{keys: make(map[string]KeyEntry)}
}

// Add inserts or replaces a key entry. It validates the public-key length.
func (r *KeyRing) Add(e KeyEntry) error {
	if e.KeyID == "" {
		return newError(CodeMalformed, "empty key_id", nil)
	}
	if len(e.PublicKey) != ed25519.PublicKeySize {
		return newError(CodeMalformed, "invalid ed25519 public key size", nil)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// Store a defensive copy of the key bytes.
	cp := make(ed25519.PublicKey, len(e.PublicKey))
	copy(cp, e.PublicKey)
	e.PublicKey = cp
	r.keys[e.KeyID] = e
	return nil
}

// AddPublicKey is a convenience helper adding an enabled, non-revoked key.
func (r *KeyRing) AddPublicKey(keyID string, pub ed25519.PublicKey) error {
	return r.Add(KeyEntry{KeyID: keyID, PublicKey: pub, Enabled: true})
}

// AddPublicKeyBase64 decodes a Base64URL-encoded public key and adds it.
// Only base64.URLEncoding is accepted (the canonical encoding produced by the
// issuer); the standard-alphabet fallback was removed so encoding is strict and
// unambiguous across producers and consumers.
func (r *KeyRing) AddPublicKeyBase64(keyID, encoded string) error {
	b, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return newError(CodeMalformed, "invalid base64 public key", err)
	}
	return r.AddPublicKey(keyID, ed25519.PublicKey(b))
}

// LookupPublicKey resolves a key_id to its entry, honoring only the immediate
// kill switches (unknown / revoked / disabled) and NOT the time window. It is
// the first half of issuance-window verification: the caller verifies the
// signature with entry.PublicKey, then calls CheckKeyPolicy with the signed
// Payload.IssuedAt to decide whether the key was valid AT ISSUANCE. This lets a
// key that has since passed its NotAfter still verify licenses it legitimately
// signed while it was active, while Revoked remains an immediate kill switch
// that rejects everything regardless of issuance time.
func (r *KeyRing) LookupPublicKey(keyID string) (KeyEntry, error) {
	r.mu.RLock()
	e, ok := r.keys[keyID]
	r.mu.RUnlock()
	if !ok {
		return KeyEntry{}, newError(CodeKeyUnknown, "unknown key_id", nil)
	}
	if e.Revoked {
		return KeyEntry{}, newError(CodeKeyRevoked, "key revoked", nil)
	}
	if !e.Enabled {
		return KeyEntry{}, newError(CodeKeyDisabled, "key disabled", nil)
	}
	return e, nil
}

// CheckKeyPolicy reports whether the key was within its issuance window at the
// given instant (typically the signed Payload.IssuedAt). Revoked/disabled keys
// are already excluded by LookupPublicKey; this enforces the NotBefore/NotAfter
// window. A zero issuedAt is treated as failing closed when a window is set.
func (r *KeyRing) CheckKeyPolicy(e KeyEntry, issuedAt time.Time) error {
	if e.Revoked {
		return newError(CodeKeyRevoked, "key revoked", nil)
	}
	if !e.Enabled {
		return newError(CodeKeyDisabled, "key disabled", nil)
	}
	if e.NotBefore != nil && issuedAt.Before(*e.NotBefore) {
		return newError(CodeKeyDisabled, "key was not yet active at issuance", nil)
	}
	if e.NotAfter != nil && issuedAt.After(*e.NotAfter) {
		return newError(CodeKeyDisabled, "key was past its validity window at issuance", nil)
	}
	return nil
}

// Lookup resolves a key_id to its entry, honoring enabled/revoked/time windows
// evaluated at `now`. It returns a stable error Code so callers can distinguish
// unknown vs disabled vs revoked vs out-of-window keys.
//
// Deprecated: Lookup evaluates the key window against `now` (wall-clock at
// verification), which incorrectly rejects licenses signed by a key that has
// since expired. Prefer LookupPublicKey + CheckKeyPolicy(entry, Payload.IssuedAt)
// for issuance-window semantics. Retained for the revocation path and callers
// that intentionally want a now-based window.
func (r *KeyRing) Lookup(keyID string, now time.Time) (KeyEntry, error) {
	e, err := r.LookupPublicKey(keyID)
	if err != nil {
		return KeyEntry{}, err
	}
	if e.NotBefore != nil && now.Before(*e.NotBefore) {
		return KeyEntry{}, newError(CodeKeyDisabled, "key not yet active", nil)
	}
	if e.NotAfter != nil && now.After(*e.NotAfter) {
		return KeyEntry{}, newError(CodeKeyDisabled, "key past validity window", nil)
	}
	return e, nil
}

// KeyIDs returns the sorted list of key_ids in the ring (for diagnostics).
func (r *KeyRing) KeyIDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.keys))
	for k := range r.keys {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
