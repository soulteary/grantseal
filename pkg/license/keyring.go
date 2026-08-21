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

// Lookup resolves a key_id to its entry, honoring enabled/revoked/time windows.
// It returns a stable error Code so callers can distinguish unknown vs disabled
// vs revoked vs out-of-window keys.
func (r *KeyRing) Lookup(keyID string, now time.Time) (KeyEntry, error) {
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
