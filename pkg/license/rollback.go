package license

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// RollbackState is the integrity-protected local anti-rollback record. It
// remembers the latest trusted time observed so a subsequent large backward
// jump in the system clock can be detected. The record itself is authenticated
// with HMAC-SHA256 so tampering is detectable (not preventable — see SECURITY).
type RollbackState struct {
	LastTrustedTime time.Time `json:"last_trusted_time"`
	LastVerifiedAt  time.Time `json:"last_verified_at"`
	MAC             string    `json:"mac"` // hex(HMAC-SHA256(key, canonical(state without mac)))
}

// rollbackMACInput is the stable, MAC-covered projection of the state.
type rollbackMACInput struct {
	LastTrustedTime time.Time `json:"last_trusted_time"`
	LastVerifiedAt  time.Time `json:"last_verified_at"`
}

// RollbackStore persists and integrity-checks RollbackState on disk. The HMAC
// key should be derived from a built-in secret combined with a device
// fingerprint so the state cannot be trivially forged or transplanted.
type RollbackStore struct {
	path    string
	hmacKey []byte
	skew    time.Duration
}

// NewRollbackStore creates a store writing to `path`, authenticated with
// `hmacKey`. A zero-length key is rejected. `skew` tolerates minor clock drift.
func NewRollbackStore(path string, hmacKey []byte, skew time.Duration) (*RollbackStore, error) {
	if path == "" {
		return nil, newError(CodeStateIntegrityFailure, "empty rollback state path", nil)
	}
	if len(hmacKey) == 0 {
		return nil, newError(CodeStateIntegrityFailure, "empty rollback hmac key", nil)
	}
	if skew < 0 {
		skew = 0
	}
	k := make([]byte, len(hmacKey))
	copy(k, hmacKey)
	return &RollbackStore{path: path, hmacKey: k, skew: skew}, nil
}

func (s *RollbackStore) mac(in rollbackMACInput) (string, error) {
	// Marshal deterministically: the struct has a fixed field order and only
	// scalar time fields, so json.Marshal is stable here.
	b, err := json.Marshal(in)
	if err != nil {
		return "", newError(CodeStateIntegrityFailure, "marshal state", err)
	}
	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write(b)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// Load reads and verifies the on-disk state. A missing file returns (nil, nil)
// meaning "no prior state". A tampered/corrupt file returns
// ErrStateIntegrityFailure (fail-closed; caller decides policy per type).
func (s *RollbackStore) Load() (*RollbackState, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, newError(CodeStateIntegrityFailure, "read rollback state", err)
	}
	if len(data) > MaxRollbackStateSize {
		return nil, newError(CodeStateIntegrityFailure, "rollback state too large", nil)
	}
	var st RollbackState
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return nil, newError(CodeStateIntegrityFailure, "decode rollback state", err)
	}
	want, err := s.mac(rollbackMACInput{LastTrustedTime: st.LastTrustedTime, LastVerifiedAt: st.LastVerifiedAt})
	if err != nil {
		return nil, err
	}
	got, err := hex.DecodeString(st.MAC)
	if err != nil {
		return nil, newError(CodeStateIntegrityFailure, "invalid state mac encoding", nil)
	}
	wantRaw, _ := hex.DecodeString(want)
	if subtle.ConstantTimeCompare(got, wantRaw) != 1 {
		return nil, newError(CodeStateIntegrityFailure, "rollback state integrity check failed", nil)
	}
	return &st, nil
}

// Save atomically writes the state with a fresh MAC (temp file + rename).
func (s *RollbackStore) Save(st *RollbackState) error {
	if st == nil {
		return newError(CodeStateIntegrityFailure, "nil rollback state", nil)
	}
	m, err := s.mac(rollbackMACInput{LastTrustedTime: st.LastTrustedTime, LastVerifiedAt: st.LastVerifiedAt})
	if err != nil {
		return err
	}
	st.MAC = m
	b, err := json.Marshal(st)
	if err != nil {
		return newError(CodeStateIntegrityFailure, "marshal rollback state", err)
	}
	return atomicWriteFile(s.path, b, 0o600)
}

// CheckRollback compares `now` against the stored last-trusted time. If `now`
// is earlier than the stored time by more than the tolerated skew, it reports
// ErrClockRollback. On success it returns an updated state to be saved.
func (s *RollbackStore) CheckRollback(prev *RollbackState, now time.Time) (*RollbackState, error) {
	now = now.UTC()
	next := &RollbackState{LastTrustedTime: now, LastVerifiedAt: now}
	if prev == nil {
		return next, nil
	}
	// Keep the maximum observed trusted time as the high-water mark.
	if prev.LastTrustedTime.After(next.LastTrustedTime) {
		next.LastTrustedTime = prev.LastTrustedTime
	}
	if now.Add(s.skew).Before(prev.LastTrustedTime) {
		return nil, newError(CodeClockRollback, "system clock moved backward past last trusted time", nil)
	}
	return next, nil
}

// DeriveRollbackKey derives an HMAC key from a built-in secret and a device
// fingerprint string, binding the local state to both.
//
// SECURITY: passing an empty fingerprint produces a key that depends only on
// the built-in secret. Such a key is portable across machines and can be
// forged or transplanted between devices, defeating the point of binding the
// anti-rollback state to a device. Production callers should use
// DeriveRollbackKeyStrict, or always pass a non-empty device fingerprint here.
func DeriveRollbackKey(builtinSecret []byte, fingerprint string) []byte {
	mac := hmac.New(sha256.New, builtinSecret)
	mac.Write([]byte("grantseal:rollback:v1"))
	mac.Write([]byte(fingerprint))
	return mac.Sum(nil)
}

// DeriveRollbackKeyStrict behaves like DeriveRollbackKey but refuses to derive
// a key from an empty fingerprint. Requiring a device fingerprint prevents a
// portable, secret-only key that could be transplanted or forged across
// machines. On success it returns the same key DeriveRollbackKey would for the
// same inputs.
func DeriveRollbackKeyStrict(builtinSecret []byte, fingerprint string) ([]byte, error) {
	if fingerprint == "" {
		return nil, newError(CodeStateIntegrityFailure, "empty device fingerprint for rollback key", nil)
	}
	return DeriveRollbackKey(builtinSecret, fingerprint), nil
}

// atomicWriteFile writes data to a temp file in the same directory and renames
// it over the target, giving an atomic replace on POSIX filesystems.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return newError(CodeStateIntegrityFailure, "create temp file", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return newError(CodeStateIntegrityFailure, "write temp file", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return newError(CodeStateIntegrityFailure, "chmod temp file", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return newError(CodeStateIntegrityFailure, "sync temp file", err)
	}
	if err := tmp.Close(); err != nil {
		return newError(CodeStateIntegrityFailure, "close temp file", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return newError(CodeStateIntegrityFailure, "rename temp file", err)
	}
	return nil
}
