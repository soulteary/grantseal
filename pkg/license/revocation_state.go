package license

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
)

// MemRevocationStateStore is an in-memory RevocationStateStore keyed by list_id.
// It is safe for concurrent use and intended for tests, single-process embedding
// where persistence across restarts is not required, or as a building block.
type MemRevocationStateStore struct {
	mu sync.Mutex
	m  map[string]RevocationState
}

// NewMemRevocationStateStore returns an empty in-memory revocation state store.
func NewMemRevocationStateStore() *MemRevocationStateStore {
	return &MemRevocationStateStore{m: make(map[string]RevocationState)}
}

// LoadRevocationState returns a copy of the stored state for listID, or
// (nil, nil) when none exists.
func (s *MemRevocationStateStore) LoadRevocationState(listID string) (*RevocationState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.m[listID]
	if !ok {
		return nil, nil
	}
	cp := st
	return &cp, nil
}

// SaveRevocationState stores a copy of st keyed by st.ListID.
func (s *MemRevocationStateStore) SaveRevocationState(st *RevocationState) error {
	if st == nil {
		return newError(CodeRevocationStateIntegrityFailure, "nil revocation state", nil)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[st.ListID] = *st
	return nil
}

// FileRevocationStateStore persists revocation high-water state to a single
// JSON file, authenticated with HMAC-SHA256 so tampering is detectable (not
// preventable — see SECURITY). It keeps one entry per list_id and is safe for
// concurrent use. Writes are atomic (temp file + rename + directory fsync).
type FileRevocationStateStore struct {
	mu      sync.Mutex
	path    string
	hmacKey []byte
}

// fileRevocationStateFile is the on-disk container: a map of list_id -> state
// plus a MAC over the canonical map bytes.
type fileRevocationStateFile struct {
	Entries map[string]RevocationState `json:"entries"`
	MAC     string                     `json:"mac"`
}

// NewFileRevocationStateStore creates a store writing to path, authenticated
// with hmacKey. A zero-length key is rejected.
func NewFileRevocationStateStore(path string, hmacKey []byte) (*FileRevocationStateStore, error) {
	if path == "" {
		return nil, newError(CodeRevocationStateIntegrityFailure, "empty revocation state path", nil)
	}
	if len(hmacKey) == 0 {
		return nil, newError(CodeRevocationStateIntegrityFailure, "empty revocation state hmac key", nil)
	}
	k := make([]byte, len(hmacKey))
	copy(k, hmacKey)
	return &FileRevocationStateStore{path: path, hmacKey: k}, nil
}

func (s *FileRevocationStateStore) mac(entries map[string]RevocationState) (string, error) {
	// Marshal deterministically: Go's json.Marshal sorts map keys, and the
	// value struct has a fixed field order with only scalar fields.
	b, err := json.Marshal(entries)
	if err != nil {
		return "", newError(CodeRevocationStateIntegrityFailure, "marshal revocation state", err)
	}
	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write(b)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func (s *FileRevocationStateStore) loadFileLocked() (map[string]RevocationState, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]RevocationState{}, nil
		}
		return nil, newError(CodeRevocationStateIntegrityFailure, "read revocation state", err)
	}
	if len(data) > MaxRevocationFileSize {
		return nil, newError(CodeRevocationStateIntegrityFailure, "revocation state too large", nil)
	}
	var f fileRevocationStateFile
	if err := decodeStrictJSON(data, &f, MaxRevocationFileSize); err != nil {
		return nil, newError(CodeRevocationStateIntegrityFailure, "decode revocation state", err)
	}
	if f.Entries == nil {
		f.Entries = map[string]RevocationState{}
	}
	want, err := s.mac(f.Entries)
	if err != nil {
		return nil, err
	}
	got, derr := hex.DecodeString(f.MAC)
	if derr != nil {
		return nil, newError(CodeRevocationStateIntegrityFailure, "invalid state mac encoding", nil)
	}
	wantRaw, _ := hex.DecodeString(want)
	if subtle.ConstantTimeCompare(got, wantRaw) != 1 {
		return nil, newError(CodeRevocationStateIntegrityFailure, "revocation state integrity check failed", nil)
	}
	return f.Entries, nil
}

// LoadRevocationState returns the stored state for listID, or (nil, nil) when
// none exists. A corrupt/tampered file returns
// CodeRevocationStateIntegrityFailure (fail-closed).
func (s *FileRevocationStateStore) LoadRevocationState(listID string) (*RevocationState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := s.loadFileLocked()
	if err != nil {
		return nil, err
	}
	st, ok := entries[listID]
	if !ok {
		return nil, nil
	}
	cp := st
	return &cp, nil
}

// SaveRevocationState atomically merges st into the on-disk map (keyed by
// st.ListID) and rewrites the file with a fresh MAC.
func (s *FileRevocationStateStore) SaveRevocationState(st *RevocationState) error {
	if st == nil {
		return newError(CodeRevocationStateIntegrityFailure, "nil revocation state", nil)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := s.loadFileLocked()
	if err != nil {
		return err
	}
	entries[st.ListID] = *st
	mac, err := s.mac(entries)
	if err != nil {
		return err
	}
	b, err := json.Marshal(fileRevocationStateFile{Entries: entries, MAC: mac})
	if err != nil {
		return newError(CodeRevocationStateIntegrityFailure, "marshal revocation state", err)
	}
	if err := atomicWriteFile(s.path, b, 0o600); err != nil {
		// atomicWriteFile returns CodeStateIntegrityFailure; normalize to the
		// revocation-specific integrity code for callers matching on it.
		return newError(CodeRevocationStateIntegrityFailure, "persist revocation state", err)
	}
	return nil
}
