package license

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// withFSSeams temporarily overrides the filesystem seams and restores them.
func withFSSeams(t *testing.T, createTemp func(string, string) (*os.File, error), rename func(string, string) error) {
	t.Helper()
	oc, or := fsCreateTemp, fsRename
	if createTemp != nil {
		fsCreateTemp = createTemp
	}
	if rename != nil {
		fsRename = rename
	}
	t.Cleanup(func() { fsCreateTemp, fsRename = oc, or })
}

func TestAtomicWriteFileCreateTempError(t *testing.T) {
	withFSSeams(t, func(string, string) (*os.File, error) {
		return nil, errors.New("boom create temp")
	}, nil)
	err := atomicWriteFile(filepath.Join(t.TempDir(), "x"), []byte("data"), 0o600)
	if CodeOf(err) != CodeStateIntegrityFailure {
		t.Fatalf("want CodeStateIntegrityFailure, got %v", err)
	}
}

func TestAtomicWriteFileRenameError(t *testing.T) {
	withFSSeams(t, nil, func(string, string) error {
		return errors.New("boom rename")
	})
	err := atomicWriteFile(filepath.Join(t.TempDir(), "x"), []byte("data"), 0o600)
	if CodeOf(err) != CodeStateIntegrityFailure {
		t.Fatalf("want CodeStateIntegrityFailure, got %v", err)
	}
}

// TestSaveRevocationStatePersistError drives the FileRevocationStateStore save
// path through atomicWriteFile failure (rename) and asserts the
// revocation-specific integrity code is surfaced.
func TestSaveRevocationStatePersistError(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileRevocationStateStore(filepath.Join(dir, "revstate.json"), []byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	withFSSeams(t, nil, func(string, string) error { return errors.New("boom rename") })
	err = store.SaveRevocationState(&RevocationState{ListID: "L1", Sequence: 1})
	if CodeOf(err) != CodeRevocationStateIntegrityFailure {
		t.Fatalf("want CodeRevocationStateIntegrityFailure, got %v", err)
	}
}

// TestRollbackSaveError drives saveLocked -> atomicWriteFile failure.
func TestRollbackSaveError(t *testing.T) {
	dir := t.TempDir()
	store, err := NewRollbackStore(filepath.Join(dir, "rb.json"), []byte("k"), 0)
	if err != nil {
		t.Fatal(err)
	}
	withFSSeams(t, func(string, string) (*os.File, error) { return nil, errors.New("boom") }, nil)
	if err := store.CheckAndSave(time.Now().UTC()); CodeOf(err) != CodeStateIntegrityFailure {
		t.Fatalf("want CodeStateIntegrityFailure, got %v", err)
	}
}

// TestNewRollbackStoreNegativeSkew covers the skew<0 normalization arm and the
// empty path/key rejection arms.
func TestNewRollbackStoreArms(t *testing.T) {
	if _, err := NewRollbackStore("", []byte("k"), 0); CodeOf(err) != CodeStateIntegrityFailure {
		t.Fatalf("empty path: want CodeStateIntegrityFailure, got %v", err)
	}
	if _, err := NewRollbackStore("p", nil, 0); CodeOf(err) != CodeStateIntegrityFailure {
		t.Fatalf("empty key: want CodeStateIntegrityFailure, got %v", err)
	}
	s, err := NewRollbackStore("p", []byte("k"), -5*time.Second)
	if err != nil {
		t.Fatalf("negative skew should be normalized, got %v", err)
	}
	if s.skew != 0 {
		t.Fatalf("negative skew should become 0, got %v", s.skew)
	}
}

// TestRollbackLoadTampered writes a state file with a broken MAC and a broken
// hex MAC to drive loadLocked's integrity-failure arms.
func TestRollbackLoadTampered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rb.json")
	store, err := NewRollbackStore(path, []byte("k"), 0)
	if err != nil {
		t.Fatal(err)
	}
	// Wrong MAC value (valid hex, wrong bytes).
	if err := os.WriteFile(path, []byte(`{"last_trusted_time":"2024-01-01T00:00:00Z","last_verified_at":"2024-01-01T00:00:00Z","mac":"deadbeef"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); CodeOf(err) != CodeStateIntegrityFailure {
		t.Fatalf("tampered mac: want CodeStateIntegrityFailure, got %v", err)
	}
	// Invalid hex encoding for the MAC.
	if err := os.WriteFile(path, []byte(`{"last_trusted_time":"2024-01-01T00:00:00Z","last_verified_at":"2024-01-01T00:00:00Z","mac":"zzzz"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); CodeOf(err) != CodeStateIntegrityFailure {
		t.Fatalf("bad hex mac: want CodeStateIntegrityFailure, got %v", err)
	}
}

// TestRevocationStateStoreArms drives nil-state rejection and tampered-file
// integrity arms for both Mem and File stores.
func TestRevocationStateStoreArms(t *testing.T) {
	mem := NewMemRevocationStateStore()
	if err := mem.SaveRevocationState(nil); CodeOf(err) != CodeRevocationStateIntegrityFailure {
		t.Fatalf("mem nil: want integrity failure, got %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "rev.json")
	fs, err := NewFileRevocationStateStore(path, []byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.SaveRevocationState(nil); CodeOf(err) != CodeRevocationStateIntegrityFailure {
		t.Fatalf("file nil: want integrity failure, got %v", err)
	}
	// Empty-path/key construction rejection.
	if _, err := NewFileRevocationStateStore("", []byte("k")); CodeOf(err) != CodeRevocationStateIntegrityFailure {
		t.Fatalf("empty path: want integrity failure, got %v", err)
	}
	if _, err := NewFileRevocationStateStore("p", nil); CodeOf(err) != CodeRevocationStateIntegrityFailure {
		t.Fatalf("empty key: want integrity failure, got %v", err)
	}
	// Tampered file: wrong MAC then bad hex.
	if err := os.WriteFile(path, []byte(`{"entries":{},"mac":"deadbeef"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.LoadRevocationState("x"); CodeOf(err) != CodeRevocationStateIntegrityFailure {
		t.Fatalf("tampered mac: want integrity failure, got %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"entries":{},"mac":"zzzz"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.LoadRevocationState("x"); CodeOf(err) != CodeRevocationStateIntegrityFailure {
		t.Fatalf("bad hex mac: want integrity failure, got %v", err)
	}
}
