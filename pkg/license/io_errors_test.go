package license

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/soulteary/grantseal/pkg/fingerprint"
)

// ioSkipIfRoot skips permission-based failure tests when running as root,
// because a 0o500 directory mode does not deny writes to the superuser and
// would make the "write must fail" expectation flaky in CI.
func ioSkipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root defeats read-only directory permissions")
	}
}

// ioReadonlyDir creates a 0o500 (read+execute, no write) directory inside a
// fresh temp dir and returns its path. Writing a new file into it fails for
// non-root users, exercising the create/rename error branches of
// atomicWriteFile.
func ioReadonlyDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	// Restore write bit on cleanup so t.TempDir removal does not fail.
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	return dir
}

// ---------------------------------------------------------------------------
// atomicWriteFile error branches
// ---------------------------------------------------------------------------

func TestIOAtomicWriteFileCreateTempFails(t *testing.T) {
	ioSkipIfRoot(t)
	dir := ioReadonlyDir(t)
	err := atomicWriteFile(filepath.Join(dir, "out.bin"), []byte("data"), 0o600)
	if err == nil {
		t.Fatal("expected atomicWriteFile to fail creating temp in read-only dir")
	}
	if CodeOf(err) != CodeStateIntegrityFailure {
		t.Fatalf("want CodeStateIntegrityFailure, got %s", CodeOf(err))
	}
}

func TestIOAtomicWriteFileMissingParentDir(t *testing.T) {
	// The parent directory does not exist, so os.CreateTemp fails.
	missing := filepath.Join(t.TempDir(), "does-not-exist", "child", "out.bin")
	if err := atomicWriteFile(missing, []byte("x"), 0o600); CodeOf(err) != CodeStateIntegrityFailure {
		t.Fatalf("missing parent: want CodeStateIntegrityFailure, got %s", CodeOf(err))
	}
}

func TestIOAtomicWriteFileHappyPath(t *testing.T) {
	// Sanity: the success path (write + chmod + sync + rename + dir sync) works
	// so the error tests above are exercising deviations from a working flow.
	path := filepath.Join(t.TempDir(), "ok.bin")
	if err := atomicWriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatalf("atomicWriteFile happy path: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("round-trip mismatch: %q", got)
	}
}

// ---------------------------------------------------------------------------
// RollbackStore.saveLocked / Save write-failure branches
// ---------------------------------------------------------------------------

func TestIORollbackSaveWriteFails(t *testing.T) {
	ioSkipIfRoot(t)
	dir := ioReadonlyDir(t)
	store, err := NewRollbackStore(filepath.Join(dir, "rollback.state"), []byte("key"), 0)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	st := &RollbackState{LastTrustedTime: time.Now().UTC(), LastVerifiedAt: time.Now().UTC()}
	if err := store.Save(st); CodeOf(err) != CodeStateIntegrityFailure {
		t.Fatalf("save into read-only dir: want CodeStateIntegrityFailure, got %s", CodeOf(err))
	}
}

func TestIORollbackSaveNilState(t *testing.T) {
	store, err := NewRollbackStore(filepath.Join(t.TempDir(), "rollback.state"), []byte("key"), 0)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := store.saveLocked(nil); CodeOf(err) != CodeStateIntegrityFailure {
		t.Fatalf("nil state: want CodeStateIntegrityFailure, got %s", CodeOf(err))
	}
}

// ---------------------------------------------------------------------------
// RollbackStore.loadLocked read/permission/MAC failure branches
// ---------------------------------------------------------------------------

func TestIORollbackLoadReadPermissionDenied(t *testing.T) {
	ioSkipIfRoot(t)
	path := filepath.Join(t.TempDir(), "rollback.state")
	if err := os.WriteFile(path, []byte(`{"last_trusted_time":"2024-01-01T00:00:00Z","last_verified_at":"2024-01-01T00:00:00Z","mac":"00"}`), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Remove all permissions so os.ReadFile fails with a non-NotExist error.
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	store, err := NewRollbackStore(path, []byte("key"), 0)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if _, err := store.Load(); CodeOf(err) != CodeStateIntegrityFailure {
		t.Fatalf("unreadable state: want CodeStateIntegrityFailure, got %s", CodeOf(err))
	}
}

func TestIORollbackLoadBadMACEncoding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollback.state")
	// Structurally valid JSON but a non-hex MAC triggers the hex-decode branch.
	if err := os.WriteFile(path, []byte(`{"last_trusted_time":"2024-01-01T00:00:00Z","last_verified_at":"2024-01-01T00:00:00Z","mac":"zz"}`), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	store, err := NewRollbackStore(path, []byte("key"), 0)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if _, err := store.Load(); CodeOf(err) != CodeStateIntegrityFailure {
		t.Fatalf("bad mac encoding: want CodeStateIntegrityFailure, got %s", CodeOf(err))
	}
}

func TestIORollbackLoadMACMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollback.state")
	// Well-formed hex MAC of the right length but computed with the wrong key
	// (here just zeros) triggers the constant-time compare mismatch branch.
	if err := os.WriteFile(path, []byte(`{"last_trusted_time":"2024-01-01T00:00:00Z","last_verified_at":"2024-01-01T00:00:00Z","mac":"00"}`), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	store, err := NewRollbackStore(path, []byte("key"), 0)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if _, err := store.Load(); CodeOf(err) != CodeStateIntegrityFailure {
		t.Fatalf("mac mismatch: want CodeStateIntegrityFailure, got %s", CodeOf(err))
	}
}

// ---------------------------------------------------------------------------
// FileRevocationStateStore: constructor, loadFileLocked, SaveRevocationState
// ---------------------------------------------------------------------------

func TestIONewFileRevocationStateStoreRejectsEmpties(t *testing.T) {
	if _, err := NewFileRevocationStateStore("", []byte("k")); CodeOf(err) != CodeRevocationStateIntegrityFailure {
		t.Fatalf("empty path: want CodeRevocationStateIntegrityFailure, got %s", CodeOf(err))
	}
	if _, err := NewFileRevocationStateStore("p", nil); CodeOf(err) != CodeRevocationStateIntegrityFailure {
		t.Fatalf("empty key: want CodeRevocationStateIntegrityFailure, got %s", CodeOf(err))
	}
}

func TestIORevocationSaveWriteFails(t *testing.T) {
	ioSkipIfRoot(t)
	dir := ioReadonlyDir(t)
	store, err := NewFileRevocationStateStore(filepath.Join(dir, "revocation.state"), []byte("key"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	st := &RevocationState{ListID: "l", Sequence: 1, IssuedAt: time.Now().UTC(), PayloadDigest: "deadbeef"}
	if err := store.SaveRevocationState(st); CodeOf(err) != CodeRevocationStateIntegrityFailure {
		t.Fatalf("save into read-only dir: want CodeRevocationStateIntegrityFailure, got %s", CodeOf(err))
	}
}

func TestIORevocationSaveNilState(t *testing.T) {
	store, err := NewFileRevocationStateStore(filepath.Join(t.TempDir(), "revocation.state"), []byte("key"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := store.SaveRevocationState(nil); CodeOf(err) != CodeRevocationStateIntegrityFailure {
		t.Fatalf("nil state: want CodeRevocationStateIntegrityFailure, got %s", CodeOf(err))
	}
}

func TestIORevocationLoadMissingIsEmpty(t *testing.T) {
	store, err := NewFileRevocationStateStore(filepath.Join(t.TempDir(), "revocation.state"), []byte("key"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	got, err := store.LoadRevocationState("anything")
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if got != nil {
		t.Fatalf("missing entry should be nil, got %+v", got)
	}
}

func TestIORevocationLoadReadPermissionDenied(t *testing.T) {
	ioSkipIfRoot(t)
	path := filepath.Join(t.TempDir(), "revocation.state")
	if err := os.WriteFile(path, []byte(`{"entries":{},"mac":"00"}`), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	store, err := NewFileRevocationStateStore(path, []byte("key"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if _, err := store.LoadRevocationState("l"); CodeOf(err) != CodeRevocationStateIntegrityFailure {
		t.Fatalf("unreadable state: want CodeRevocationStateIntegrityFailure, got %s", CodeOf(err))
	}
}

func TestIORevocationLoadOversized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revocation.state")
	big := make([]byte, MaxRevocationFileSize+1)
	for i := range big {
		big[i] = 'x'
	}
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	store, err := NewFileRevocationStateStore(path, []byte("key"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if _, err := store.LoadRevocationState("l"); CodeOf(err) != CodeRevocationStateIntegrityFailure {
		t.Fatalf("oversized state: want CodeRevocationStateIntegrityFailure, got %s", CodeOf(err))
	}
}

func TestIORevocationLoadCorruptJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revocation.state")
	if err := os.WriteFile(path, []byte(`{"entries":`), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	store, err := NewFileRevocationStateStore(path, []byte("key"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if _, err := store.LoadRevocationState("l"); CodeOf(err) != CodeRevocationStateIntegrityFailure {
		t.Fatalf("corrupt json: want CodeRevocationStateIntegrityFailure, got %s", CodeOf(err))
	}
}

func TestIORevocationLoadBadMACEncoding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revocation.state")
	if err := os.WriteFile(path, []byte(`{"entries":{},"mac":"zz"}`), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	store, err := NewFileRevocationStateStore(path, []byte("key"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if _, err := store.LoadRevocationState("l"); CodeOf(err) != CodeRevocationStateIntegrityFailure {
		t.Fatalf("bad mac encoding: want CodeRevocationStateIntegrityFailure, got %s", CodeOf(err))
	}
}

func TestIORevocationLoadMACMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revocation.state")
	// Valid hex MAC but not the one computed over the (empty) entries map.
	if err := os.WriteFile(path, []byte(`{"entries":{},"mac":"00"}`), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	store, err := NewFileRevocationStateStore(path, []byte("key"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if _, err := store.LoadRevocationState("l"); CodeOf(err) != CodeRevocationStateIntegrityFailure {
		t.Fatalf("mac mismatch: want CodeRevocationStateIntegrityFailure, got %s", CodeOf(err))
	}
}

func TestIORevocationSaveThenLoadRoundTrip(t *testing.T) {
	// Confirms saveLocked's write path succeeds and loadFileLocked verifies the
	// freshly-computed MAC, so the failure tests above deviate from a working
	// baseline.
	path := filepath.Join(t.TempDir(), "revocation.state")
	store, err := NewFileRevocationStateStore(path, []byte("key"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	want := &RevocationState{ListID: "l", Sequence: 7, IssuedAt: time.Now().UTC().Truncate(time.Second), PayloadDigest: "abcd"}
	if err := store.SaveRevocationState(want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := store.LoadRevocationState("l")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got == nil || got.Sequence != want.Sequence || got.PayloadDigest != want.PayloadDigest {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

// ---------------------------------------------------------------------------
// Manager.LoadAndValidate stat / too-large / read-failure branches
// ---------------------------------------------------------------------------

func TestIOLoadAndValidateFileNotFound(t *testing.T) {
	mgr := NewManager(NewKeyRing(), WithUnscopedProductValidation())
	path := filepath.Join(t.TempDir(), "nope.lic")
	res, err := mgr.LoadAndValidate(path, ValidationContext{})
	if CodeOf(err) != CodeFileNotFound {
		t.Fatalf("missing file: want CodeFileNotFound, got %s", CodeOf(err))
	}
	if res.Valid() {
		t.Fatal("missing file must not produce a valid result")
	}
}

func TestIOLoadAndValidateFileTooLarge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.lic")
	big := make([]byte, MaxLicenseFileSize+1)
	for i := range big {
		big[i] = 'x'
	}
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	mgr := NewManager(NewKeyRing(), WithUnscopedProductValidation())
	if _, err := mgr.LoadAndValidate(path, ValidationContext{}); CodeOf(err) != CodeFileTooLarge {
		t.Fatalf("oversized file: want CodeFileTooLarge, got %s", CodeOf(err))
	}
}

func TestIOLoadAndValidatePathIsDirectory(t *testing.T) {
	// A directory stats fine (exists, small size) but os.ReadFile fails, hitting
	// the read-failure branch that maps to CodeMalformed.
	dir := t.TempDir()
	mgr := NewManager(NewKeyRing(), WithUnscopedProductValidation())
	if _, err := mgr.LoadAndValidate(dir, ValidationContext{}); CodeOf(err) != CodeMalformed {
		t.Fatalf("directory path: want CodeMalformed, got %s", CodeOf(err))
	}
}

// ---------------------------------------------------------------------------
// Manager.GetDeviceRequestCode delegation
// ---------------------------------------------------------------------------

func TestIOGetDeviceRequestCodeDelegates(t *testing.T) {
	mgr := NewManager(NewKeyRing())
	code, err := mgr.GetDeviceRequestCode("acme-app")
	// The delegation is environment-dependent: on a machine with a stable
	// hardware identifier it returns a code; otherwise fingerprint reports
	// insufficient info. Accept either outcome; just ensure it executed without
	// an unexpected error.
	if err != nil {
		if !errors.Is(err, fingerprint.ErrInsufficientInfo) {
			t.Fatalf("unexpected error from GetDeviceRequestCode: %v", err)
		}
		return
	}
	if code == "" {
		t.Fatal("expected a non-empty request code when no error is returned")
	}
}
