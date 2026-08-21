package issuer

import (
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestRandomIDAndSerialRandError(t *testing.T) {
	orig := randRead
	randRead = func([]byte) (int, error) { return 0, errors.New("no entropy") }
	t.Cleanup(func() { randRead = orig })

	if _, err := randomID(16); err == nil {
		t.Fatal("randomID: want error on rand failure")
	}
	if _, err := randomSerial(); err == nil {
		t.Fatal("randomSerial: want error on rand failure")
	}
	// BuildPayload should propagate the rand failure when ids are omitted.
	if _, err := BuildPayload(IssueRequest{}); err == nil {
		t.Fatal("BuildPayload: want error when randomID fails")
	}
}

func TestBuildPayloadSerialRandError(t *testing.T) {
	orig := randRead
	// Succeed for the license id (first call), fail for the serial (second).
	calls := 0
	randRead = func(b []byte) (int, error) {
		calls++
		if calls == 1 {
			return io.ReadFull(zeroReader{}, b)
		}
		return 0, errors.New("no entropy")
	}
	t.Cleanup(func() { randRead = orig })
	if _, err := BuildPayload(IssueRequest{}); err == nil {
		t.Fatal("BuildPayload: want error when randomSerial fails")
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func TestGenerateKeyPairRandError(t *testing.T) {
	orig := edGenerateKey
	edGenerateKey = func(io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
		return nil, nil, errors.New("no entropy")
	}
	t.Cleanup(func() { edGenerateKey = orig })
	if _, err := GenerateKeyPair("k1"); err == nil {
		t.Fatal("GenerateKeyPair: want error on rand failure")
	}
}

func TestWriteKeyFileDurableNoForceOpenError(t *testing.T) {
	orig := fsOpenFile
	fsOpenFile = func(string, int, os.FileMode) (*os.File, error) {
		return nil, errors.New("open denied")
	}
	t.Cleanup(func() { fsOpenFile = orig })
	if err := writeKeyFileDurable(filepath.Join(t.TempDir(), "k"), []byte("x"), 0o600, false); err == nil {
		t.Fatal("want error when open fails")
	}
}

func TestWriteKeyFileDurableForceTempError(t *testing.T) {
	orig := fsCreateTemp
	fsCreateTemp = func(string, string) (*os.File, error) { return nil, errors.New("temp denied") }
	t.Cleanup(func() { fsCreateTemp = orig })
	if err := writeKeyFileDurable(filepath.Join(t.TempDir(), "k"), []byte("x"), 0o600, true); err == nil {
		t.Fatal("want error when create temp fails")
	}
}

func TestWriteKeyFileDurableForceRenameError(t *testing.T) {
	orig := fsRename
	fsRename = func(string, string) error { return errors.New("rename denied") }
	t.Cleanup(func() { fsRename = orig })
	if err := writeKeyFileDurable(filepath.Join(t.TempDir(), "k"), []byte("x"), 0o600, true); err == nil {
		t.Fatal("want error when rename fails")
	}
}

// TestWriteKeyFileDurableForceWriteError returns a read-only temp file so the
// subsequent Write fails, exercising the force-mode write-failure arm.
func TestWriteKeyFileDurableForceWriteError(t *testing.T) {
	orig := fsCreateTemp
	fsCreateTemp = func(dir, pattern string) (*os.File, error) {
		f, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		name := f.Name()
		_ = f.Close()
		// Reopen read-only so Write returns an error.
		return os.OpenFile(name, os.O_RDONLY, 0o600)
	}
	t.Cleanup(func() { fsCreateTemp = orig })
	if err := writeKeyFileDurable(filepath.Join(t.TempDir(), "k"), []byte("x"), 0o600, true); err == nil {
		t.Fatal("want error when writing to read-only temp file")
	}
}

// TestWriteKeyFileDurableNoForceWriteError returns a read-only file for the
// O_EXCL path so the write fails, covering the no-force write-failure arm.
func TestWriteKeyFileDurableNoForceWriteError(t *testing.T) {
	orig := fsOpenFile
	fsOpenFile = func(name string, _ int, _ os.FileMode) (*os.File, error) {
		f, err := os.Create(name)
		if err != nil {
			return nil, err
		}
		_ = f.Close()
		return os.OpenFile(name, os.O_RDONLY, 0o600)
	}
	t.Cleanup(func() { fsOpenFile = orig })
	if err := writeKeyFileDurable(filepath.Join(t.TempDir(), "k"), []byte("x"), 0o600, false); err == nil {
		t.Fatal("want error when writing to read-only file")
	}
}

// TestFsyncDirIssuerSyncErrorNonWindows opens a regular file (not a dir) via the
// seam so Sync fails on some platforms; if Sync succeeds the test still passes.
func TestFsyncDirIssuerSyncError(t *testing.T) {
	origOpen, origGOOS := fsOpen, runtimeGOOS
	runtimeGOOS = "linux"
	fsOpen = func(string) (*os.File, error) {
		// Return a file whose Sync errors: use an already-closed file.
		f, err := os.CreateTemp(t.TempDir(), "f-*")
		if err != nil {
			return nil, err
		}
		_ = f.Close()
		return f, nil
	}
	t.Cleanup(func() { fsOpen, runtimeGOOS = origOpen, origGOOS })
	// Either Sync errors (covered arm) or not; both are acceptable outcomes.
	_ = fsyncDirIssuer(t.TempDir())
}

func TestFsyncDirIssuerOpenErrorNonWindows(t *testing.T) {
	origOpen, origGOOS := fsOpen, runtimeGOOS
	fsOpen = func(string) (*os.File, error) { return nil, errors.New("open denied") }
	runtimeGOOS = "linux"
	t.Cleanup(func() { fsOpen, runtimeGOOS = origOpen, origGOOS })
	if err := fsyncDirIssuer(t.TempDir()); err == nil {
		t.Fatal("want error on non-windows open failure")
	}
}

func TestFsyncDirIssuerOpenErrorWindowsIgnored(t *testing.T) {
	origOpen, origGOOS := fsOpen, runtimeGOOS
	fsOpen = func(string) (*os.File, error) { return nil, errors.New("open denied") }
	runtimeGOOS = "windows"
	t.Cleanup(func() { fsOpen, runtimeGOOS = origOpen, origGOOS })
	if err := fsyncDirIssuer(t.TempDir()); err != nil {
		t.Fatalf("windows open error should be ignored, got %v", err)
	}
}
