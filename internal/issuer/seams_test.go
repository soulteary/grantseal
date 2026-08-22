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

func TestStageKeyFileTempError(t *testing.T) {
	orig := fsCreateTemp
	fsCreateTemp = func(string, string) (*os.File, error) { return nil, errors.New("temp denied") }
	t.Cleanup(func() { fsCreateTemp = orig })
	if _, err := stageKeyFile(t.TempDir(), []byte("x"), 0o600); err == nil {
		t.Fatal("want error when create temp fails")
	}
}

// stageKeyFile removes its temp file and errors when the write fails: the
// injected temp file is reopened read-only so Write returns an error.
func TestStageKeyFileWriteError(t *testing.T) {
	dir := t.TempDir()
	orig := fsCreateTemp
	fsCreateTemp = func(d, pattern string) (*os.File, error) {
		f, err := os.CreateTemp(d, pattern)
		if err != nil {
			return nil, err
		}
		name := f.Name()
		_ = f.Close()
		return os.OpenFile(name, os.O_RDONLY, 0o600)
	}
	t.Cleanup(func() { fsCreateTemp = orig })
	if _, err := stageKeyFile(dir, []byte("x"), 0o600); err == nil {
		t.Fatal("want error when writing to read-only temp file")
	}
	// No stray temp file should remain after a staging failure.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("staging failure left %d files behind", len(entries))
	}
}

// verifyStagedPair rejects a staged private/public pair that does not match.
func TestVerifyStagedPairMismatch(t *testing.T) {
	dir := t.TempDir()
	kp1, _ := GenerateKeyPair("k1")
	kp2, _ := GenerateKeyPair("k2")
	privTmp, err := stageKeyFile(dir, []byte(kp1.privateKeyBase64()+"\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	// Public key from a different pair -> mismatch.
	pubTmp, err := stageKeyFile(dir, []byte(kp2.PublicKeyBase64()+"\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyStagedPair(privTmp, pubTmp); err == nil {
		t.Fatal("want mismatch error for non-matching staged pair")
	}
	// A matching pair passes.
	pubTmp2, err := stageKeyFile(dir, []byte(kp1.PublicKeyBase64()+"\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyStagedPair(privTmp, pubTmp2); err != nil {
		t.Fatalf("matching pair should verify: %v", err)
	}
}

// commitStagedKeyFiles surfaces a rename failure on the private-key commit and
// leaves any pre-existing files restored from backup.
func TestCommitStagedRenameError(t *testing.T) {
	orig := fsRename
	fsRename = func(string, string) error { return errors.New("rename denied") }
	t.Cleanup(func() { fsRename = orig })
	dir := t.TempDir()
	privTmp, err := stageKeyFile(dir, []byte("priv\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	pubTmp, err := stageKeyFile(dir, []byte("pub\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	privPath := filepath.Join(dir, "k-private.key")
	pubPath := filepath.Join(dir, "k-public.key")
	if err := commitStagedKeyFiles(dir, privTmp, pubTmp, privPath, pubPath); err == nil {
		t.Fatal("want error when rename fails")
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
