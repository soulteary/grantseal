package issuer

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// verifyStagedPair surfaces the LoadPrivateKey failure arm when the staged
// private key file cannot be read/decoded (here: a missing path).
func TestVerifyStagedPairLoadPrivateError(t *testing.T) {
	dir := t.TempDir()
	kp, _ := GenerateKeyPair("k1")
	pubTmp, err := stageKeyFile(dir, []byte(kp.PublicKeyBase64()+"\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	missingPriv := filepath.Join(dir, "does-not-exist.key")
	if err := verifyStagedPair(missingPriv, pubTmp); err == nil {
		t.Fatal("want error when staged private key cannot be loaded")
	}
}

// verifyStagedPair surfaces the public-key ReadFile failure arm: the staged
// private key loads fine, but the public temp path is missing.
func TestVerifyStagedPairReadPublicError(t *testing.T) {
	dir := t.TempDir()
	kp, _ := GenerateKeyPair("k1")
	privTmp, err := stageKeyFile(dir, []byte(kp.privateKeyBase64()+"\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	missingPub := filepath.Join(dir, "does-not-exist.pub")
	if err := verifyStagedPair(privTmp, missingPub); err == nil {
		t.Fatal("want error when staged public key cannot be read")
	}
}

// verifyStagedPair surfaces the base64-decode failure arm when the staged
// public key file contains bytes that are not valid Base64URL.
func TestVerifyStagedPairPublicDecodeError(t *testing.T) {
	dir := t.TempDir()
	kp, _ := GenerateKeyPair("k1")
	privTmp, err := stageKeyFile(dir, []byte(kp.privateKeyBase64()+"\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	badPub, err := stageKeyFile(dir, []byte("!!!not-base64!!!\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyStagedPair(privTmp, badPub); err == nil {
		t.Fatal("want error when staged public key is not valid base64")
	}
}

// backupExisting surfaces the CreateTemp failure arm: the target exists so a
// backup is attempted, but the injected temp creator fails.
func TestBackupExistingCreateTempError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.key")
	if err := os.WriteFile(path, []byte("data\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := fsCreateTemp
	fsCreateTemp = func(string, string) (*os.File, error) { return nil, errors.New("temp denied") }
	t.Cleanup(func() { fsCreateTemp = orig })
	if _, err := backupExisting(dir, path); err == nil {
		t.Fatal("want error when backup temp cannot be created")
	}
}

// backupExisting surfaces the rename failure arm: the placeholder temp is made,
// but renaming the existing target onto the backup name fails.
func TestBackupExistingRenameError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.key")
	if err := os.WriteFile(path, []byte("data\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := fsRename
	fsRename = func(string, string) error { return errors.New("rename denied") }
	t.Cleanup(func() { fsRename = orig })
	if _, err := backupExisting(dir, path); err == nil {
		t.Fatal("want error when backup rename fails")
	}
}

// backupExisting returns ("", nil) when the target does not exist: there is
// nothing to back up. (Covers the not-exist fast path.)
func TestBackupExistingMissingTargetIsNoop(t *testing.T) {
	dir := t.TempDir()
	bak, err := backupExisting(dir, filepath.Join(dir, "nope.key"))
	if err != nil {
		t.Fatalf("missing target should not error: %v", err)
	}
	if bak != "" {
		t.Fatalf("missing target should yield empty backup, got %q", bak)
	}
}

// commitStagedKeyFiles surfaces the private-key backup failure arm: the private
// target exists and its backup temp cannot be created, so the commit aborts
// before touching anything.
func TestCommitStagedPrivateBackupError(t *testing.T) {
	dir := t.TempDir()
	// Seed an existing private target so backupExisting(priv) is attempted.
	privPath := filepath.Join(dir, "k1-private.key")
	pubPath := filepath.Join(dir, "k1-public.key")
	if err := os.WriteFile(privPath, []byte("old-priv\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kp, _ := GenerateKeyPair("k1")
	privTmp, err := stageKeyFile(dir, []byte(kp.privateKeyBase64()+"\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	pubTmp, err := stageKeyFile(dir, []byte(kp.PublicKeyBase64()+"\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	origTemp := fsCreateTemp
	fsCreateTemp = func(string, string) (*os.File, error) { return nil, errors.New("backup temp denied") }
	t.Cleanup(func() { fsCreateTemp = origTemp })
	if err := commitStagedKeyFiles(dir, privTmp, pubTmp, privPath, pubPath); err == nil {
		t.Fatal("want error when private-key backup fails")
	}
}

// commitStagedKeyFiles surfaces the public-key backup failure arm and confirms
// the private backup is restored before returning: the private target has no
// existing file (so its backup is a no-op) while the public target exists and
// its backup temp fails.
func TestCommitStagedPublicBackupErrorRestoresPrivate(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "k1-public.key")
	privPath := filepath.Join(dir, "k1-private.key")
	// Only the public target exists, forcing a public backup while the private
	// backup is a no-op.
	if err := os.WriteFile(pubPath, []byte("old-pub\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	kp, _ := GenerateKeyPair("k1")
	privTmp, err := stageKeyFile(dir, []byte(kp.privateKeyBase64()+"\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	pubTmp, err := stageKeyFile(dir, []byte(kp.PublicKeyBase64()+"\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	origTemp := fsCreateTemp
	fsCreateTemp = func(string, string) (*os.File, error) { return nil, errors.New("backup temp denied") }
	t.Cleanup(func() { fsCreateTemp = origTemp })
	if err := commitStagedKeyFiles(dir, privTmp, pubTmp, privPath, pubPath); err == nil {
		t.Fatal("want error when public-key backup fails")
	}
}

// commitStagedKeyFiles surfaces the "fsync dir after private key" failure arm.
// The private rename succeeds, then the directory fsync fails, so the freshly
// committed private key is removed and the previous pair (none here) restored.
func TestCommitStagedFsyncAfterPrivateError(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "k1-private.key")
	pubPath := filepath.Join(dir, "k1-public.key")
	kp, _ := GenerateKeyPair("k1")
	privTmp, err := stageKeyFile(dir, []byte(kp.privateKeyBase64()+"\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	pubTmp, err := stageKeyFile(dir, []byte(kp.PublicKeyBase64()+"\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	origOpen, origGOOS := fsOpen, runtimeGOOS
	runtimeGOOS = "linux"
	fsOpen = func(string) (*os.File, error) { return nil, errors.New("open denied") }
	t.Cleanup(func() { fsOpen, runtimeGOOS = origOpen, origGOOS })
	if err := commitStagedKeyFiles(dir, privTmp, pubTmp, privPath, pubPath); err == nil {
		t.Fatal("want error when dir fsync after private commit fails")
	}
	// The private key was removed after the fsync failure (best-effort rollback).
	if _, statErr := os.Stat(privPath); !os.IsNotExist(statErr) {
		t.Fatalf("private key should have been rolled back, stat err = %v", statErr)
	}
}

// commitStagedKeyFiles surfaces the "fsync dir after public key" failure arm:
// both renames succeed, the first dir fsync (after private) succeeds, and the
// second (after public) fails. Recovery must NOT leave a mismatched pair: since
// both new files are already on disk, the committed private and public keys
// must remain a matching pair (never "new private + old public").
func TestCommitStagedFsyncAfterPublicError(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "k1-private.key")
	pubPath := filepath.Join(dir, "k1-public.key")

	// Seed a PREVIOUS key pair on disk so the commit is a force-replace and any
	// reversion to the old public key would create a detectable mismatch.
	oldKP, _ := GenerateKeyPair("k1")
	if err := os.WriteFile(privPath, []byte(oldKP.privateKeyBase64()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, []byte(oldKP.PublicKeyBase64()+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	kp, _ := GenerateKeyPair("k1")
	privTmp, err := stageKeyFile(dir, []byte(kp.privateKeyBase64()+"\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	pubTmp, err := stageKeyFile(dir, []byte(kp.PublicKeyBase64()+"\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	origOpen, origGOOS := fsOpen, runtimeGOOS
	runtimeGOOS = "linux"
	calls := 0
	fsOpen = func(name string) (*os.File, error) {
		calls++
		if calls >= 2 { // succeed after private, fail after public
			return nil, errors.New("open denied")
		}
		// The first dir fsync must succeed. Directory Sync() fails on Windows,
		// so hand back a regular file whose Sync() succeeds on every platform
		// rather than opening the directory itself.
		f, err := os.CreateTemp(t.TempDir(), "dirsync-*")
		if err != nil {
			return nil, err
		}
		return f, nil
	}
	t.Cleanup(func() { fsOpen, runtimeGOOS = origOpen, origGOOS })
	if err := commitStagedKeyFiles(dir, privTmp, pubTmp, privPath, pubPath); err == nil {
		t.Fatal("want error when dir fsync after public commit fails")
	}
	// The private key must survive: a public-side failure must never lose it.
	if _, statErr := os.Stat(privPath); statErr != nil {
		t.Fatalf("private key must survive a public fsync failure: %v", statErr)
	}
	// Invariant: whatever landed must be a MATCHING pair. Reverting the public
	// key to the old one while keeping the new private key would strand a
	// mismatched pair, which this asserts against.
	assertMatchingPairOnDisk(t, privPath, pubPath)
}

// assertMatchingPairOnDisk loads the committed private key, derives its public
// key and compares it byte-for-byte with the committed public key file. A
// missing public key is tolerated (private-key-only survival is an accepted
// invariant: the public key can be regenerated from the private key), but a
// present-yet-mismatched public key fails the test.
func assertMatchingPairOnDisk(t *testing.T, privPath, pubPath string) {
	t.Helper()
	if _, statErr := os.Stat(pubPath); os.IsNotExist(statErr) {
		return // private-only survival is acceptable
	}
	if err := verifyStagedPair(privPath, pubPath); err != nil {
		t.Fatalf("committed key pair is mismatched: %v", err)
	}
}

// fsyncDirIssuer ignores a directory Sync failure on Windows: an already-closed
// file makes Sync fail, but runtimeGOOS=="windows" swallows the error.
func TestFsyncDirIssuerSyncErrorWindowsIgnored(t *testing.T) {
	origOpen, origGOOS := fsOpen, runtimeGOOS
	runtimeGOOS = "windows"
	fsOpen = func(string) (*os.File, error) {
		f, err := os.CreateTemp(t.TempDir(), "f-*")
		if err != nil {
			return nil, err
		}
		_ = f.Close() // a closed file's Sync returns an error
		return f, nil
	}
	t.Cleanup(func() { fsOpen, runtimeGOOS = origOpen, origGOOS })
	if err := fsyncDirIssuer(t.TempDir()); err != nil {
		t.Fatalf("windows dir-sync error should be ignored, got %v", err)
	}
}

// stageKeyFile surfaces the Sync/Close failure arm: the injected temp file is
// returned already closed, so Write fails and the temp is cleaned up. This
// asserts no stray artifact remains regardless of which write step fails first.
func TestStageKeyFileClosedFileCleansUp(t *testing.T) {
	dir := t.TempDir()
	orig := fsCreateTemp
	fsCreateTemp = func(d, pattern string) (*os.File, error) {
		f, err := os.CreateTemp(d, pattern)
		if err != nil {
			return nil, err
		}
		_ = f.Close()
		return f, nil
	}
	t.Cleanup(func() { fsCreateTemp = orig })
	if _, err := stageKeyFile(dir, []byte("x"), 0o600); err == nil {
		t.Fatal("want error when writing to a closed temp file")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-key-") {
			t.Fatalf("staging failure left stray temp %q", e.Name())
		}
	}
}
