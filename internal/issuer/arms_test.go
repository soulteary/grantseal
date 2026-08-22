package issuer

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/soulteary/grantseal/pkg/license"
)

func TestBuildRevocationListNilSigner(t *testing.T) {
	if _, err := BuildRevocationList(nil, []string{"a"}); err == nil {
		t.Fatal("want error on nil signer")
	}
}

func TestBuildRevocationListV2Arms(t *testing.T) {
	if _, err := BuildRevocationListV2(nil, RevocationListOptions{}); err == nil {
		t.Fatal("nil signer: want error")
	}
	s := newTestSigner(t)
	if _, err := BuildRevocationListV2(s, RevocationListOptions{Sequence: 1, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour)}); err == nil {
		t.Fatal("empty list_id: want error")
	}
	if _, err := BuildRevocationListV2(s, RevocationListOptions{ListID: "l", Sequence: 0}); err == nil {
		t.Fatal("zero sequence: want error")
	}
	if _, err := BuildRevocationListV2(s, RevocationListOptions{ListID: "l", Sequence: 1}); err == nil {
		t.Fatal("zero issued_at: want error")
	}
	now := time.Now().UTC()
	if _, err := BuildRevocationListV2(s, RevocationListOptions{ListID: "l", Sequence: 1, IssuedAt: now, ExpiresAt: now.Add(-time.Hour)}); err == nil {
		t.Fatal("expires before issued: want error")
	}
}

// TestIssueBuildPayloadRandError drives Issue -> BuildPayload rand-failure arm.
func TestIssueBuildPayloadRandError(t *testing.T) {
	orig := randRead
	randRead = func([]byte) (int, error) { return 0, errors.New("no entropy") }
	t.Cleanup(func() { randRead = orig })
	s := newTestSigner(t)
	if _, err := Issue(s, IssueRequest{}); err == nil {
		t.Fatal("want error when BuildPayload fails")
	}
}

// TestIssueStaticValidationError drives Issue's ValidatePayloadStatic error arm
// by supplying an invalid edition/type that static validation rejects.
func TestIssueStaticValidationError(t *testing.T) {
	s := newTestSigner(t)
	req := IssueRequest{
		LicenseID:    "lic_x",
		SerialNumber: "SER-1",
		ProductID:    "prod",
		Edition:      license.Edition("bogus-edition"),
		LicenseType:  license.LicenseType("bogus-type"),
	}
	if _, err := Issue(s, req); err == nil {
		t.Fatal("want static validation error for invalid enums")
	}
}

func newTestSigner(t *testing.T) *Signer {
	t.Helper()
	kp, err := GenerateKeyPair("test-key")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(kp.KeyID, kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// countKeyDirEntries returns how many entries in dir are NOT the two committed
// key files, i.e. any leftover staging temp (".tmp-key-*") or backup
// (".bak-key-*") artifacts that must not survive a call.
func countStrayKeyArtifacts(t *testing.T, dir, keyID string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	priv := keyID + "-private.key"
	pub := keyID + "-public.key"
	stray := 0
	for _, e := range entries {
		if e.Name() == priv || e.Name() == pub {
			continue
		}
		stray++
	}
	return stray
}

// TestWriteKeyFilesForceDerivesMatchingPublic covers the happy force path: the
// committed public key must be derivable from the committed private key and no
// staging/backup artifacts may remain.
func TestWriteKeyFilesForceDerivesMatchingPublic(t *testing.T) {
	dir := t.TempDir()
	kp1, _ := GenerateKeyPair("k1")
	if _, _, err := kp1.WriteKeyFiles(dir, false); err != nil {
		t.Fatal(err)
	}
	kp2, _ := GenerateKeyPair("k1")
	privPath, pubPath, err := kp2.WriteKeyFiles(dir, true)
	if err != nil {
		t.Fatalf("force overwrite failed: %v", err)
	}
	priv, err := LoadPrivateKey(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.Equal(kp2.PrivateKey) {
		t.Fatal("committed private key is not the latest pair")
	}
	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if trimSpace(string(pubData)) != kp2.PublicKeyBase64() {
		t.Fatal("committed public key does not match private key's derivation")
	}
	if n := countStrayKeyArtifacts(t, dir, "k1"); n != 0 {
		t.Fatalf("force success left %d stray artifacts", n)
	}
}

// TestWriteKeyFilesForcePublicCommitFailureKeepsPrivate injects a rename
// failure on the SECOND rename (the public-key commit). The freshly committed
// private key must survive and remain loadable; a public commit failure must
// never delete the private key.
func TestWriteKeyFilesForcePublicCommitFailureKeepsPrivate(t *testing.T) {
	dir := t.TempDir()
	// Seed an existing pair so backups are involved too.
	kp0, _ := GenerateKeyPair("k1")
	if _, _, err := kp0.WriteKeyFiles(dir, false); err != nil {
		t.Fatal(err)
	}

	kp1, _ := GenerateKeyPair("k1")
	orig := fsRename
	privPath := filepath.Join(dir, "k1-private.key")
	calls := 0
	fsRename = func(oldp, newp string) error {
		// Fail only when committing the staged public key into place (temp ->
		// public.key), not backup moves or restores.
		if filepath.Base(newp) == "k1-public.key" && strings.HasPrefix(filepath.Base(oldp), ".tmp-key-") {
			return errors.New("public commit denied")
		}
		calls++
		return orig(oldp, newp)
	}
	t.Cleanup(func() { fsRename = orig })

	if _, _, err := kp1.WriteKeyFiles(dir, true); err == nil {
		t.Fatal("want error when public-key commit fails")
	}
	// The new private key was committed before the public failure and must NOT
	// have been deleted; it must be loadable and be the new key.
	loaded, err := LoadPrivateKey(privPath)
	if err != nil {
		t.Fatalf("private key lost after public commit failure: %v", err)
	}
	if !loaded.Equal(kp1.PrivateKey) {
		t.Fatal("private key on disk is not the newly committed one")
	}
	// The previous public key must have been restored, and no stale backup or
	// staging temp may remain (the committed private key makes its backup
	// redundant).
	if _, err := os.Stat(filepath.Join(dir, "k1-public.key")); err != nil {
		t.Fatalf("public key missing after restore: %v", err)
	}
	fsRename = orig
	if n := countStrayKeyArtifacts(t, dir, "k1"); n != 0 {
		t.Fatalf("public commit failure left %d stray artifacts", n)
	}
	_ = calls
}

// TestWriteKeyFilesForcePrivateCommitFailureKeepsOldPair injects a rename
// failure on the private-key commit. The previously existing private and
// public key must be restored unchanged.
func TestWriteKeyFilesForcePrivateCommitFailureKeepsOldPair(t *testing.T) {
	dir := t.TempDir()
	kp0, _ := GenerateKeyPair("k1")
	if _, _, err := kp0.WriteKeyFiles(dir, false); err != nil {
		t.Fatal(err)
	}
	privPath := filepath.Join(dir, "k1-private.key")
	pubPath := filepath.Join(dir, "k1-public.key")
	oldPriv, _ := os.ReadFile(privPath)
	oldPub, _ := os.ReadFile(pubPath)

	kp1, _ := GenerateKeyPair("k1")
	orig := fsRename
	fsRename = func(oldp, newp string) error {
		// Fail only the staged-temp -> private target commit, not backup moves
		// or restores (which rename from/to .bak-key-* names).
		if filepath.Base(newp) == "k1-private.key" && strings.HasPrefix(filepath.Base(oldp), ".tmp-key-") {
			return errors.New("private commit denied")
		}
		return orig(oldp, newp)
	}
	t.Cleanup(func() { fsRename = orig })

	if _, _, err := kp1.WriteKeyFiles(dir, true); err == nil {
		t.Fatal("want error when private-key commit fails")
	}
	fsRename = orig

	gotPriv, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("old private key missing after failed commit: %v", err)
	}
	gotPub, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("old public key missing after failed commit: %v", err)
	}
	if string(gotPriv) != string(oldPriv) {
		t.Fatal("old private key was changed after a failed private commit")
	}
	if string(gotPub) != string(oldPub) {
		t.Fatal("old public key was changed after a failed private commit")
	}
	if loaded, err := LoadPrivateKey(privPath); err != nil || !loaded.Equal(kp0.PrivateKey) {
		t.Fatalf("restored private key is not the original pair: %v", err)
	}
	if n := countStrayKeyArtifacts(t, dir, "k1"); n != 0 {
		t.Fatalf("failed private commit left %d stray artifacts", n)
	}
}

// TestWriteKeyFilesNoForcePublicExistsLeavesEverything verifies that no-force
// mode never creates or modifies any file when EITHER target already exists.
func TestWriteKeyFilesNoForcePublicExistsLeavesEverything(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "k1-public.key")
	if err := os.WriteFile(pubPath, []byte("preexisting\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	kp, _ := GenerateKeyPair("k1")
	if _, _, err := kp.WriteKeyFiles(dir, false); err == nil {
		t.Fatal("want refusal when public target already exists (no force)")
	}
	if _, err := os.Stat(filepath.Join(dir, "k1-private.key")); !os.IsNotExist(err) {
		t.Fatalf("private key must not be created when public target exists: %v", err)
	}
	pub, _ := os.ReadFile(pubPath)
	if string(pub) != "preexisting\n" {
		t.Fatal("pre-existing public key was modified")
	}
	if n := countStrayKeyArtifacts(t, dir, "k1"); n != 0 {
		t.Fatalf("no-force refusal left %d stray artifacts", n)
	}
}

// TestWriteKeyFilesNoForcePrivateExistsLeavesEverything is the symmetric case
// where only the private target exists.
func TestWriteKeyFilesNoForcePrivateExistsLeavesEverything(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "k1-private.key")
	if err := os.WriteFile(privPath, []byte("preexisting\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kp, _ := GenerateKeyPair("k1")
	if _, _, err := kp.WriteKeyFiles(dir, false); err == nil {
		t.Fatal("want refusal when private target already exists (no force)")
	}
	if _, err := os.Stat(filepath.Join(dir, "k1-public.key")); !os.IsNotExist(err) {
		t.Fatalf("public key must not be created when private target exists: %v", err)
	}
	priv, _ := os.ReadFile(privPath)
	if string(priv) != "preexisting\n" {
		t.Fatal("pre-existing private key was modified")
	}
}

// TestWriteKeyFilesStagePublicFailureLeavesTargetsUntouched injects a temp
// failure on the SECOND staging call (public key) and confirms the existing
// private/public targets are untouched and no stray artifacts remain.
func TestWriteKeyFilesStagePublicFailureLeavesTargetsUntouched(t *testing.T) {
	dir := t.TempDir()
	kp0, _ := GenerateKeyPair("k1")
	if _, _, err := kp0.WriteKeyFiles(dir, false); err != nil {
		t.Fatal(err)
	}
	privPath := filepath.Join(dir, "k1-private.key")
	oldPriv, _ := os.ReadFile(privPath)

	orig := fsCreateTemp
	calls := 0
	fsCreateTemp = func(d, pattern string) (*os.File, error) {
		calls++
		if calls == 2 { // first stages private, second stages public
			return nil, errors.New("temp denied")
		}
		return orig(d, pattern)
	}
	t.Cleanup(func() { fsCreateTemp = orig })

	kp1, _ := GenerateKeyPair("k1")
	if _, _, err := kp1.WriteKeyFiles(dir, true); err == nil {
		t.Fatal("want error when staging public key fails")
	}
	fsCreateTemp = orig

	gotPriv, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("existing private key missing after staging failure: %v", err)
	}
	if string(gotPriv) != string(oldPriv) {
		t.Fatal("existing private key changed after a staging failure")
	}
	if n := countStrayKeyArtifacts(t, dir, "k1"); n != 0 {
		t.Fatalf("staging failure left %d stray artifacts", n)
	}
}

// TestWriteKeyFilesPermissions asserts the committed private/public modes on
// platforms that honour Unix permission bits.
func TestWriteKeyFilesPermissions(t *testing.T) {
	dir := t.TempDir()
	kp, _ := GenerateKeyPair("k1")
	privPath, pubPath, err := kp.WriteKeyFiles(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if runtimeGOOS == "windows" {
		t.Skip("Unix permission bits are not enforced on Windows")
	}
	pfi, err := os.Stat(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if pfi.Mode().Perm() != 0o600 {
		t.Fatalf("private mode = %o, want 0600", pfi.Mode().Perm())
	}
	ufi, err := os.Stat(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if ufi.Mode().Perm() != 0o644 {
		t.Fatalf("public mode = %o, want 0644", ufi.Mode().Perm())
	}
}
