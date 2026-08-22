package issuer_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/soulteary/grantseal/internal/issuer"
	"github.com/soulteary/grantseal/pkg/license"
)

// Key generation produces distinct random license IDs / serials.
func TestRandomLicenseIDAndSerialUnique(t *testing.T) {
	kp, err := issuer.GenerateKeyPair("k1")
	if err != nil {
		t.Fatal(err)
	}
	s, err := issuer.NewSigner(kp.KeyID, kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	seenID := map[string]bool{}
	seenSerial := map[string]bool{}
	for i := 0; i < 100; i++ {
		p, err := issuer.BuildPayload(issuer.IssueRequest{
			ProductID:     "p",
			Edition:       license.EditionBasic,
			LicenseType:   license.LicenseTypeSubscription,
			DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
		})
		if err != nil {
			t.Fatal(err)
		}
		if seenID[p.LicenseID] {
			t.Fatalf("duplicate license_id %q", p.LicenseID)
		}
		if seenSerial[p.SerialNumber] {
			t.Fatalf("duplicate serial %q", p.SerialNumber)
		}
		seenID[p.LicenseID] = true
		seenSerial[p.SerialNumber] = true
	}
	_ = s
}

// Private key files are written with 0600 and refuse to clobber.
func TestWriteKeyFilesPermissionsAndNoClobber(t *testing.T) {
	dir := t.TempDir()
	kp, err := issuer.GenerateKeyPair("k1")
	if err != nil {
		t.Fatal(err)
	}
	privPath, pubPath, err := kp.WriteKeyFiles(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pubPath); err != nil {
		t.Fatalf("public key missing: %v", err)
	}
	// Windows does not honour Unix permission bits; files always report ~0666.
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode = %o, want 0600", fi.Mode().Perm())
	}
	// Second write without force must fail (no clobber).
	if _, _, err := kp.WriteKeyFiles(dir, false); err == nil {
		t.Fatal("expected no-clobber error on existing private key")
	}
}

// LoadPrivateKey rejects world-readable key files.
func TestLoadPrivateKeyRejectsLoosePerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits are not enforced on Windows")
	}
	dir := t.TempDir()
	kp, _ := issuer.GenerateKeyPair("k1")
	privPath, _, err := kp.WriteKeyFiles(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(privPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.LoadPrivateKey(privPath); err == nil {
		t.Fatal("expected rejection of 0644 private key")
	}
}

// Round-trip: issue then load key back and verify signature via public key.
func TestIssueRoundTrip(t *testing.T) {
	dir := t.TempDir()
	kp, _ := issuer.GenerateKeyPair("k1")
	privPath, pubPath, err := kp.WriteKeyFiles(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := issuer.LoadPrivateKey(privPath)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := issuer.NewSigner("k1", priv)
	env, err := issuer.Issue(signer, issuer.IssueRequest{
		ProductID:     "p",
		Edition:       license.EditionEnterprise,
		LicenseType:   license.LicenseTypeLifetime,
		DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
	})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := env.MarshalJSONIndent()

	pubB64, _ := os.ReadFile(pubPath)
	ring := license.NewKeyRing()
	if err := ring.AddPublicKeyBase64("k1", string(pubB64)); err != nil {
		t.Fatal(err)
	}
	mgr := license.NewManager(ring)
	res, err := mgr.Validate(data, license.ValidationContext{ProductID: "p"})
	if err != nil || !res.Valid() {
		t.Fatalf("round-trip validation failed: %v", err)
	}
	_ = filepath.Base(privPath)
}

// WriteKeyFiles with force=true atomically replaces existing key files instead
// of failing the no-clobber check, exercising the durable atomic-replace path.
func TestWriteKeyFilesForceOverwrite(t *testing.T) {
	dir := t.TempDir()
	kp, err := issuer.GenerateKeyPair("k1")
	if err != nil {
		t.Fatal(err)
	}
	privPath, pubPath, err := kp.WriteKeyFiles(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatal(err)
	}
	// A different key pair, written with force, must overwrite the first one.
	kp2, err := issuer.GenerateKeyPair("k1")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := kp2.WriteKeyFiles(dir, true); err != nil {
		t.Fatalf("force overwrite failed: %v", err)
	}
	second, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) == string(second) {
		t.Fatal("force write did not replace the private key contents")
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(privPath)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("private key mode after force = %o, want 0600", fi.Mode().Perm())
		}
	}
	if _, err := os.Stat(pubPath); err != nil {
		t.Fatalf("public key missing after force: %v", err)
	}
}

// WriteKeyFiles fails when the output path cannot be a directory (a regular
// file already occupies it), exercising the mkdir error branch.
func TestWriteKeyFilesMissingDir(t *testing.T) {
	kp, err := issuer.GenerateKeyPair("k1")
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	blocker := filepath.Join(base, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := kp.WriteKeyFiles(filepath.Join(blocker, "sub"), false); err == nil {
		t.Fatal("expected error when the directory path is blocked by a file")
	}
}

// BuildRevocationListV2 rejects malformed options and produces a domain-signed
// v2 list that verifies against the client under its default (v2-only) policy.
func TestBuildRevocationListV2(t *testing.T) {
	kp, _ := issuer.GenerateKeyPair("k1")
	s, err := issuer.NewSigner(kp.KeyID, kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Unix(1_700_000_000, 0).UTC()
	expires := issued.Add(24 * time.Hour)

	bad := []issuer.RevocationListOptions{
		{Sequence: 0, IssuedAt: issued, ExpiresAt: expires},                // sequence must be > 0
		{Sequence: 1, ExpiresAt: expires},                                  // missing issued_at
		{Sequence: 1, IssuedAt: issued, ExpiresAt: issued.Add(-time.Hour)}, // expires before issued
	}
	for i, opts := range bad {
		if _, err := issuer.BuildRevocationListV2(s, opts); err == nil {
			t.Fatalf("bad options[%d] unexpectedly accepted", i)
		}
	}
	if _, err := issuer.BuildRevocationListV2(nil, issuer.RevocationListOptions{Sequence: 1, IssuedAt: issued, ExpiresAt: expires}); err == nil {
		t.Fatal("nil signer unexpectedly accepted")
	}

	env, err := issuer.BuildRevocationListV2(s, issuer.RevocationListOptions{
		ListID:     "default",
		Sequence:   7,
		IssuedAt:   issued,
		ExpiresAt:  expires,
		RevokedIDs: []string{"lic-1", "lic-1", "", "lic-2"},
	})
	if err != nil {
		t.Fatalf("build v2 list: %v", err)
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	ring := license.NewKeyRing()
	pubB64 := base64.URLEncoding.EncodeToString(kp.PublicKey)
	if err := ring.AddPublicKeyBase64("k1", pubB64); err != nil {
		t.Fatal(err)
	}
	rl, err := license.LoadRevocationList(ring, data, issued.Add(time.Hour))
	if err != nil {
		t.Fatalf("client rejected issuer v2 list: %v", err)
	}
	if !rl.IsRevoked("lic-1") || !rl.IsRevoked("lic-2") {
		t.Fatal("expected lic-1 and lic-2 to be revoked")
	}
	if rl.IsRevoked("") {
		t.Fatal("empty id must not be treated as revoked")
	}
}

// SignLicenseBytes / SignRevocationBytes use distinct signing domains, so a
// signature from one domain must not verify under the other.
func TestSignDomainSeparation(t *testing.T) {
	kp, _ := issuer.GenerateKeyPair("k1")
	s, err := issuer.NewSigner(kp.KeyID, kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte(`{"schema_version":2}`)
	licSig := issuer.SignLicenseBytes(s, msg)
	revSig := issuer.SignRevocationBytes(s, msg)

	if !ed25519.Verify(kp.PublicKey, license.LicenseSigningInput(msg), licSig) {
		t.Fatal("license signature failed under license domain")
	}
	if ed25519.Verify(kp.PublicKey, license.RevocationSigningInput(msg), licSig) {
		t.Fatal("license signature must not verify under revocation domain")
	}
	if !ed25519.Verify(kp.PublicKey, license.RevocationSigningInput(msg), revSig) {
		t.Fatal("revocation signature failed under revocation domain")
	}
	if ed25519.Verify(kp.PublicKey, license.LicenseSigningInput(msg), revSig) {
		t.Fatal("revocation signature must not verify under license domain")
	}
}
