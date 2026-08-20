package issuer_test

import (
	"os"
	"path/filepath"
	"testing"

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
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode = %o, want 0600", fi.Mode().Perm())
	}
	if _, err := os.Stat(pubPath); err != nil {
		t.Fatalf("public key missing: %v", err)
	}
	// Second write without force must fail (no clobber).
	if _, _, err := kp.WriteKeyFiles(dir, false); err == nil {
		t.Fatal("expected no-clobber error on existing private key")
	}
}

// LoadPrivateKey rejects world-readable key files.
func TestLoadPrivateKeyRejectsLoosePerms(t *testing.T) {
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
	res, err := mgr.Validate(data, license.ValidationContext{})
	if err != nil || !res.Valid() {
		t.Fatalf("round-trip validation failed: %v", err)
	}
	_ = filepath.Base(privPath)
}
