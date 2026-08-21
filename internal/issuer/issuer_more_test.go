package issuer_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/soulteary/grantseal/internal/issuer"
	"github.com/soulteary/grantseal/pkg/license"
)

// GenerateKeyPair rejects an empty key_id.
func TestGenerateKeyPairEmptyKeyID(t *testing.T) {
	if _, err := issuer.GenerateKeyPair(""); err == nil {
		t.Fatal("expected error for empty key_id")
	}
}

// NewSigner rejects empty key_id and wrong-sized keys.
func TestNewSignerRejectsBadInput(t *testing.T) {
	kp, err := issuer.GenerateKeyPair("k1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.NewSigner("", kp.PrivateKey); err == nil {
		t.Fatal("expected error for empty key_id")
	}
	if _, err := issuer.NewSigner("k1", ed25519.PrivateKey{1, 2, 3}); err == nil {
		t.Fatal("expected error for short private key")
	}
}

// PublicKeyBase64 round-trips through DecodePrivateKey / seed.
func TestPublicKeyBase64Decodable(t *testing.T) {
	kp, _ := issuer.GenerateKeyPair("k1")
	raw, err := base64.URLEncoding.DecodeString(kp.PublicKeyBase64())
	if err != nil {
		t.Fatalf("public key base64 not decodable: %v", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		t.Fatalf("public key size = %d, want %d", len(raw), ed25519.PublicKeySize)
	}
}

// DecodePrivateKey accepts a 32-byte seed and a full 64-byte key, rejecting
// bad base64 and wrong lengths.
func TestDecodePrivateKey(t *testing.T) {
	kp, _ := issuer.GenerateKeyPair("k1")
	seed := kp.PrivateKey.Seed()

	seedB64 := base64.URLEncoding.EncodeToString(seed)
	if _, err := issuer.DecodePrivateKey(seedB64); err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	if _, err := issuer.DecodePrivateKey("  " + seedB64 + "\n"); err != nil {
		t.Fatalf("decode seed with whitespace: %v", err)
	}

	fullB64 := base64.URLEncoding.EncodeToString(kp.PrivateKey)
	if _, err := issuer.DecodePrivateKey(fullB64); err != nil {
		t.Fatalf("decode full key: %v", err)
	}

	if _, err := issuer.DecodePrivateKey("!!!not-base64!!!"); err == nil {
		t.Fatal("expected base64 decode error")
	}
	shortB64 := base64.URLEncoding.EncodeToString([]byte("too short"))
	if _, err := issuer.DecodePrivateKey(shortB64); err == nil {
		t.Fatal("expected invalid length error")
	}
	// Standard-alphabet encoding must be rejected (only URL encoding accepted).
	stdB64 := base64.StdEncoding.EncodeToString(seed)
	if stdB64 != seedB64 {
		if _, err := issuer.DecodePrivateKey(stdB64); err == nil {
			t.Fatal("expected rejection of standard-alphabet encoding")
		}
	}
}

// LoadPrivateKey reports a clear error for a missing file.
func TestLoadPrivateKeyMissingFile(t *testing.T) {
	if _, err := issuer.LoadPrivateKey(filepath.Join(t.TempDir(), "nope.key")); err == nil {
		t.Fatal("expected stat error for missing key")
	}
}

// WriteKeyFiles with force overwrites an existing key.
func TestWriteKeyFilesForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	kp, _ := issuer.GenerateKeyPair("k1")
	if _, _, err := kp.WriteKeyFiles(dir, false); err != nil {
		t.Fatal(err)
	}
	kp2, _ := issuer.GenerateKeyPair("k1")
	priv2, _, err := kp2.WriteKeyFiles(dir, true)
	if err != nil {
		t.Fatalf("force overwrite failed: %v", err)
	}
	loaded, err := issuer.LoadPrivateKey(priv2)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Equal(kp2.PrivateKey) {
		t.Fatal("overwritten key does not match latest key pair")
	}
}

// SignPayload rejects a nil payload and stamps key_id + schema version.
func TestSignPayloadStampsAndRejectsNil(t *testing.T) {
	kp, _ := issuer.GenerateKeyPair("k1")
	signer, _ := issuer.NewSigner("k1", kp.PrivateKey)
	if _, err := signer.SignPayload(nil); err == nil {
		t.Fatal("expected error for nil payload")
	}
	p := &license.Payload{
		LicenseID:     "lic_1",
		SerialNumber:  "SER",
		ProductID:     "p",
		CustomerID:    "c",
		Edition:       license.EditionBasic,
		LicenseType:   license.LicenseTypeLifetime,
		IssuedAt:      time.Now().UTC(),
		DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
	}
	env, err := signer.SignPayload(p)
	if err != nil {
		t.Fatalf("SignPayload: %v", err)
	}
	if p.KeyID != "k1" {
		t.Fatalf("key_id not stamped: %q", p.KeyID)
	}
	if p.SchemaVersion != license.SchemaVersion {
		t.Fatalf("schema version not stamped: %d", p.SchemaVersion)
	}
	if env.KeyID != "k1" || env.Algorithm != license.AlgorithmEd25519 {
		t.Fatalf("envelope fields wrong: %+v", env)
	}
}

// SignCanonical produces a signature verifiable with the public key.
func TestSignCanonicalVerifiable(t *testing.T) {
	kp, _ := issuer.GenerateKeyPair("k1")
	signer, _ := issuer.NewSigner("k1", kp.PrivateKey)
	msg := []byte("canonical-bytes")
	sig := signer.SignCanonical(msg)
	if !ed25519.Verify(kp.PublicKey, msg, sig) {
		t.Fatal("signature failed to verify")
	}
	if signer.KeyID() != "k1" {
		t.Fatalf("KeyID = %q", signer.KeyID())
	}
}

// Issue rejects a structurally invalid license (subscription without expiry).
func TestIssueRejectsInvalidLicense(t *testing.T) {
	kp, _ := issuer.GenerateKeyPair("k1")
	signer, _ := issuer.NewSigner("k1", kp.PrivateKey)
	_, err := issuer.Issue(signer, issuer.IssueRequest{
		ProductID:     "p",
		Edition:       license.EditionBasic,
		LicenseType:   license.LicenseTypeSubscription,
		DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
	})
	if err == nil {
		t.Fatal("expected invalid-license error for subscription without expiry")
	}
}

// Issue honours explicit IssuedAt and preset ids.
func TestIssueHonoursExplicitFields(t *testing.T) {
	kp, _ := issuer.GenerateKeyPair("k1")
	signer, _ := issuer.NewSigner("k1", kp.PrivateKey)
	issued := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	env, err := issuer.Issue(signer, issuer.IssueRequest{
		LicenseID:     "lic_explicit",
		SerialNumber:  "SERIAL-1",
		ProductID:     "p",
		CustomerID:    "c",
		Edition:       license.EditionEnterprise,
		LicenseType:   license.LicenseTypeLifetime,
		IssuedAt:      &issued,
		DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	data, err := env.MarshalJSONIndent()
	if err != nil {
		t.Fatal(err)
	}
	ring := license.NewKeyRing()
	if err := ring.AddPublicKeyBase64("k1", kp.PublicKeyBase64()); err != nil {
		t.Fatal(err)
	}
	payload, err := license.NewManager(ring).Inspect(data)
	if err != nil {
		t.Fatal(err)
	}
	if payload.LicenseID != "lic_explicit" || payload.SerialNumber != "SERIAL-1" {
		t.Fatalf("explicit ids not preserved: %+v", payload)
	}
	if !payload.IssuedAt.Equal(issued) {
		t.Fatalf("issued_at = %v, want %v", payload.IssuedAt, issued)
	}
}

// BuildRevocationList rejects a nil signer and deduplicates/strips empty ids.
func TestBuildRevocationList(t *testing.T) {
	if _, err := issuer.BuildRevocationList(nil, []string{"a"}); err == nil {
		t.Fatal("expected error for nil signer")
	}
	kp, _ := issuer.GenerateKeyPair("k1")
	signer, _ := issuer.NewSigner("k1", kp.PrivateKey)
	env, err := issuer.BuildRevocationList(signer, []string{"a", "", "a", "b", ""})
	if err != nil {
		t.Fatalf("BuildRevocationList: %v", err)
	}
	data, err := os.ReadFile(writeTemp(t, env))
	if err != nil {
		t.Fatal(err)
	}
	ring := license.NewKeyRing()
	if err := ring.AddPublicKeyBase64("k1", kp.PublicKeyBase64()); err != nil {
		t.Fatal(err)
	}
	rp, err := license.LoadRevocationList(ring, data, time.Now().UTC())
	if err != nil {
		t.Fatalf("load revocation list: %v", err)
	}
	if !rp.IsRevoked("a") || !rp.IsRevoked("b") {
		t.Fatal("expected a and b revoked")
	}
	if rp.IsRevoked("") {
		t.Fatal("empty id should not be revoked")
	}
}

// writeTemp marshals a revocation envelope to a temp file for round-tripping.
func writeTemp(t *testing.T, env *license.RevocationEnvelope) string {
	t.Helper()
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rev.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
