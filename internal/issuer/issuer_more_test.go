package issuer_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
	if p.SchemaVersion != license.LicenseSchemaVersion {
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

// Issue honors explicit IssuedAt and preset ids.
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

// BuildRevocationList (legacy v1) rejects a nil signer and deduplicates/strips
// empty ids. v1 lists are rejected by clients unless AllowLegacyV1 is set.
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
	rp, err := license.LoadRevocationListWithPolicy(ring, data, time.Now().UTC(), license.RevocationPolicy{AllowLegacyV1: true})
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

// BuildPayload preserves explicit ids and normalises NotBefore/ExpiresAt to
// UTC (exercising the utcPtr non-nil branch), and defaults DeviceBinding.Mode.
func TestBuildPayloadExplicitAndTimePointers(t *testing.T) {
	loc := time.FixedZone("UTC+8", 8*3600)
	notBefore := time.Date(2030, 1, 2, 3, 4, 5, 0, loc)
	expires := time.Date(2031, 6, 7, 8, 9, 10, 0, loc)
	issued := time.Date(2029, 12, 31, 23, 0, 0, 0, loc)

	p, err := issuer.BuildPayload(issuer.IssueRequest{
		LicenseID:    "lic_explicit_id",
		SerialNumber: "SER-EXPLICIT",
		ProductID:    "p",
		Edition:      license.EditionBasic,
		LicenseType:  license.LicenseTypeSubscription,
		IssuedAt:     &issued,
		NotBefore:    &notBefore,
		ExpiresAt:    &expires,
	})
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}
	if p.LicenseID != "lic_explicit_id" || p.SerialNumber != "SER-EXPLICIT" {
		t.Fatalf("explicit ids not preserved: id=%q serial=%q", p.LicenseID, p.SerialNumber)
	}
	if p.NotBefore == nil || p.ExpiresAt == nil {
		t.Fatal("expected NotBefore and ExpiresAt to be set")
	}
	if p.NotBefore.Location() != time.UTC {
		t.Fatalf("NotBefore not normalised to UTC: %v", p.NotBefore.Location())
	}
	if p.ExpiresAt.Location() != time.UTC {
		t.Fatalf("ExpiresAt not normalised to UTC: %v", p.ExpiresAt.Location())
	}
	if !p.NotBefore.Equal(notBefore) || !p.ExpiresAt.Equal(expires) {
		t.Fatal("time instants changed during UTC normalisation")
	}
	if !p.IssuedAt.Equal(issued) || p.IssuedAt.Location() != time.UTC {
		t.Fatalf("IssuedAt not normalised: %v (%v)", p.IssuedAt, p.IssuedAt.Location())
	}
	if p.DeviceBinding.Mode != license.DeviceModeNone {
		t.Fatalf("DeviceBinding.Mode default = %q, want none", p.DeviceBinding.Mode)
	}
	if p.SchemaVersion != license.LicenseSchemaVersion {
		t.Fatalf("schema version = %d, want %d", p.SchemaVersion, license.LicenseSchemaVersion)
	}
}

// BuildPayload generates well-formed random license_id (lic_ + 32 hex chars)
// and serial (grouped uppercase, no ambiguous chars) when omitted, checking the
// randomID/randomSerial length and format contracts.
func TestBuildPayloadRandomIDAndSerialFormat(t *testing.T) {
	p, err := issuer.BuildPayload(issuer.IssueRequest{
		ProductID:     "p",
		Edition:       license.EditionBasic,
		LicenseType:   license.LicenseTypeLifetime,
		DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
	})
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}

	if !strings.HasPrefix(p.LicenseID, "lic_") {
		t.Fatalf("license_id missing lic_ prefix: %q", p.LicenseID)
	}
	hexPart := strings.TrimPrefix(p.LicenseID, "lic_")
	if len(hexPart) != 32 { // 16 random bytes hex-encoded
		t.Fatalf("license_id hex part length = %d, want 32 (%q)", len(hexPart), hexPart)
	}
	for _, c := range hexPart {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Fatalf("license_id hex part contains non-hex char %q", c)
		}
	}

	// randomSerial: 10 bytes -> 20 alphabet chars grouped in 4-char blocks with
	// dashes: "AAAA-AAAA-AAAA-AAAA-AAAA" => 24 runes.
	if got := len(p.SerialNumber); got != 24 {
		t.Fatalf("serial length = %d, want 24 (%q)", got, p.SerialNumber)
	}
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	for i, c := range p.SerialNumber {
		if (i+1)%5 == 0 {
			if c != '-' {
				t.Fatalf("serial position %d = %q, want '-'", i, c)
			}
			continue
		}
		if !strings.ContainsRune(alphabet, c) {
			t.Fatalf("serial contains char %q outside the safe alphabet", c)
		}
	}
}

// Issue propagates a validation error. randomID/randomSerial only fail if
// crypto/rand fails (not deterministically triggerable), so we exercise the
// error-propagation path via structural validation failure instead: a
// device-bound license without any device_id is rejected, and Issue must
// surface that error unchanged rather than returning an envelope.
func TestIssuePropagatesValidationError(t *testing.T) {
	kp, _ := issuer.GenerateKeyPair("k1")
	signer, _ := issuer.NewSigner("k1", kp.PrivateKey)
	env, err := issuer.Issue(signer, issuer.IssueRequest{
		ProductID:   "p",
		Edition:     license.EditionBasic,
		LicenseType: license.LicenseTypeLifetime,
		// Single device binding with no device_id fails static validation.
		DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeSingle},
	})
	if err == nil {
		t.Fatal("expected error for device binding without any device_id")
	}
	if env != nil {
		t.Fatalf("expected nil envelope on error, got %+v", env)
	}
	if !strings.Contains(err.Error(), "issuer: invalid license") {
		t.Fatalf("error not wrapped by Issue: %v", err)
	}
}

// LoadPrivateKey rejects a group-readable (0640) key file, covering the
// permission-mask branch for group bits (the 0644 case is covered elsewhere).
func TestLoadPrivateKeyRejectsGroupReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits are not enforced on Windows")
	}
	dir := t.TempDir()
	kp, _ := issuer.GenerateKeyPair("k1")
	privPath, _, err := kp.WriteKeyFiles(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(privPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.LoadPrivateKey(privPath); err == nil {
		t.Fatal("expected rejection of group-readable (0640) private key")
	}
}

// WriteKeyFiles surfaces a write failure when the target directory is
// read-only, exercising the staging temp-file create-failure branch.
// Skipped when running as root, where directory mode is not enforced.
func TestWriteKeyFilesReadOnlyDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("read-only directory semantics differ on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permission checks")
	}
	base := t.TempDir()
	dir := filepath.Join(base, "ro")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	kp, _ := issuer.GenerateKeyPair("k1")
	if _, _, err := kp.WriteKeyFiles(dir, false); err == nil {
		t.Fatal("expected write failure in a read-only directory (no force)")
	}
	if _, _, err := kp.WriteKeyFiles(dir, true); err == nil {
		t.Fatal("expected write failure in a read-only directory (force)")
	}
}

// LoadPrivateKey surfaces a read failure when the path is a directory, covering
// the ReadFile error branch after the permission check passes.
func TestLoadPrivateKeyReadFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permission semantics differ on Windows")
	}
	dir := t.TempDir()
	sub := filepath.Join(dir, "keydir")
	// 0700 dir passes the &0o077 permissive-mode check but cannot be ReadFile'd.
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.LoadPrivateKey(sub); err == nil {
		t.Fatal("expected read error when private key path is a directory")
	}
}

// WriteKeyFiles never touches the private key when a target already exists in
// no-force mode: pre-creating the public-key path as a directory makes the
// up-front existence check refuse before any file is staged or committed, so a
// caller never observes a private key without its matching public key.
func TestWriteKeyFilesRollsBackOnPublicWriteFailure(t *testing.T) {
	dir := t.TempDir()
	kp, err := issuer.GenerateKeyPair("k1")
	if err != nil {
		t.Fatal(err)
	}
	// The public key would be written to "<dir>/k1-public.key"; make that path a
	// directory so the public-key write fails after the private key is written.
	pubPath := filepath.Join(dir, "k1-public.key")
	if err := os.Mkdir(pubPath, 0o700); err != nil {
		t.Fatal(err)
	}
	privPath, _, err := kp.WriteKeyFiles(dir, false)
	if err == nil {
		t.Fatal("expected public-key write failure")
	}
	if privPath != "" {
		t.Fatalf("expected empty privPath on failure, got %q", privPath)
	}
	// The private key must have been rolled back (removed).
	if _, statErr := os.Stat(filepath.Join(dir, "k1-private.key")); !os.IsNotExist(statErr) {
		t.Fatalf("private key was not rolled back: stat err = %v", statErr)
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
