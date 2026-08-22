package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/soulteary/grantseal/pkg/license"
)

// A bare -pubkey with no derivable key_id (empty license/-key-id) is a usage
// error rather than a ring that silently binds to "".
func TestBuildVerifyKeyRingBarePubkeyNoDefaultKeyID(t *testing.T) {
	_, _, pubPath := newTestKeyPair(t, "k1")
	_, err := buildVerifyKeyRing([]string{pubPath}, "", "")
	if err == nil {
		t.Fatal("expected a usage error when no key_id can be derived for a bare -pubkey")
	}
	if !strings.Contains(err.Error(), "cannot derive key_id") {
		t.Fatalf("want cannot-derive-key_id message, got %v", err)
	}
}

// No sources at all yields the "no verification keys" usage error.
func TestBuildVerifyKeyRingNoSources(t *testing.T) {
	_, err := buildVerifyKeyRing(nil, "", "k1")
	if err == nil {
		t.Fatal("expected an error when neither -pubkey nor -keyring is provided")
	}
	if !strings.Contains(err.Error(), "no verification keys") {
		t.Fatalf("want no-verification-keys message, got %v", err)
	}
}

// A bare -pubkey path that does not exist surfaces the file read error.
func TestBuildVerifyKeyRingMissingPubkeyFile(t *testing.T) {
	_, err := buildVerifyKeyRing([]string{filepath.Join(t.TempDir(), "nope.pub")}, "", "k1")
	if err == nil {
		t.Fatal("expected an error for a missing -pubkey file")
	}
}

// loadKeyringFile rejects a nonexistent path.
func TestLoadKeyringFileMissing(t *testing.T) {
	_, err := loadKeyringFile(filepath.Join(t.TempDir(), "absent.json"))
	if err == nil {
		t.Fatal("expected an error for a missing keyring file")
	}
}

// loadKeyringFile rejects malformed JSON as a usage error.
func TestLoadKeyringFileMalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := loadKeyringFile(path)
	if err == nil {
		t.Fatal("expected a parse error for malformed keyring JSON")
	}
	var ue *usageError
	if !errors.As(err, &ue) {
		t.Fatalf("malformed keyring should be a usage error, got %T: %v", err, err)
	}
}

// loadKeyringFile rejects a keyring with an empty keys array.
func TestLoadKeyringFileNoKeys(t *testing.T) {
	dir := t.TempDir()
	kr := writeKeyring(t, dir)
	_, err := loadKeyringFile(kr)
	if err == nil {
		t.Fatal("expected an error for a keyring with no keys")
	}
	if !strings.Contains(err.Error(), "no keys") {
		t.Fatalf("want no-keys message, got %v", err)
	}
}

// loadKeyringFile rejects a bad not_before timestamp with a usage error.
func TestLoadKeyringFileBadNotBefore(t *testing.T) {
	dir, _, pubPath := newTestKeyPair(t, "k1")
	kr := writeKeyring(t, dir, map[string]any{
		"key_id":     "k1",
		"public_key": pubB64(t, pubPath),
		"enabled":    true,
		"not_before": "not-a-timestamp",
	})
	_, err := loadKeyringFile(kr)
	if err == nil {
		t.Fatal("expected an error for an unparseable not_before")
	}
	if !strings.Contains(err.Error(), "not_before") {
		t.Fatalf("want not_before message, got %v", err)
	}
}

// loadKeyringFile rejects a bad not_after timestamp.
func TestLoadKeyringFileBadNotAfter(t *testing.T) {
	dir, _, pubPath := newTestKeyPair(t, "k1")
	kr := writeKeyring(t, dir, map[string]any{
		"key_id":     "k1",
		"public_key": pubB64(t, pubPath),
		"enabled":    true,
		"not_after":  "whenever",
	})
	_, err := loadKeyringFile(kr)
	if err == nil {
		t.Fatal("expected an error for an unparseable not_after")
	}
	if !strings.Contains(err.Error(), "not_after") {
		t.Fatalf("want not_after message, got %v", err)
	}
}

// loadKeyringFile rejects an undecodable public key in an entry.
func TestLoadKeyringFileBadPublicKey(t *testing.T) {
	dir := t.TempDir()
	kr := writeKeyring(t, dir, map[string]any{
		"key_id":     "k1",
		"public_key": "!!!not-base64!!!",
		"enabled":    true,
	})
	_, err := loadKeyringFile(kr)
	if err == nil {
		t.Fatal("expected an error for an undecodable public key")
	}
}

// verifyRevocationKeyRing returns the license ring unchanged when no separate
// revocation keyring is configured.
func TestVerifyRevocationKeyRingFallsBackToLicenseRing(t *testing.T) {
	_, _, pubPath := newTestKeyPair(t, "k1")
	licRing, err := buildVerifyKeyRing([]string{pubPath}, "", "k1")
	if err != nil {
		t.Fatalf("build license ring: %v", err)
	}
	got, err := verifyRevocationKeyRing(licRing, "")
	if err != nil {
		t.Fatalf("verifyRevocationKeyRing: %v", err)
	}
	if got != licRing {
		t.Fatal("expected the license ring to be reused when -revocation-keyring is empty")
	}
}

// verifyRevocationKeyRing rejects a duplicate key_id inside the revocation
// keyring file.
func TestVerifyRevocationKeyRingDuplicate(t *testing.T) {
	dir, _, pubPath := newTestKeyPair(t, "k1")
	kr := writeKeyring(t, dir,
		map[string]any{"key_id": "k1", "public_key": pubB64(t, pubPath), "enabled": true},
		map[string]any{"key_id": "k1", "public_key": pubB64(t, pubPath), "enabled": true},
	)
	_, err := verifyRevocationKeyRing(license.NewKeyRing(), kr)
	if err == nil {
		t.Fatal("expected a duplicate-key_id error in the revocation keyring")
	}
	if !strings.Contains(err.Error(), "duplicate key_id") {
		t.Fatalf("want duplicate key_id message, got %v", err)
	}
}

// decodePublicKeyBase64 rejects non-base64 and wrong-length inputs, and accepts
// a valid Ed25519 public key.
func TestDecodePublicKeyBase64(t *testing.T) {
	if _, err := decodePublicKeyBase64("###"); err == nil {
		t.Fatal("expected an error for non-base64 input")
	}
	short := base64.URLEncoding.EncodeToString([]byte("too-short"))
	if _, err := decodePublicKeyBase64(short); err == nil {
		t.Fatal("expected an error for a wrong-length key")
	}
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.URLEncoding.EncodeToString(pub)
	got, err := decodePublicKeyBase64("  " + enc + "  ")
	if err != nil {
		t.Fatalf("decodePublicKeyBase64 on a valid key: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatal("decoded key does not match the original")
	}
}
