package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeKeyring writes a -keyring JSON file from the given entries and returns
// its path. Each entry is a raw map so tests can omit optional fields and model
// malformed inputs.
func writeKeyring(t *testing.T, dir string, keys ...map[string]any) string {
	t.Helper()
	body := map[string]any{"keys": keys}
	data, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		t.Fatalf("marshal keyring: %v", err)
	}
	path := filepath.Join(dir, "keyring.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write keyring: %v", err)
	}
	return path
}

// pubB64 reads a Base64URL public key file's trimmed contents.
func pubB64(t *testing.T, pubPath string) string {
	t.Helper()
	b, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("read pubkey: %v", err)
	}
	return strings.TrimSpace(string(b))
}

// A repeatable -pubkey keyID=path form builds a multi-key ring and verifies a
// license whose key_id matches one of the supplied ids.
func TestCmdVerifyPubkeyKeyIDForm(t *testing.T) {
	dir, privPath, pubPath := newTestKeyPair(t, "k1")
	licPath := issueTestLicense(t, dir, "k1", privPath)

	// Add an unrelated second key alongside k1; verification must still succeed
	// because the license's key_id (k1) resolves to a present, enabled key.
	_, _, otherPub := newTestKeyPair(t, "k2")
	out, err := callCmd(cmdVerify, []string{
		"-license", licPath, "-product", "prod-1",
		"-pubkey", "k1=" + pubPath,
		"-pubkey", "k2=" + otherPub,
	})
	if err != nil {
		t.Fatalf("verify with keyID=path pubkeys: %v", err)
	}
	if !strings.Contains(out, "status:") {
		t.Fatalf("verify output missing status: %q", out)
	}
}

// A -keyring file alone (no -pubkey) is sufficient to build the ring.
func TestCmdVerifyKeyringFile(t *testing.T) {
	dir, privPath, pubPath := newTestKeyPair(t, "k1")
	licPath := issueTestLicense(t, dir, "k1", privPath)
	kr := writeKeyring(t, dir, map[string]any{
		"key_id":     "k1",
		"public_key": pubB64(t, pubPath),
		"enabled":    true,
	})
	out, err := callCmd(cmdVerify, []string{"-license", licPath, "-product", "prod-1", "-keyring", kr})
	if err != nil {
		t.Fatalf("verify with -keyring: %v", err)
	}
	if !strings.Contains(out, "status:") {
		t.Fatalf("verify output missing status: %q", out)
	}
}

// An unknown key (the ring has no entry for the license's key_id) is rejected
// with the stable LICENSE_KEY_UNKNOWN code.
func TestCmdVerifyKeyringUnknownKey(t *testing.T) {
	dir, privPath, pubPath := newTestKeyPair(t, "k1")
	licPath := issueTestLicense(t, dir, "k1", privPath)
	kr := writeKeyring(t, dir, map[string]any{
		"key_id":     "some-other-id",
		"public_key": pubB64(t, pubPath),
		"enabled":    true,
	})
	_, err := callCmd(cmdVerify, []string{"-license", licPath, "-product", "prod-1", "-keyring", kr})
	if err == nil {
		t.Fatal("expected verify to fail for an unknown key_id")
	}
	if !strings.Contains(err.Error(), "LICENSE_KEY_UNKNOWN") {
		t.Fatalf("want LICENSE_KEY_UNKNOWN, got %v", err)
	}
}

// A revoked key rejects everything regardless of issuance time
// (LICENSE_KEY_REVOKED).
func TestCmdVerifyKeyringRevokedKey(t *testing.T) {
	dir, privPath, pubPath := newTestKeyPair(t, "k1")
	licPath := issueTestLicense(t, dir, "k1", privPath)
	kr := writeKeyring(t, dir, map[string]any{
		"key_id":     "k1",
		"public_key": pubB64(t, pubPath),
		"enabled":    true,
		"revoked":    true,
	})
	_, err := callCmd(cmdVerify, []string{"-license", licPath, "-product", "prod-1", "-keyring", kr})
	if err == nil {
		t.Fatal("expected verify to fail for a revoked key")
	}
	if !strings.Contains(err.Error(), "LICENSE_KEY_REVOKED") {
		t.Fatalf("want LICENSE_KEY_REVOKED, got %v", err)
	}
}

// A disabled key (enabled:false) is rejected with LICENSE_KEY_DISABLED.
func TestCmdVerifyKeyringDisabledKey(t *testing.T) {
	dir, privPath, pubPath := newTestKeyPair(t, "k1")
	licPath := issueTestLicense(t, dir, "k1", privPath)
	kr := writeKeyring(t, dir, map[string]any{
		"key_id":     "k1",
		"public_key": pubB64(t, pubPath),
		"enabled":    false,
	})
	_, err := callCmd(cmdVerify, []string{"-license", licPath, "-product", "prod-1", "-keyring", kr})
	if err == nil {
		t.Fatal("expected verify to fail for a disabled key")
	}
	if !strings.Contains(err.Error(), "LICENSE_KEY_DISABLED") {
		t.Fatalf("want LICENSE_KEY_DISABLED, got %v", err)
	}
}

// A key whose issuance window (not_after) has passed relative to the license's
// signed IssuedAt is rejected with LICENSE_KEY_DISABLED: the license was signed
// now, but the key claims to have expired in the past.
func TestCmdVerifyKeyringIssuanceWindow(t *testing.T) {
	dir, privPath, pubPath := newTestKeyPair(t, "k1")
	licPath := issueTestLicense(t, dir, "k1", privPath)
	past := timeNow().Add(-24 * time.Hour).Format(time.RFC3339)
	kr := writeKeyring(t, dir, map[string]any{
		"key_id":     "k1",
		"public_key": pubB64(t, pubPath),
		"enabled":    true,
		"not_after":  past,
	})
	_, err := callCmd(cmdVerify, []string{"-license", licPath, "-product", "prod-1", "-keyring", kr})
	if err == nil {
		t.Fatal("expected verify to fail when the key was past its window at issuance")
	}
	if !strings.Contains(err.Error(), "LICENSE_KEY_DISABLED") {
		t.Fatalf("want LICENSE_KEY_DISABLED, got %v", err)
	}
}

// A duplicate key_id across keyring input is a usage error (exit 2), never a
// silent shadowing.
func TestCmdVerifyKeyringDuplicateKeyID(t *testing.T) {
	dir, privPath, pubPath := newTestKeyPair(t, "k1")
	licPath := issueTestLicense(t, dir, "k1", privPath)
	kr := writeKeyring(t, dir,
		map[string]any{"key_id": "k1", "public_key": pubB64(t, pubPath), "enabled": true},
		map[string]any{"key_id": "k1", "public_key": pubB64(t, pubPath), "enabled": true},
	)
	_, err := callCmd(cmdVerify, []string{"-license", licPath, "-product", "prod-1", "-keyring", kr})
	if err == nil {
		t.Fatal("expected a usage error for a duplicate key_id")
	}
	var ue *usageError
	if !errors.As(err, &ue) {
		t.Fatalf("duplicate key_id should be a usage error, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "duplicate key_id") {
		t.Fatalf("want duplicate key_id message, got %v", err)
	}
}

// A duplicate key_id across BOTH -pubkey and -keyring is likewise rejected.
func TestCmdVerifyDuplicateAcrossSources(t *testing.T) {
	dir, privPath, pubPath := newTestKeyPair(t, "k1")
	licPath := issueTestLicense(t, dir, "k1", privPath)
	kr := writeKeyring(t, dir, map[string]any{"key_id": "k1", "public_key": pubB64(t, pubPath), "enabled": true})
	_, err := callCmd(cmdVerify, []string{
		"-license", licPath, "-product", "prod-1",
		"-pubkey", "k1=" + pubPath,
		"-keyring", kr,
	})
	if err == nil {
		t.Fatal("expected a usage error for a key_id present in both -pubkey and -keyring")
	}
	var ue *usageError
	if !errors.As(err, &ue) {
		t.Fatalf("expected usageError, got %T: %v", err, err)
	}
}

// A separate -revocation-keyring authenticates the revocation list independently
// of the license verification key. Using the same key material here proves the
// wiring; a mismatched key would fail to load the list.
func TestCmdVerifyRevocationKeyring(t *testing.T) {
	dir, privPath, pubPath := newTestKeyPair(t, "k1")
	licPath := issueTestLicense(t, dir, "k1", privPath)

	revPath := filepath.Join(dir, "revocation.json")
	if _, err := callCmd(cmdRevokeList, []string{
		"-key", privPath, "-key-id", "k1", "-ids", "someone_else",
		"-sequence", "1", "-ttl", "8760h", "-list-id", "list-1", "-out", revPath,
	}); err != nil {
		t.Fatalf("build revocation: %v", err)
	}

	licKR := writeKeyring(t, dir, map[string]any{"key_id": "k1", "public_key": pubB64(t, pubPath), "enabled": true})
	revKR := filepath.Join(dir, "rev-keyring.json")
	revBody, _ := json.MarshalIndent(map[string]any{
		"keys": []map[string]any{{"key_id": "k1", "public_key": pubB64(t, pubPath), "enabled": true}},
	}, "", "  ")
	if err := os.WriteFile(revKR, revBody, 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := callCmd(cmdVerify, []string{
		"-license", licPath, "-product", "prod-1",
		"-keyring", licKR, "-revocation", revPath, "-revocation-keyring", revKR,
	})
	if err != nil {
		t.Fatalf("verify with -revocation-keyring: %v", err)
	}
	if !strings.Contains(out, "status:") {
		t.Fatalf("verify output missing status: %q", out)
	}
}

// A malformed keyring (empty key_id) is a usage error.
func TestCmdVerifyKeyringEmptyKeyID(t *testing.T) {
	dir, privPath, pubPath := newTestKeyPair(t, "k1")
	licPath := issueTestLicense(t, dir, "k1", privPath)
	kr := writeKeyring(t, dir, map[string]any{"key_id": "", "public_key": pubB64(t, pubPath), "enabled": true})
	_, err := callCmd(cmdVerify, []string{"-license", licPath, "-product", "prod-1", "-keyring", kr})
	if err == nil {
		t.Fatal("expected error for an empty key_id in the keyring")
	}
}

// parsePubkeyValue distinguishes the bare-path and keyID=path forms, including
// a path that itself contains '=' (treated as a bare path, not a keyID).
func TestParsePubkeyValue(t *testing.T) {
	cases := []struct {
		in        string
		wantKeyID string
		wantPath  string
		wantErr   bool
	}{
		{in: "k1=/tmp/k1.key", wantKeyID: "k1", wantPath: "/tmp/k1.key"},
		{in: "/tmp/plain.key", wantKeyID: "", wantPath: "/tmp/plain.key"},
		{in: "/tmp/we=ird.key", wantKeyID: "", wantPath: "/tmp/we=ird.key"},
		{in: "k1=", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tc := range cases {
		spec, err := parsePubkeyValue(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("parsePubkeyValue(%q): want error, got %+v", tc.in, spec)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parsePubkeyValue(%q): unexpected error %v", tc.in, err)
		}
		if spec.keyID != tc.wantKeyID || spec.path != tc.wantPath {
			t.Fatalf("parsePubkeyValue(%q) = %+v, want keyID=%q path=%q", tc.in, spec, tc.wantKeyID, tc.wantPath)
		}
	}
}
