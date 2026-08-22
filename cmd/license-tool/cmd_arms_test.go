package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/soulteary/grantseal/pkg/license"
)

// cmdFingerprint -request-code and -json exercise those output branches.
func TestCmdFingerprintOutputModes(t *testing.T) {
	if _, err := callCmd(cmdFingerprint, []string{"-namespace", "prod-1", "-request-code"}); err != nil {
		t.Fatalf("fingerprint -request-code: %v", err)
	}
	if _, err := callCmd(cmdFingerprint, []string{"-namespace", "prod-1", "-json"}); err != nil {
		t.Fatalf("fingerprint -json: %v", err)
	}
	if _, err := callCmd(cmdFingerprint, []string{"-namespace", "prod-1", "-v2", "-request-code"}); err != nil {
		t.Fatalf("fingerprint -v2 -request-code: %v", err)
	}
}

// verify without -product is a usage error (exit 2 path).
func TestCmdVerifyMissingProduct(t *testing.T) {
	dir, privPath, pubPath := newTestKeyPair(t, "k1")
	licPath := issueTestLicense(t, dir, "k1", privPath)
	if _, err := callCmd(cmdVerify, []string{"-license", licPath, "-pubkey", pubPath}); err == nil {
		t.Fatal("expected usage error for missing -product")
	}
}

// verify with a public key file whose contents are not valid base64 must fail
// in AddPublicKeyBase64.
func TestCmdVerifyBadPubKeyContents(t *testing.T) {
	dir, privPath, _ := newTestKeyPair(t, "k1")
	licPath := issueTestLicense(t, dir, "k1", privPath)
	badPub := filepath.Join(dir, "bad-pub.key")
	if err := os.WriteFile(badPub, []byte("!!!not-base64!!!"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := callCmd(cmdVerify, []string{"-license", licPath, "-pubkey", badPub, "-key-id", "k1", "-product", "prod-1"}); err == nil {
		t.Fatal("expected error for invalid public key contents")
	}
}

// verify with a malformed revocation file must fail loading the revocation list.
func TestCmdVerifyBadRevocation(t *testing.T) {
	dir, privPath, pubPath := newTestKeyPair(t, "k1")
	licPath := issueTestLicense(t, dir, "k1", privPath)
	badRev := filepath.Join(dir, "bad-rev.json")
	if err := os.WriteFile(badRev, []byte("{not-json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := callCmd(cmdVerify, []string{"-license", licPath, "-pubkey", pubPath, "-product", "prod-1", "-revocation", badRev}); err == nil {
		t.Fatal("expected error for malformed revocation list")
	}
}

// inspect with invalid public key contents must fail in AddPublicKeyBase64.
func TestCmdInspectBadPubKeyContents(t *testing.T) {
	dir, privPath, _ := newTestKeyPair(t, "k1")
	licPath := issueTestLicense(t, dir, "k1", privPath)
	badPub := filepath.Join(dir, "bad-pub.key")
	if err := os.WriteFile(badPub, []byte("!!!not-base64!!!"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := callCmd(cmdInspect, []string{"-license", licPath, "-pubkey", badPub, "-key-id", "k1"}); err == nil {
		t.Fatal("expected error for invalid public key contents")
	}
}

// toRequest surfaces parse errors for not_before and maintenance_until.
func TestToRequestBadTimes(t *testing.T) {
	if _, err := (issueConfig{NotBefore: "nope"}).toRequest(); err == nil {
		t.Fatal("expected not_before parse error")
	}
	if _, err := (issueConfig{VersionConstraint: versionConstraintCfg{MaintenanceUntil: "nope"}}).toRequest(); err == nil {
		t.Fatal("expected maintenance_until parse error")
	}
}

// revoke-list writing to -out exercises the file-output branch, and a v1 list
// to -out too.
func TestCmdRevokeListOutFile(t *testing.T) {
	dir, privPath, _ := newTestKeyPair(t, "k1")
	outPath := filepath.Join(dir, "rev.json")
	if _, err := callCmd(cmdRevokeList, []string{
		"-key", privPath, "-key-id", "k1", "-ids", "lic_a,lic_b",
		"-sequence", "2", "-ttl", "100h", "-list-id", "list-1", "-out", outPath,
	}); err != nil {
		t.Fatalf("revoke-list -out: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("revocation file not written: %v", err)
	}
	// Sanity: it is a valid envelope JSON.
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var env license.RevocationEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("output not valid envelope json: %v", err)
	}
}

// revoke-list with a mismatched key-id/private-key still signs (NewSigner only
// checks size); use an empty key-id to hit the usage-error arm instead.
func TestCmdRevokeListMissingKeyID(t *testing.T) {
	dir, privPath, _ := newTestKeyPair(t, "k1")
	if _, err := callCmd(cmdRevokeList, []string{"-key", privPath, "-ids", "lic_a", "-sequence", "1", "-ttl", "10h"}); err == nil {
		t.Fatal("expected usage error for missing -key-id")
	}
	_ = dir
}
