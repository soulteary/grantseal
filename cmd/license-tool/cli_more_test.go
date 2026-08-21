package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/soulteary/grantseal/pkg/license"
)

// Every subcommand parses flags with flag.ContinueOnError, so an unknown flag
// must surface as an error (which main maps to a non-zero exit) rather than a
// panic or os.Exit inside the handler.
func TestUnknownFlagIsError(t *testing.T) {
	cmds := map[string]func([]string) error{
		"version":     cmdVersion,
		"keygen":      cmdKeygen,
		"public-key":  cmdPublicKey,
		"issue":       cmdIssue,
		"verify":      cmdVerify,
		"inspect":     cmdInspect,
		"revoke":      cmdRevokeList,
		"fingerprint": cmdFingerprint,
	}
	for name, fn := range cmds {
		if err := fn([]string{"-this-flag-does-not-exist"}); err == nil {
			t.Fatalf("%s: expected error on unknown flag", name)
		}
	}
}

// A missing input file must produce a runtime error, not a panic.
func TestCmdVerifyMissingFilesError(t *testing.T) {
	dir, privPath, pubPath := newTestKeyPair(t, "k1")
	missingLic := filepath.Join(dir, "nope-license.json")
	if err := cmdVerify([]string{"-license", missingLic, "-pubkey", pubPath, "-product", "prod-1"}); err == nil {
		t.Fatal("expected error for missing license file")
	}
	// Missing pubkey file.
	missingPub := filepath.Join(dir, "nope-pub.key")
	licPath := issueTestLicense(t, dir, "k1", privPath)
	if err := cmdVerify([]string{"-license", licPath, "-pubkey", missingPub, "-product", "prod-1"}); err == nil {
		t.Fatal("expected error for missing pubkey file")
	}
}

// A malformed license envelope makes key-id derivation (ParseEnvelope) fail.
func TestCmdVerifyBadEnvelopeError(t *testing.T) {
	dir := t.TempDir()
	_, _, pubPath := newTestKeyPair(t, "k1")
	bad := filepath.Join(dir, "bad-license.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdVerify([]string{"-license", bad, "-pubkey", pubPath, "-product", "prod-1"}); err == nil {
		t.Fatal("expected error for malformed license envelope")
	}
}

// The full option surface (explicit -key-id, -version, -device, -clock-skew,
// -revocation) must exercise the corresponding branches and succeed for a
// device-unbound, current license.
func TestCmdVerifyAllOptions(t *testing.T) {
	dir, privPath, pubPath := newTestKeyPair(t, "k1")
	licPath := issueTestLicense(t, dir, "k1", privPath)

	// A fresh v2 revocation list that does NOT revoke our license.
	revPath := filepath.Join(dir, "revocation.json")
	if _, err := captureStdout(t, func() error {
		return cmdRevokeList([]string{
			"-key", privPath, "-key-id", "k1", "-ids", "someone_else",
			"-sequence", "1", "-ttl", "8760h", "-out", revPath,
		})
	}); err != nil {
		t.Fatalf("build revocation: %v", err)
	}

	out, err := captureStdout(t, func() error {
		return cmdVerify([]string{
			"-license", licPath, "-pubkey", pubPath, "-key-id", "k1",
			"-product", "prod-1", "-version", "1.0.0", "-clock-skew", "5s",
			"-revocation", revPath,
		})
	})
	if err != nil {
		t.Fatalf("cmdVerify all options: %v", err)
	}
	if !strings.Contains(out, "status:") {
		t.Fatalf("verify output missing status: %q", out)
	}
}

// A revoked license must make verify fail with the revocation code.
func TestCmdVerifyRevokedLicenseFails(t *testing.T) {
	dir, privPath, pubPath := newTestKeyPair(t, "k1")
	licPath := issueTestLicense(t, dir, "k1", privPath)

	// Discover the issued license_id via inspect so we can revoke it.
	inspectOut, err := captureStdout(t, func() error {
		return cmdInspect([]string{"-license", licPath, "-pubkey", pubPath})
	})
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	var payload license.Payload
	if err := json.Unmarshal([]byte(inspectOut), &payload); err != nil {
		t.Fatalf("inspect json: %v", err)
	}

	revPath := filepath.Join(dir, "revocation.json")
	if _, err := captureStdout(t, func() error {
		return cmdRevokeList([]string{
			"-key", privPath, "-key-id", "k1", "-ids", payload.LicenseID,
			"-sequence", "1", "-ttl", "8760h", "-out", revPath,
		})
	}); err != nil {
		t.Fatalf("build revocation: %v", err)
	}

	_, verr := captureStdout(t, func() error {
		return cmdVerify([]string{
			"-license", licPath, "-pubkey", pubPath,
			"-product", "prod-1", "-revocation", revPath,
		})
	})
	if verr == nil {
		t.Fatal("expected verify to fail for a revoked license")
	}
}

// A bad revocation file path surfaces a read error before validation.
func TestCmdVerifyBadRevocationPath(t *testing.T) {
	dir, privPath, pubPath := newTestKeyPair(t, "k1")
	licPath := issueTestLicense(t, dir, "k1", privPath)
	if err := cmdVerify([]string{
		"-license", licPath, "-pubkey", pubPath, "-product", "prod-1",
		"-revocation", filepath.Join(dir, "no-such-revocation.json"),
	}); err == nil {
		t.Fatal("expected error for missing revocation file")
	}
}

// issueTestLicense issues a license into dir signed by privPath (whose public
// half the caller already holds) and returns the license path. Centralizes the
// common "give me a valid license file for this key" case.
func issueTestLicense(t *testing.T, dir, keyID, privPath string) string {
	t.Helper()
	cfgPath := writeIssueConfig(t, dir, keyID)
	licPath := filepath.Join(dir, "license.json")
	if _, err := captureStdout(t, func() error {
		return cmdIssue([]string{"-config", cfgPath, "-key", privPath, "-out", licPath})
	}); err != nil {
		t.Fatalf("cmdIssue: %v", err)
	}
	return licPath
}

// --- issue branch coverage ---------------------------------------------------

// A missing config file is a runtime error (read failure), distinct from the
// usage error when the flag itself is absent.
func TestCmdIssueMissingConfigFile(t *testing.T) {
	dir, privPath, _ := newTestKeyPair(t, "k1")
	if err := cmdIssue([]string{"-config", filepath.Join(dir, "nope.json"), "-key", privPath}); err == nil {
		t.Fatal("expected error for missing config file")
	}
}

// A config with an unparseable time (expires_at) must fail in toRequest.
func TestCmdIssueBadTimeInConfig(t *testing.T) {
	dir, privPath, _ := newTestKeyPair(t, "k1")
	cfg := issueConfig{
		KeyID:       "k1",
		ProductID:   "prod-1",
		CustomerID:  "cust-1",
		Edition:     string(license.EditionBasic),
		LicenseType: string(license.LicenseTypeSubscription),
		ExpiresAt:   "definitely-not-a-time",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	cfgPath := filepath.Join(dir, "issue-config.json")
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdIssue([]string{"-config", cfgPath, "-key", privPath}); err == nil {
		t.Fatal("expected error for bad expires_at time")
	}
}

// A config without key_id must fail with the key_id-required error.
func TestCmdIssueMissingKeyIDInConfig(t *testing.T) {
	dir, privPath, _ := newTestKeyPair(t, "k1")
	cfg := issueConfig{
		ProductID:   "prod-1",
		CustomerID:  "cust-1",
		Edition:     string(license.EditionBasic),
		LicenseType: string(license.LicenseTypeSubscription),
		ExpiresAt:   "2999-01-01T00:00:00Z",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	cfgPath := filepath.Join(dir, "issue-config.json")
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdIssue([]string{"-config", cfgPath, "-key", privPath}); err == nil {
		t.Fatal("expected error for missing config.key_id")
	}
}

// The -covered-max-version flag overrides the config value and the device
// binding + version constraint fields flow through toRequest. Issuing to an
// existing -out without -force must fail (no-clobber); with -force it succeeds.
func TestCmdIssueOverridesAndForce(t *testing.T) {
	dir, privPath, _ := newTestKeyPair(t, "k1")
	cfg := issueConfig{
		KeyID:       "k1",
		ProductID:   "prod-1",
		CustomerID:  "cust-1",
		Edition:     string(license.EditionProfessional),
		LicenseType: string(license.LicenseTypeSubscription),
		ExpiresAt:   "2999-01-01T00:00:00Z",
		Features:    []string{"f1", "f2"},
		Limits:      map[string]int64{"seats": 5},
		DeviceBinding: deviceBindingConfig{
			Mode:      string(license.DeviceModeMulti),
			DeviceIDs: []string{"dev-1"},
		},
		VersionConstraint: versionConstraintCfg{MinVersion: "1.0.0", MaxVersion: "2.0.0"},
		Metadata:          map[string]string{"tier": "gold"},
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	cfgPath := filepath.Join(dir, "issue-config.json")
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	licPath := filepath.Join(dir, "license.json")
	if _, err := captureStdout(t, func() error {
		return cmdIssue([]string{"-config", cfgPath, "-key", privPath, "-out", licPath, "-covered-max-version", "1.9.0"})
	}); err != nil {
		t.Fatalf("first issue: %v", err)
	}
	// Second issue to the same path without -force must fail (no-clobber).
	if _, err := captureStdout(t, func() error {
		return cmdIssue([]string{"-config", cfgPath, "-key", privPath, "-out", licPath})
	}); err == nil {
		t.Fatal("expected no-clobber error re-issuing to existing -out without -force")
	}
	// With -force it must overwrite.
	if _, err := captureStdout(t, func() error {
		return cmdIssue([]string{"-config", cfgPath, "-key", privPath, "-out", licPath, "-force"})
	}); err != nil {
		t.Fatalf("forced re-issue: %v", err)
	}
}

// issue to stdout (no -out) must print the envelope JSON.
func TestCmdIssueStdout(t *testing.T) {
	dir, privPath, _ := newTestKeyPair(t, "k1")
	cfgPath := writeIssueConfig(t, dir, "k1")
	out, err := captureStdout(t, func() error {
		return cmdIssue([]string{"-config", cfgPath, "-key", privPath})
	})
	if err != nil {
		t.Fatalf("cmdIssue stdout: %v", err)
	}
	if !strings.Contains(out, "\"payload\"") && !strings.Contains(out, "payload") {
		t.Fatalf("expected envelope JSON on stdout, got: %q", out)
	}
}

// A missing private key file must fail during LoadPrivateKey.
func TestCmdIssueMissingKeyFile(t *testing.T) {
	dir, _, _ := newTestKeyPair(t, "k1")
	cfgPath := writeIssueConfig(t, dir, "k1")
	if err := cmdIssue([]string{"-config", cfgPath, "-key", filepath.Join(dir, "no-such.key")}); err == nil {
		t.Fatal("expected error for missing private key file")
	}
}

// --- revoke-list v2 branch coverage -----------------------------------------

// v2 lists require -sequence; without it the build fails as a usage error.
func TestCmdRevokeListV2RequiresSequence(t *testing.T) {
	_, privPath, _ := newTestKeyPair(t, "k1")
	err := cmdRevokeList([]string{"-key", privPath, "-key-id", "k1", "-ids", "lic_a", "-ttl", "1h"})
	if err == nil {
		t.Fatal("expected error when -sequence missing for v2")
	}
	if _, ok := err.(*usageError); !ok {
		t.Fatalf("expected usageError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "-sequence") {
		t.Fatalf("usage error message should mention -sequence: %q", err.Error())
	}
}

// -expires-at and -ttl are mutually exclusive.
func TestCmdRevokeListV2ExpiryMutuallyExclusive(t *testing.T) {
	_, privPath, _ := newTestKeyPair(t, "k1")
	err := cmdRevokeList([]string{
		"-key", privPath, "-key-id", "k1", "-ids", "lic_a",
		"-sequence", "1", "-ttl", "1h", "-expires-at", "2999-01-01T00:00:00Z",
	})
	if err == nil {
		t.Fatal("expected error for -expires-at + -ttl together")
	}
}

// v2 requires an expiry source; neither -ttl nor -expires-at fails.
func TestCmdRevokeListV2RequiresExpiry(t *testing.T) {
	_, privPath, _ := newTestKeyPair(t, "k1")
	err := cmdRevokeList([]string{"-key", privPath, "-key-id", "k1", "-ids", "lic_a", "-sequence", "1"})
	if err == nil {
		t.Fatal("expected error when no expiry provided for v2")
	}
}

// A malformed -expires-at value is a usage error.
func TestCmdRevokeListV2BadExpiresAt(t *testing.T) {
	_, privPath, _ := newTestKeyPair(t, "k1")
	err := cmdRevokeList([]string{
		"-key", privPath, "-key-id", "k1", "-ids", "lic_a",
		"-sequence", "1", "-expires-at", "nope",
	})
	if err == nil {
		t.Fatal("expected error for malformed -expires-at")
	}
}

// The -expires-at path (RFC3339) with a -list-id produces a loadable v2 list.
func TestCmdRevokeListV2ExpiresAtAndListID(t *testing.T) {
	dir, privPath, pubPath := newTestKeyPair(t, "k1")
	revPath := filepath.Join(dir, "revocation.json")
	if _, err := captureStdout(t, func() error {
		return cmdRevokeList([]string{
			"-key", privPath, "-key-id", "k1", "-ids", "lic_a",
			"-sequence", "2", "-expires-at", "2999-01-01T00:00:00Z",
			"-list-id", "list-1", "-out", revPath,
		})
	}); err != nil {
		t.Fatalf("revoke-list v2 expires-at: %v", err)
	}
	revData, err := os.ReadFile(revPath)
	if err != nil {
		t.Fatal(err)
	}
	pubB64, _ := os.ReadFile(pubPath)
	ring := license.NewKeyRing()
	if err := ring.AddPublicKeyBase64("k1", string(pubB64)); err != nil {
		t.Fatal(err)
	}
	rp, err := license.LoadRevocationList(ring, revData, timeNow())
	if err != nil {
		t.Fatalf("load v2 list: %v", err)
	}
	if !rp.IsRevoked("lic_a") {
		t.Fatal("expected lic_a revoked")
	}
}

// A legacy v1 list (-v1) still builds and loads when the caller opts in.
func TestCmdRevokeListV1Legacy(t *testing.T) {
	dir, privPath, pubPath := newTestKeyPair(t, "k1")
	revPath := filepath.Join(dir, "revocation-v1.json")
	if _, err := captureStdout(t, func() error {
		return cmdRevokeList([]string{"-key", privPath, "-key-id", "k1", "-ids", "lic_v1", "-v1", "-out", revPath})
	}); err != nil {
		t.Fatalf("revoke-list v1: %v", err)
	}
	revData, err := os.ReadFile(revPath)
	if err != nil {
		t.Fatal(err)
	}
	pubB64, _ := os.ReadFile(pubPath)
	ring := license.NewKeyRing()
	if err := ring.AddPublicKeyBase64("k1", string(pubB64)); err != nil {
		t.Fatal(err)
	}
	// v1 lists are rejected by default; the caller must opt in explicitly.
	if _, err := license.LoadRevocationList(ring, revData, timeNow()); err == nil {
		t.Fatal("expected default policy to reject a v1 list")
	}
	pol := license.RevocationPolicy{}.AllowLegacyV1Revocation()
	rp, err := license.LoadRevocationListWithPolicy(ring, revData, timeNow(), pol)
	if err != nil {
		t.Fatalf("load v1 list with legacy opt-in: %v", err)
	}
	if !rp.IsRevoked("lic_v1") {
		t.Fatal("expected lic_v1 revoked under legacy policy")
	}
}

// revoke-list to an existing -out without -force fails; with -force overwrites.
func TestCmdRevokeListForce(t *testing.T) {
	dir, privPath, _ := newTestKeyPair(t, "k1")
	revPath := filepath.Join(dir, "revocation.json")
	args := []string{"-key", privPath, "-key-id", "k1", "-ids", "lic_a", "-sequence", "1", "-ttl", "1h", "-out", revPath}
	if _, err := captureStdout(t, func() error { return cmdRevokeList(args) }); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if _, err := captureStdout(t, func() error { return cmdRevokeList(args) }); err == nil {
		t.Fatal("expected no-clobber error without -force")
	}
	if _, err := captureStdout(t, func() error { return cmdRevokeList(append(args, "-force")) }); err != nil {
		t.Fatalf("forced overwrite: %v", err)
	}
}

// A missing ids-file path is a runtime error.
func TestCmdRevokeListMissingIDsFile(t *testing.T) {
	dir, privPath, _ := newTestKeyPair(t, "k1")
	if err := cmdRevokeList([]string{
		"-key", privPath, "-key-id", "k1", "-ids-file", filepath.Join(dir, "no-ids.txt"),
		"-sequence", "1", "-ttl", "1h",
	}); err == nil {
		t.Fatal("expected error for missing ids-file")
	}
}

// A missing private key file fails before signing.
func TestCmdRevokeListMissingKeyFile(t *testing.T) {
	dir, _, _ := newTestKeyPair(t, "k1")
	if err := cmdRevokeList([]string{
		"-key", filepath.Join(dir, "no-such.key"), "-key-id", "k1",
		"-ids", "lic_a", "-sequence", "1", "-ttl", "1h",
	}); err == nil {
		t.Fatal("expected error for missing private key file")
	}
}

// --- fingerprint -json branch -----------------------------------------------

// The -json branch prints the full fingerprint object (or reports insufficient
// hardware info on fallback platforms). Anything else is a failure.
func TestCmdFingerprintJSON(t *testing.T) {
	out, err := captureStdout(t, func() error {
		return cmdFingerprint([]string{"-namespace", "ns", "-json"})
	})
	if err != nil {
		if !strings.Contains(err.Error(), "insufficient hardware info") {
			t.Fatalf("unexpected fingerprint -json error: %v", err)
		}
		return
	}
	var obj map[string]any
	if uerr := json.Unmarshal([]byte(out), &obj); uerr != nil {
		t.Fatalf("fingerprint -json not valid JSON: %v\n%s", uerr, out)
	}
}

// --- util error paths --------------------------------------------------------

// writeExclusive into a non-existent directory fails (create error path).
func TestWriteExclusiveBadDir(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "no-such-subdir", "out.txt")
	if err := writeFileNoClobber(bad, []byte("x"), 0o644, false); err == nil {
		t.Fatal("expected error writing into a non-existent directory")
	}
}

// writeAtomicReplace (force mode) into a non-existent directory fails when the
// temp file cannot be created.
func TestWriteAtomicReplaceBadDir(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "no-such-subdir", "out.txt")
	if err := writeFileNoClobber(bad, []byte("x"), 0o644, true); err == nil {
		t.Fatal("expected error force-writing into a non-existent directory")
	}
}

// readPublicKeyFile on a missing path returns an error.
func TestReadPublicKeyFileMissing(t *testing.T) {
	if _, err := readPublicKeyFile(filepath.Join(t.TempDir(), "no.key")); err == nil {
		t.Fatal("expected error reading a missing public key file")
	}
}

// marshalIndentEnvelope must reject values that cannot be JSON-encoded.
func TestMarshalIndentEnvelopeError(t *testing.T) {
	if _, err := marshalIndentEnvelope(make(chan int)); err == nil {
		t.Fatal("expected error marshaling an unencodable value")
	}
}
