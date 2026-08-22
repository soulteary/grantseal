package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/soulteary/grantseal/internal/issuer"
	"github.com/soulteary/grantseal/pkg/license"
)

// cmdFunc is the shared shape of every subcommand handler after the exit-code
// refactor: it takes the subcommand args plus injected stdout/stderr writers.
type cmdFunc func(args []string, stdout, stderr io.Writer) error

// callCmd invokes a subcommand handler with buffered stdout/stderr and returns
// what it wrote to stdout plus the handler's error. Handlers write only to the
// injected writers (never the global os.Stdout/os.Stderr), so this needs no
// pipe redirection and is safe under -race.
func callCmd(fn cmdFunc, args []string) (stdout string, err error) {
	var out, errBuf bytes.Buffer
	err = fn(args, &out, &errBuf)
	return out.String(), err
}

// runCLI drives the top-level run() entry with buffered streams and returns
// stdout, stderr, and the process exit code. Tests assert the exit-code
// contract directly through run without ever calling os.Exit.
func runCLI(args ...string) (stdout, stderr string, code int) {
	var out, errBuf bytes.Buffer
	code = run(args, &out, &errBuf)
	return out.String(), errBuf.String(), code
}

// newTestKeyPair writes a key pair to a temp dir and returns paths + key id.
func newTestKeyPair(t *testing.T, keyID string) (dir, privPath, pubPath string) {
	t.Helper()
	dir = t.TempDir()
	kp, err := issuer.GenerateKeyPair(keyID)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	privPath, pubPath, err = kp.WriteKeyFiles(dir, false)
	if err != nil {
		t.Fatalf("WriteKeyFiles: %v", err)
	}
	return dir, privPath, pubPath
}

// writeIssueConfig writes a minimal valid issue-config.json and returns its path.
func writeIssueConfig(t *testing.T, dir, keyID string) string {
	t.Helper()
	cfg := issueConfig{
		KeyID:       keyID,
		ProductID:   "prod-1",
		CustomerID:  "cust-1",
		Edition:     string(license.EditionBasic),
		LicenseType: string(license.LicenseTypeSubscription),
		ExpiresAt:   "2999-01-01T00:00:00Z",
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	path := filepath.Join(dir, "issue-config.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestCmdVersion(t *testing.T) {
	out, err := callCmd(cmdVersion, nil)
	if err != nil {
		t.Fatalf("cmdVersion: %v", err)
	}
	if !strings.Contains(out, "license-tool") {
		t.Fatalf("version output missing name: %q", out)
	}
}

func TestCmdKeygenRequiresKeyID(t *testing.T) {
	if _, err := callCmd(cmdKeygen, nil); err == nil {
		t.Fatal("expected error when -key-id missing")
	}
}

func TestCmdKeygenWritesFiles(t *testing.T) {
	dir := t.TempDir()
	out, err := callCmd(cmdKeygen, []string{"-key-id", "k1", "-out-dir", dir})
	if err != nil {
		t.Fatalf("cmdKeygen: %v", err)
	}
	if strings.Contains(out, "-----BEGIN") {
		t.Fatalf("keygen output must not contain private key material: %q", out)
	}
	if !strings.Contains(out, "public_b64:") {
		t.Fatalf("keygen output missing public key: %q", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "k1-private.key")); err != nil {
		t.Fatalf("private key not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "k1-public.key")); err != nil {
		t.Fatalf("public key not written: %v", err)
	}
}

func TestCmdPublicKey(t *testing.T) {
	_, privPath, pubPath := newTestKeyPair(t, "k1")
	out, err := callCmd(cmdPublicKey, []string{"-key", privPath})
	if err != nil {
		t.Fatalf("cmdPublicKey: %v", err)
	}
	wantB64, _ := os.ReadFile(pubPath)
	if strings.TrimSpace(out) != strings.TrimSpace(string(wantB64)) {
		t.Fatalf("public-key mismatch:\n got %q\nwant %q", out, string(wantB64))
	}
}

func TestCmdPublicKeyRequiresKey(t *testing.T) {
	if _, err := callCmd(cmdPublicKey, nil); err == nil {
		t.Fatal("expected error when -key missing")
	}
}

func TestCmdIssueRequiresFlags(t *testing.T) {
	if _, err := callCmd(cmdIssue, nil); err == nil {
		t.Fatal("expected error when -config and -key missing")
	}
}

func TestCmdIssueVerifyInspectRoundTrip(t *testing.T) {
	dir, privPath, pubPath := newTestKeyPair(t, "k1")
	cfgPath := writeIssueConfig(t, dir, "k1")
	licPath := filepath.Join(dir, "license.json")

	if _, err := callCmd(cmdIssue, []string{"-config", cfgPath, "-key", privPath, "-out", licPath}); err != nil {
		t.Fatalf("cmdIssue: %v", err)
	}
	if _, err := os.Stat(licPath); err != nil {
		t.Fatalf("license not written: %v", err)
	}

	verifyOut, err := callCmd(cmdVerify, []string{"-license", licPath, "-pubkey", pubPath, "-product", "prod-1"})
	if err != nil {
		t.Fatalf("cmdVerify: %v", err)
	}
	if !strings.Contains(verifyOut, "status:") || !strings.Contains(verifyOut, "prod-1") {
		t.Fatalf("verify output unexpected: %q", verifyOut)
	}

	inspectOut, err := callCmd(cmdInspect, []string{"-license", licPath, "-pubkey", pubPath})
	if err != nil {
		t.Fatalf("cmdInspect: %v", err)
	}
	var payload license.Payload
	if err := json.Unmarshal([]byte(inspectOut), &payload); err != nil {
		t.Fatalf("inspect output not valid payload JSON: %v\n%s", err, inspectOut)
	}
	if payload.ProductID != "prod-1" {
		t.Fatalf("inspect product mismatch: %q", payload.ProductID)
	}
}

func TestCmdVerifyWrongProductReturnsError(t *testing.T) {
	dir, privPath, pubPath := newTestKeyPair(t, "k1")
	cfgPath := writeIssueConfig(t, dir, "k1")
	licPath := filepath.Join(dir, "license.json")
	if _, err := callCmd(cmdIssue, []string{"-config", cfgPath, "-key", privPath, "-out", licPath}); err != nil {
		t.Fatalf("cmdIssue: %v", err)
	}
	_, err := callCmd(cmdVerify, []string{"-license", licPath, "-pubkey", pubPath, "-product", "other-product"})
	if err == nil {
		t.Fatal("expected verify error for product mismatch")
	}
}

func TestCmdVerifyRequiresFlags(t *testing.T) {
	if _, err := callCmd(cmdVerify, nil); err == nil {
		t.Fatal("expected error when -license and -pubkey missing")
	}
}

func TestCmdInspectRequiresFlags(t *testing.T) {
	if _, err := callCmd(cmdInspect, nil); err == nil {
		t.Fatal("expected error when -license and -pubkey missing")
	}
}

func TestCmdIssueBadConfig(t *testing.T) {
	dir, privPath, _ := newTestKeyPair(t, "k1")
	cfgPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(cfgPath, []byte(`{"unknown_field": true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := callCmd(cmdIssue, []string{"-config", cfgPath, "-key", privPath}); err == nil {
		t.Fatal("expected error on unknown config field")
	}
}

func TestCmdRevokeListRequiresFlags(t *testing.T) {
	if _, err := callCmd(cmdRevokeList, nil); err == nil {
		t.Fatal("expected error when -key and -key-id missing")
	}
}

func TestCmdRevokeListNoIDs(t *testing.T) {
	_, privPath, _ := newTestKeyPair(t, "k1")
	if _, err := callCmd(cmdRevokeList, []string{"-key", privPath, "-key-id", "k1"}); err == nil {
		t.Fatal("expected error when no ids provided")
	}
}

func TestCmdRevokeListRoundTrip(t *testing.T) {
	dir, privPath, pubPath := newTestKeyPair(t, "k1")
	revPath := filepath.Join(dir, "revocation.json")
	if _, err := callCmd(cmdRevokeList, []string{"-key", privPath, "-key-id", "k1", "-ids", "lic_a,lic_b", "-sequence", "1", "-ttl", "8760h", "-list-id", "list-1", "-out", revPath}); err != nil {
		t.Fatalf("cmdRevokeList: %v", err)
	}
	revData, err := os.ReadFile(revPath)
	if err != nil {
		t.Fatalf("read revocation: %v", err)
	}
	pubB64, _ := os.ReadFile(pubPath)
	ring := license.NewKeyRing()
	if err := ring.AddPublicKeyBase64("k1", string(pubB64)); err != nil {
		t.Fatal(err)
	}
	rp, err := license.LoadRevocationList(ring, revData, timeNow())
	if err != nil {
		t.Fatalf("load revocation list: %v", err)
	}
	if !rp.IsRevoked("lic_a") || !rp.IsRevoked("lic_b") {
		t.Fatal("expected lic_a and lic_b to be revoked")
	}
}

func TestCmdRevokeListIDsFile(t *testing.T) {
	dir, privPath, pubPath := newTestKeyPair(t, "k1")
	idsFile := filepath.Join(dir, "ids.txt")
	if err := os.WriteFile(idsFile, []byte("lic_x\n\nlic_y\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	revPath := filepath.Join(dir, "revocation.json")
	if _, err := callCmd(cmdRevokeList, []string{"-key", privPath, "-key-id", "k1", "-ids-file", idsFile, "-sequence", "1", "-ttl", "8760h", "-list-id", "list-1", "-out", revPath}); err != nil {
		t.Fatalf("cmdRevokeList ids-file: %v", err)
	}
	revData, err := os.ReadFile(revPath)
	if err != nil {
		t.Fatalf("read revocation: %v", err)
	}
	pubB64, _ := os.ReadFile(pubPath)
	ring := license.NewKeyRing()
	if err := ring.AddPublicKeyBase64("k1", string(pubB64)); err != nil {
		t.Fatal(err)
	}
	rp, err := license.LoadRevocationList(ring, revData, timeNow())
	if err != nil {
		t.Fatalf("load revocation list: %v", err)
	}
	if !rp.IsRevoked("lic_x") || !rp.IsRevoked("lic_y") {
		t.Fatal("expected lic_x and lic_y to be revoked (blank lines skipped)")
	}
}

func TestCmdFingerprintRequiresNamespace(t *testing.T) {
	if _, err := callCmd(cmdFingerprint, nil); err == nil {
		t.Fatal("expected error when -namespace missing")
	}
}

// cmdFingerprint depends on host hardware; on fallback platforms it returns an
// insufficient-info error. We accept either a successful fingerprint or that
// specific error, but never a panic or a different failure.
func TestCmdFingerprintRunsOrReportsInsufficient(t *testing.T) {
	out, err := callCmd(cmdFingerprint, []string{"-namespace", "test-ns"})
	if err != nil {
		if !strings.Contains(err.Error(), "insufficient hardware info") {
			t.Fatalf("unexpected fingerprint error: %v", err)
		}
		return
	}
	if strings.TrimSpace(out) == "" {
		t.Fatal("expected non-empty fingerprint output")
	}
}

func TestWriteFileNoClobber(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	if err := writeFileNoClobber(path, []byte("first"), 0o644, false); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := writeFileNoClobber(path, []byte("second"), 0o644, false); err == nil {
		t.Fatal("expected no-clobber error on existing file")
	}
	if err := writeFileNoClobber(path, []byte("second"), 0o644, true); err != nil {
		t.Fatalf("forced overwrite: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "second" {
		t.Fatalf("force overwrite content = %q", string(got))
	}
}

// The -v2 fingerprint mode runs the v2 code path (per-platform primary
// identifier). Like v1 it may report insufficient hardware info on fallback
// platforms; anything else — including a panic — is a failure. With
// -request-code the emitted code is tagged with the V2- version prefix.
func TestCmdFingerprintV2RunsOrReportsInsufficient(t *testing.T) {
	out, err := callCmd(cmdFingerprint, []string{"-namespace", "test-ns", "-v2", "-request-code"})
	if err != nil {
		if !strings.Contains(err.Error(), "insufficient hardware info") {
			t.Fatalf("unexpected v2 fingerprint error: %v", err)
		}
		return
	}
	if strings.TrimSpace(out) == "" {
		t.Fatal("expected non-empty v2 request code output")
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "V2-") {
		t.Fatalf("expected a V2- request code in output, got: %q", out)
	}
}

// writeFileNoClobber in force mode must overwrite an existing file atomically
// while preserving the requested permission bits.
func TestWriteFileNoClobberForcePreservesPerm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "perm.txt")
	if err := writeFileNoClobber(path, []byte("a"), 0o600, false); err != nil {
		t.Fatal(err)
	}
	if err := writeFileNoClobber(path, []byte("bb"), 0o600, true); err != nil {
		t.Fatalf("force overwrite: %v", err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode after force = %o, want 0600", fi.Mode().Perm())
		}
	}
	got, _ := os.ReadFile(path)
	if string(got) != "bb" {
		t.Fatalf("content = %q, want bb", string(got))
	}
}

func TestParseOptTime(t *testing.T) {
	if tm, err := parseOptTime(""); err != nil || tm != nil {
		t.Fatalf("empty time = (%v,%v), want (nil,nil)", tm, err)
	}
	if _, err := parseOptTime("not-a-time"); err == nil {
		t.Fatal("expected parse error for bad time")
	}
	tm, err := parseOptTime("2030-01-02T03:04:05Z")
	if err != nil || tm == nil {
		t.Fatalf("valid time parse failed: %v", err)
	}
	if tm.Location().String() != "UTC" {
		t.Fatalf("parsed time not UTC: %v", tm.Location())
	}
}

func TestSplitCSV(t *testing.T) {
	if got := splitCSV(""); got != nil {
		t.Fatalf("empty splitCSV = %v, want nil", got)
	}
	got := splitCSV("a, b ,,c")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("splitCSV len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitCSV[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
