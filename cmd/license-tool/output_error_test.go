package main

import (
	"errors"
	"strings"
	"testing"
)

// failWriter fails every Write, modeling a broken pipe / full disk / closed
// stdout so the output-error-propagation contract (P2-1) can be exercised.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

// shortWriter accepts fewer bytes than requested without returning an error,
// modeling a short write; the checkable output helpers must still treat this as
// a failure.
type shortWriter struct{ n int }

func (s *shortWriter) Write(p []byte) (int, error) {
	if len(p) <= s.n {
		return len(p), nil
	}
	return s.n, nil
}

func TestWriteStringSurfacesError(t *testing.T) {
	if err := writeString(failWriter{}, "hello"); err == nil {
		t.Fatal("writeString must return the underlying write error")
	}
	if err := writeLine(failWriter{}, "hello"); err == nil {
		t.Fatal("writeLine must return the underlying write error")
	}
}

func TestWriteStringDetectsShortWrite(t *testing.T) {
	if err := writeString(&shortWriter{n: 2}, "hello"); err == nil {
		t.Fatal("writeString must fail on a short write")
	}
}

// Each command whose PRIMARY output is stdout must return the write error when
// stdout fails, so run() maps it to a non-zero exit rather than reporting
// success on a dropped write.
func TestCommandsPropagateStdoutWriteError(t *testing.T) {
	dir, privPath, pubPath := newTestKeyPair(t, "k1")
	licPath := issueTestLicense(t, dir, "k1", privPath)

	var errBuf strings.Builder

	if err := cmdVersion(nil, failWriter{}, &errBuf); err == nil {
		t.Fatal("version: expected stdout write error")
	}
	if err := cmdPublicKey([]string{"-key", privPath}, failWriter{}, &errBuf); err == nil {
		t.Fatal("public-key: expected stdout write error")
	}
	if err := cmdKeygen([]string{"-key-id", "kx", "-out-dir", t.TempDir()}, failWriter{}, &errBuf); err == nil {
		t.Fatal("keygen: expected stdout write error")
	}
	cfgPath := writeIssueConfig(t, dir, "k1")
	if err := cmdIssue([]string{"-config", cfgPath, "-key", privPath}, failWriter{}, &errBuf); err == nil {
		t.Fatal("issue(stdout): expected stdout write error")
	}
	if err := cmdVerify([]string{"-license", licPath, "-pubkey", pubPath, "-product", "prod-1"}, failWriter{}, &errBuf); err == nil {
		t.Fatal("verify: expected stdout write error")
	}
	if err := cmdInspect([]string{"-license", licPath, "-pubkey", pubPath}, failWriter{}, &errBuf); err == nil {
		t.Fatal("inspect: expected stdout write error")
	}
	if err := cmdRevokeList([]string{"-key", privPath, "-key-id", "k1", "-ids", "lic_a", "-sequence", "1", "-ttl", "1h", "-list-id", "l1"}, failWriter{}, &errBuf); err == nil {
		t.Fatal("revoke-list(stdout): expected stdout write error")
	}
}

// The top-level `help` output is business stdout too: a stdout write failure
// must map to a non-zero exit code, not exitOK.
func TestRunHelpWriteErrorNonZeroExit(t *testing.T) {
	var errBuf strings.Builder
	if code := run([]string{"help"}, failWriter{}, &errBuf); code == exitOK {
		t.Fatal("help with a failing stdout must not report success")
	}
}
