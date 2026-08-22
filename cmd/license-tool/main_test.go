package main

import (
	"os"
	"strings"
	"testing"
)

// The exit-code contract is verified directly through run(args, stdout, stderr)
// with buffered streams. No subprocess re-exec or os.Exit is needed: run returns
// the code that main() would pass to os.Exit, and never exits the process
// itself, so tests assert both the code and the output stream a real invocation
// would produce.

// Successful invocations and every help form return exit code 0.
func TestRunExitZero(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantOut  string // substring expected on stdout
		wantErr  string // substring expected on stderr ("" = no assertion)
		wantCode int
	}{
		{"version", []string{"version"}, "license-tool", "", exitOK},
		{"version alias -v", []string{"-v"}, "license-tool", "", exitOK},
		{"version alias --version", []string{"--version"}, "license-tool", "", exitOK},
		{"top-level help", []string{"help"}, "Usage:", "", exitOK},
		{"top-level -h", []string{"-h"}, "Usage:", "", exitOK},
		{"top-level --help", []string{"--help"}, "Usage:", "", exitOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, errOut, code := runCLI(tc.args...)
			if code != tc.wantCode {
				t.Fatalf("code = %d, want %d (stdout=%q stderr=%q)", code, tc.wantCode, out, errOut)
			}
			if tc.wantOut != "" && !strings.Contains(out, tc.wantOut) {
				t.Fatalf("stdout %q missing %q", out, tc.wantOut)
			}
		})
	}
}

// A subcommand's -h/-help requests help: the flag package returns flag.ErrHelp,
// which run classifies as success (exit 0). The flag package writes its own
// usage text to the injected stderr; run adds no "error:" diagnostic.
func TestRunSubcommandHelpExitZero(t *testing.T) {
	for _, sub := range []string{"keygen", "public-key", "issue", "verify", "inspect", "fingerprint", "revoke-list", "version"} {
		for _, flag := range []string{"-h", "--help"} {
			out, errOut, code := runCLI(sub, flag)
			if code != exitOK {
				t.Fatalf("%s %s: code = %d, want 0 (stdout=%q stderr=%q)", sub, flag, code, out, errOut)
			}
			if strings.Contains(errOut, "error:") {
				t.Fatalf("%s %s: help should not print an error diagnostic, got stderr=%q", sub, flag, errOut)
			}
		}
	}
}

// Usage errors (exit 2): no args, unknown command, unknown flag, missing
// required flags, and malformed user input (duration / RFC3339 / enum / bool /
// number). Each writes a diagnostic to stderr, never stdout.
func TestRunUsageErrorsExitTwo(t *testing.T) {
	_, privPath, pubPath := newTestKeyPair(t, "k1")
	licPath := issueTestLicense(t, t.TempDir(), "k1", privPath)

	cases := []struct {
		name string
		args []string
	}{
		{"no args", nil},
		{"unknown command", []string{"definitely-not-a-command"}},

		{"unknown flag keygen", []string{"keygen", "-nope"}},
		{"unknown flag verify", []string{"verify", "-nope"}},

		{"keygen missing key-id", []string{"keygen"}},
		{"public-key missing key", []string{"public-key"}},
		{"issue missing flags", []string{"issue"}},
		{"verify missing flags", []string{"verify"}},
		{"verify missing product", []string{"verify", "-license", licPath, "-pubkey", pubPath}},
		{"inspect missing flags", []string{"inspect"}},
		{"fingerprint missing namespace", []string{"fingerprint"}},
		{"revoke-list missing key/key-id", []string{"revoke-list"}},

		// Malformed user input parsed by the flag package -> usage (2).
		{"bad duration ttl", []string{"revoke-list", "-key", privPath, "-key-id", "k1", "-ids", "lic_a", "-ttl", "not-a-duration"}},
		{"bad duration clock-skew", []string{"verify", "-license", licPath, "-pubkey", pubPath, "-product", "p", "-clock-skew", "5"}},
		{"bad bool force", []string{"issue", "-force=notabool"}},
		{"bad number sequence", []string{"revoke-list", "-key", privPath, "-key-id", "k1", "-sequence", "not-a-number"}},

		// Malformed user input parsed by the command body -> usage (2).
		{"bad RFC3339 expires-at", []string{"revoke-list", "-key", privPath, "-key-id", "k1", "-ids", "lic_a", "-sequence", "1", "-expires-at", "nope"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, errOut, code := runCLI(tc.args...)
			if code != exitUsage {
				t.Fatalf("code = %d, want 2 (stdout=%q stderr=%q)", code, out, errOut)
			}
			if strings.TrimSpace(out) != "" {
				t.Fatalf("usage error must not write to stdout, got %q", out)
			}
			if strings.TrimSpace(errOut) == "" {
				t.Fatal("usage error should write a diagnostic to stderr")
			}
		})
	}
}

// A malformed issue config (unknown field) is user input -> usage (2).
func TestRunIssueBadConfigExitTwo(t *testing.T) {
	dir, privPath, _ := newTestKeyPair(t, "k1")
	cfg := writeBadIssueConfig(t, dir)
	_, errOut, code := runCLI("issue", "-config", cfg, "-key", privPath)
	if code != exitUsage {
		t.Fatalf("bad config code = %d, want 2 (stderr=%q)", code, errOut)
	}
}

// Runtime/domain errors (exit 1): file I/O, key loading, and license rejection.
func TestRunRuntimeErrorsExitOne(t *testing.T) {
	dir, privPath, pubPath := newTestKeyPair(t, "k1")
	licPath := issueTestLicense(t, dir, "k1", privPath)

	cases := []struct {
		name string
		args []string
	}{
		{"issue missing config file", []string{"issue", "-config", dir + "/no-such.json", "-key", privPath}},
		{"issue missing key file", []string{"issue", "-config", writeIssueConfig(t, dir, "k1"), "-key", dir + "/no-such.key"}},
		{"verify missing license file", []string{"verify", "-license", dir + "/no-such.json", "-pubkey", pubPath, "-product", "prod-1"}},
		{"verify license rejected (wrong product)", []string{"verify", "-license", licPath, "-pubkey", pubPath, "-product", "other-product"}},
		{"public-key missing key file", []string{"public-key", "-key", dir + "/no-such.key"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, errOut, code := runCLI(tc.args...)
			if code != exitRuntime {
				t.Fatalf("code = %d, want 1 (stdout=%q stderr=%q)", code, out, errOut)
			}
			if !strings.Contains(errOut, "error:") {
				t.Fatalf("runtime error should print an 'error:' diagnostic to stderr, got %q", errOut)
			}
		})
	}
}

// Success paths (exit 0) that produce real output and side effects.
func TestRunSuccessExitZero(t *testing.T) {
	dir, privPath, pubPath := newTestKeyPair(t, "k1")
	licPath := issueTestLicense(t, dir, "k1", privPath)

	out, errOut, code := runCLI("verify", "-license", licPath, "-pubkey", pubPath, "-product", "prod-1")
	if code != exitOK {
		t.Fatalf("verify code = %d, want 0 (stderr=%q)", code, errOut)
	}
	if !strings.Contains(out, "status:") {
		t.Fatalf("verify stdout missing status: %q", out)
	}
}

// writeBadIssueConfig writes a config JSON with an unknown field so strict
// decoding rejects it, and returns its path.
func writeBadIssueConfig(t *testing.T, dir string) string {
	t.Helper()
	path := dir + "/bad-config.json"
	if err := os.WriteFile(path, []byte(`{"unknown_field": true}`), 0o644); err != nil {
		t.Fatalf("write bad config: %v", err)
	}
	return path
}
