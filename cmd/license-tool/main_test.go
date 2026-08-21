package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// mainTestEnv, when set, tells the re-executed test binary to run main() and
// exit instead of running the test suite. This is the classic Go subprocess
// pattern for covering functions that call os.Exit (main here). See
// https://pkg.go.dev/os#Exit and the stdlib's own os/exec tests for the shape.
const mainTestEnv = "GRANTSEAL_TEST_MAIN"

// TestMain intercepts the special env var: when it is set the process behaves as
// the license-tool binary (dispatching os.Args[2:] through main()), otherwise it
// runs the normal test suite. os.Args is rewritten so main() sees the caller's
// desired argv (the requested subcommand and flags follow the env sentinel).
func TestMain(m *testing.M) {
	if os.Getenv(mainTestEnv) == "1" {
		// os.Args here is: [test-binary, <subcommand>, <flags...>]. main() reads
		// os.Args[1:], so leave it as-is and just invoke main().
		main()
		return
	}
	os.Exit(m.Run())
}

// runMain re-execs this test binary with GRANTSEAL_TEST_MAIN=1 so the child
// process runs main() with the supplied args. It returns combined output and
// the child's exit code (0 on success).
func runMain(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), mainTestEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	ee, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("runMain %v: unexpected error type %T: %v", args, err, err)
	}
	return string(out), ee.ExitCode()
}

// The version subcommand dispatches through main() to cmdVersion and exits 0.
func TestMainVersion(t *testing.T) {
	out, code := runMain(t, "version")
	if code != 0 {
		t.Fatalf("version exit code = %d, want 0 (output: %q)", code, out)
	}
	if !strings.Contains(out, "license-tool") {
		t.Fatalf("version output missing name: %q", out)
	}
}

// The help subcommand prints usage to stdout and returns without os.Exit (0).
func TestMainHelp(t *testing.T) {
	out, code := runMain(t, "help")
	if code != 0 {
		t.Fatalf("help exit code = %d, want 0 (output: %q)", code, out)
	}
	if !strings.Contains(out, "Usage:") {
		t.Fatalf("help output missing usage: %q", out)
	}
}

// An unknown subcommand prints the usage banner and exits with code 2.
func TestMainUnknownCommand(t *testing.T) {
	out, code := runMain(t, "definitely-not-a-command")
	if code != 2 {
		t.Fatalf("unknown command exit code = %d, want 2 (output: %q)", code, out)
	}
	if !strings.Contains(out, "unknown command") {
		t.Fatalf("unknown command output missing message: %q", out)
	}
}

// No args triggers the usage-and-exit-2 branch (len(os.Args) < 2).
func TestMainNoArgs(t *testing.T) {
	out, code := runMain(t)
	if code != 2 {
		t.Fatalf("no-args exit code = %d, want 2 (output: %q)", code, out)
	}
	if !strings.Contains(out, "Usage:") {
		t.Fatalf("no-args output missing usage: %q", out)
	}
}

// A handler returning a runtime (non-usage) error makes main() exit 1. issue
// with a missing config file is a read failure, i.e. exit code 1.
func TestMainRuntimeErrorExit1(t *testing.T) {
	out, code := runMain(t, "issue", "-config", "/no/such/config.json", "-key", "/no/such.key")
	if code != 1 {
		t.Fatalf("runtime-error exit code = %d, want 1 (output: %q)", code, out)
	}
	if !strings.Contains(out, "error:") {
		t.Fatalf("runtime error output missing 'error:' prefix: %q", out)
	}
}

// A handler returning a usageError makes main() exit 2. revoke-list without a
// -sequence for a v2 list yields a *usageError.
func TestMainUsageErrorExit2(t *testing.T) {
	_, privPath, _ := newTestKeyPair(t, "k1")
	out, code := runMain(t, "revoke-list", "-key", privPath, "-key-id", "k1", "-ids", "lic_a", "-ttl", "1h")
	if code != 2 {
		t.Fatalf("usage-error exit code = %d, want 2 (output: %q)", code, out)
	}
	if !strings.Contains(out, "error:") {
		t.Fatalf("usage error output missing 'error:' prefix: %q", out)
	}
}

// Every remaining switch case in main() must be reachable. We drive each
// subcommand with a flag that makes its handler fail fast (so no real key/IO is
// needed), asserting only that main() dispatched it and exited non-zero — this
// exercises the per-command dispatch statements. The version aliases (-v,
// --version) route to cmdVersion and exit 0.
func TestMainDispatchesAllSubcommands(t *testing.T) {
	nonZero := [][]string{
		{"keygen"},                              // -key-id required -> exit 1
		{"public-key"},                          // -key required -> exit 1
		{"verify"},                              // -license/-pubkey required -> exit 1
		{"inspect"},                             // -license/-pubkey required -> exit 1
		{"fingerprint"},                         // -namespace required -> exit 1
		{"issue"},                               // -config/-key required -> exit 1
		{"revoke-list"},                         // -key/-key-id required -> exit 1
		{"keygen", "-this-flag-does-not-exist"}, // flag parse error -> exit 1
	}
	for _, args := range nonZero {
		out, code := runMain(t, args...)
		if code == 0 {
			t.Fatalf("%v: expected non-zero exit, got 0 (output: %q)", args, out)
		}
	}

	for _, alias := range []string{"-v", "--version"} {
		out, code := runMain(t, alias)
		if code != 0 {
			t.Fatalf("%s exit code = %d, want 0 (output: %q)", alias, code, out)
		}
		if !strings.Contains(out, "license-tool") {
			t.Fatalf("%s output missing name: %q", alias, out)
		}
	}
}
