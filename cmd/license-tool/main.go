// Command license-tool is the issuer-side CLI for grantseal. It generates keys,
// issues and inspects licenses, verifies licenses client-side, produces device
// fingerprints, and builds signed revocation lists.
//
// Private-key handling is confined to the keygen/issue/revoke-list commands and
// delegated to internal/issuer. Private keys are never printed to stdout.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

const usage = `license-tool - grantseal offline license CLI

Usage:
  license-tool <command> [flags]

Commands:
  keygen        Generate an Ed25519 key pair (private key stays local)
  public-key    Print the Base64URL public key derived from a private key
  issue         Issue and sign a license from a JSON config
  verify        Verify + policy-validate a license against a public key
  inspect       Verify signature and print the payload (no policy checks)
  fingerprint   Compute this device's fingerprint / request code
  revoke-list   Build a signed revocation list
  version       Print the license-tool version

Run "license-tool <command> -h" for command-specific flags.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// Exit codes form the CLI's stable compatibility contract:
//
//	0  success, --help/-h/help, and per-command -h/-help (flag.ErrHelp)
//	2  usage errors: unknown command, flag parse failures, missing required
//	   flags, and malformed user input (duration/RFC3339/enum/bool/number)
//	1  runtime/domain errors: file I/O, key loading, signing/verification
//	   failures, and license rejections
const (
	exitOK      = 0
	exitRuntime = 1
	exitUsage   = 2
)

// run dispatches a single license-tool invocation and returns its process exit
// code. It is the single place where errors are classified into exit codes, so
// main() only needs to forward the result. Normal output is written to stdout;
// diagnostics and usage text go to stderr. Classification uses error types
// (flag.ErrHelp and *usageError) rather than matching error strings.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	cmd := args[0]
	rest := args[1:]

	var err error
	switch cmd {
	case "keygen":
		err = cmdKeygen(rest, stdout, stderr)
	case "public-key":
		err = cmdPublicKey(rest, stdout, stderr)
	case "issue":
		err = cmdIssue(rest, stdout, stderr)
	case "verify":
		err = cmdVerify(rest, stdout, stderr)
	case "inspect":
		err = cmdInspect(rest, stdout, stderr)
	case "fingerprint":
		err = cmdFingerprint(rest, stdout, stderr)
	case "revoke-list":
		err = cmdRevokeList(rest, stdout, stderr)
	case "version", "--version", "-v":
		err = cmdVersion(rest, stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return exitUsage
	}

	return classify(err, stderr)
}

// classify maps a command's returned error to an exit code and writes any
// diagnostic to stderr. A nil error is success; flag.ErrHelp (a subcommand's
// -h/-help) is success with no extra diagnostic (the flag package already wrote
// its usage text); a *usageError is a usage failure (exit 2); anything else is a
// runtime/domain failure (exit 1).
func classify(err error, stderr io.Writer) int {
	if err == nil {
		return exitOK
	}
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	var ue *usageError
	if errors.As(err, &ue) {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}
	fmt.Fprintf(stderr, "error: %v\n", err)
	return exitRuntime
}
