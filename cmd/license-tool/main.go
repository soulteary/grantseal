// Command license-tool is the issuer-side CLI for grantseal. It generates keys,
// issues and inspects licenses, verifies licenses client-side, produces device
// fingerprints, and builds signed revocation lists.
//
// Private-key handling is confined to the keygen/issue/revoke-list commands and
// delegated to internal/issuer. Private keys are never printed to stdout.
package main

import (
	"fmt"
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
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "keygen":
		err = cmdKeygen(args)
	case "public-key":
		err = cmdPublicKey(args)
	case "issue":
		err = cmdIssue(args)
	case "verify":
		err = cmdVerify(args)
	case "inspect":
		err = cmdInspect(args)
	case "fingerprint":
		err = cmdFingerprint(args)
	case "revoke-list":
		err = cmdRevokeList(args)
	case "version", "--version", "-v":
		err = cmdVersion(args)
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
