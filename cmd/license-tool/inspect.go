package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/soulteary/grantseal/pkg/license"
)

func cmdInspect(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	licPath := fs.String("license", "", "path to the license file (required)")
	pubPath := fs.String("pubkey", "", "path to a Base64URL public key file (required)")
	keyID := fs.String("key-id", "", "key_id for the public key (default: from license)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *licPath == "" || *pubPath == "" {
		return usageErrorf("inspect: -license and -pubkey are required")
	}
	licData, err := os.ReadFile(*licPath)
	if err != nil {
		return fmt.Errorf("inspect: read license: %w", err)
	}
	pubB64, err := readPublicKeyFile(*pubPath)
	if err != nil {
		return err
	}
	kid := *keyID
	if kid == "" {
		env, perr := license.ParseEnvelope(licData)
		if perr != nil {
			return perr
		}
		kid = env.KeyID
	}
	ring := license.NewKeyRing()
	if err := ring.AddPublicKeyBase64(kid, pubB64); err != nil {
		return err
	}
	mgr := license.NewManager(ring)
	payload, err := mgr.Inspect(licData)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, string(out))
	fmt.Fprintln(stderr, "note: signature verified; policy checks (time/device/product) NOT applied")
	return nil
}
