package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/soulteary/grantseal/internal/issuer"
)

func cmdKeygen(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyID := fs.String("key-id", "", "key identifier (required)")
	outDir := fs.String("out-dir", "./keys", "output directory for key files")
	force := fs.Bool("force", false, "overwrite an existing private key file")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *keyID == "" {
		return usageErrorf("keygen: -key-id is required")
	}
	kp, err := issuer.GenerateKeyPair(*keyID)
	if err != nil {
		return err
	}
	privPath, pubPath, err := kp.WriteKeyFiles(*outDir, *force)
	if err != nil {
		return err
	}
	// Never print the private key material itself; only its path.
	fmt.Fprintf(stdout, "key_id:      %s\n", kp.KeyID)
	fmt.Fprintf(stdout, "private_key: %s (mode 0600 - keep secret, never commit)\n", privPath)
	fmt.Fprintf(stdout, "public_key:  %s\n", pubPath)
	fmt.Fprintf(stdout, "public_b64:  %s\n", kp.PublicKeyBase64())
	return nil
}
