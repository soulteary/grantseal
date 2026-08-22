package main

import (
	"bytes"
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
	// Never print the private key material itself; only its path. Build the
	// whole block first, then write it in one checkable call so a write failure
	// surfaces to the caller instead of being silently dropped.
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "key_id:      %s\n", kp.KeyID)
	fmt.Fprintf(&buf, "private_key: %s (mode 0600 - keep secret, never commit)\n", privPath)
	fmt.Fprintf(&buf, "public_key:  %s\n", pubPath)
	fmt.Fprintf(&buf, "public_b64:  %s\n", kp.PublicKeyBase64())
	return writeString(stdout, buf.String())
}
