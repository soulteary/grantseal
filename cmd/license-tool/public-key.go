package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"io"

	"github.com/soulteary/grantseal/internal/issuer"
)

func cmdPublicKey(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("public-key", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyPath := fs.String("key", "", "path to the Base64URL private key file (required)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *keyPath == "" {
		return usageErrorf("public-key: -key is required")
	}
	priv, err := issuer.LoadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	fmt.Fprintln(stdout, base64.URLEncoding.EncodeToString(pub))
	return nil
}
