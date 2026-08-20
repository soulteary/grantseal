package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"

	"github.com/soulteary/grantseal/internal/issuer"
)

func cmdPublicKey(args []string) error {
	fs := flag.NewFlagSet("public-key", flag.ContinueOnError)
	keyPath := fs.String("key", "", "path to the Base64URL private key file (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" {
		return fmt.Errorf("public-key: -key is required")
	}
	priv, err := issuer.LoadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	fmt.Println(base64.URLEncoding.EncodeToString(pub))
	return nil
}
