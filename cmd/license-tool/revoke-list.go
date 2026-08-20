package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/soulteary/grantseal/internal/issuer"
)

func cmdRevokeList(args []string) error {
	fs := flag.NewFlagSet("revoke-list", flag.ContinueOnError)
	keyPath := fs.String("key", "", "path to the private key file (required)")
	keyID := fs.String("key-id", "", "key_id for the signature (required)")
	ids := fs.String("ids", "", "comma-separated license_ids to revoke")
	idsFile := fs.String("ids-file", "", "file with one license_id per line")
	out := fs.String("out", "", "output revocation file path (default stdout)")
	force := fs.Bool("force", false, "overwrite existing output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *keyID == "" {
		return fmt.Errorf("revoke-list: -key and -key-id are required")
	}

	revoked := splitCSV(*ids)
	if *idsFile != "" {
		data, err := os.ReadFile(*idsFile)
		if err != nil {
			return fmt.Errorf("revoke-list: read ids-file: %w", err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				revoked = append(revoked, line)
			}
		}
	}
	if len(revoked) == 0 {
		return fmt.Errorf("revoke-list: no license_ids provided")
	}

	priv, err := issuer.LoadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	signer, err := issuer.NewSigner(*keyID, priv)
	if err != nil {
		return err
	}
	env, err := issuer.BuildRevocationList(signer, revoked)
	if err != nil {
		return err
	}
	data, err := marshalIndentEnvelope(env)
	if err != nil {
		return err
	}
	if *out == "" {
		fmt.Println(string(data))
		return nil
	}
	if err := writeFileNoClobber(*out, data, 0o644, *force); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote revocation list -> %s (%d ids)\n", *out, len(revoked))
	return nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
