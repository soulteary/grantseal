package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/soulteary/grantseal/internal/issuer"
	"github.com/soulteary/grantseal/pkg/license"
)

func cmdRevokeList(args []string) error {
	fs := flag.NewFlagSet("revoke-list", flag.ContinueOnError)
	keyPath := fs.String("key", "", "path to the private key file (required)")
	keyID := fs.String("key-id", "", "key_id for the signature (required)")
	ids := fs.String("ids", "", "comma-separated license_ids to revoke")
	idsFile := fs.String("ids-file", "", "file with one license_id per line")
	listID := fs.String("list-id", "", "logical list id (v2; keeps a separate client high-water mark)")
	sequence := fs.Uint64("sequence", 0, "v2 monotonically increasing publication counter (required unless -v1)")
	expiresAt := fs.String("expires-at", "", "v2 expiry as RFC3339 (e.g. 2026-12-31T00:00:00Z); mutually exclusive with -ttl")
	ttl := fs.Duration("ttl", 0, "v2 time-to-live from now (e.g. 720h); mutually exclusive with -expires-at")
	v1 := fs.Bool("v1", false, "emit a LEGACY v1 list (no replay resistance; clients must opt in to accept)")
	out := fs.String("out", "", "output revocation file path (default stdout)")
	force := fs.Bool("force", false, "overwrite existing output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *keyID == "" {
		return &usageError{msg: "revoke-list: -key and -key-id are required"}
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
		return &usageError{msg: "revoke-list: no license_ids provided"}
	}

	priv, err := issuer.LoadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	signer, err := issuer.NewSigner(*keyID, priv)
	if err != nil {
		return err
	}

	var env *license.RevocationEnvelope
	if *v1 {
		env, err = issuer.BuildRevocationList(signer, revoked)
	} else {
		env, err = buildRevocationV2(signer, revoked, *listID, *sequence, *expiresAt, *ttl)
	}
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

// buildRevocationV2 assembles a v2 revocation list from CLI flags, enforcing
// that a sequence is present and exactly one expiry source is provided.
func buildRevocationV2(signer *issuer.Signer, revoked []string, listID string, sequence uint64, expiresAt string, ttl time.Duration) (*license.RevocationEnvelope, error) {
	if sequence == 0 {
		return nil, &usageError{msg: "revoke-list: -sequence is required for v2 lists (use -v1 for a legacy list)"}
	}
	if expiresAt != "" && ttl > 0 {
		return nil, &usageError{msg: "revoke-list: -expires-at and -ttl are mutually exclusive"}
	}
	now := timeNow().UTC()
	var exp time.Time
	switch {
	case expiresAt != "":
		t, perr := time.Parse(time.RFC3339, expiresAt)
		if perr != nil {
			return nil, &usageError{msg: "revoke-list: invalid -expires-at (want RFC3339): " + perr.Error()}
		}
		exp = t.UTC()
	case ttl > 0:
		exp = now.Add(ttl)
	default:
		return nil, &usageError{msg: "revoke-list: provide -expires-at or -ttl for v2 lists"}
	}
	return issuer.BuildRevocationListV2(signer, issuer.RevocationListOptions{
		ListID:     listID,
		Sequence:   sequence,
		IssuedAt:   now,
		ExpiresAt:  exp,
		RevokedIDs: revoked,
	})
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
