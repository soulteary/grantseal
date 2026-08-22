package main

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/soulteary/grantseal/pkg/license"
)

func cmdVerify(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	licPath := fs.String("license", "", "path to the license file (required)")
	pubPath := fs.String("pubkey", "", "path to a Base64URL public key file (required)")
	keyID := fs.String("key-id", "", "key_id for the public key (default: derive from license)")
	product := fs.String("product", "", "expected product_id (required; scopes validation to a product)")
	version := fs.String("version", "", "running product version (optional)")
	device := fs.String("device", "", "device fingerprint (optional)")
	revPath := fs.String("revocation", "", "path to a signed revocation list (optional)")
	clockSkew := fs.Duration("clock-skew", 0, "tolerated clock skew (e.g. 2s, 5m); 0 uses the default/env value")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *licPath == "" || *pubPath == "" {
		return &usageError{msg: "verify: -license and -pubkey are required"}
	}
	// Product scoping is required: an unscoped verification could authorize a
	// license issued for a different product. Missing -product is a usage error
	// (exit code 2), distinct from a validation failure (exit code 1).
	if *product == "" {
		return &usageError{msg: "verify: -product is required (scope validation to a product)"}
	}

	pubB64, err := readPublicKeyFile(*pubPath)
	if err != nil {
		return err
	}

	// Determine the key_id: use the flag, else read it from the license envelope.
	licData, err := readFileBounded(*licPath, "license", license.MaxLicenseFileSize)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
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

	var opts []license.Option
	if *clockSkew > 0 {
		opts = append(opts, license.WithClockSkew(*clockSkew))
	}
	mgr := license.NewManager(ring, opts...)

	ctx := license.ValidationContext{
		ProductID:         *product,
		ProductVersion:    *version,
		DeviceFingerprint: *device,
	}
	if *revPath != "" {
		revData, rerr := readFileBounded(*revPath, "revocation", license.MaxRevocationFileSize)
		if rerr != nil {
			return fmt.Errorf("verify: %w", rerr)
		}
		rp, rerr := license.LoadRevocationList(ring, revData, timeNow())
		if rerr != nil {
			return fmt.Errorf("verify: load revocation: %w", rerr)
		}
		ctx.Revocation = rp
	}

	res, verr := mgr.Validate(licData, ctx)
	printResult(stdout, res)
	if verr != nil {
		return fmt.Errorf("%s", license.CodeOf(verr))
	}
	return nil
}

func printResult(w io.Writer, res license.ValidationResult) {
	fmt.Fprintf(w, "status:      %s\n", res.Status())
	fmt.Fprintf(w, "code:        %s\n", res.Code())
	if res.LicenseID() != "" {
		fmt.Fprintf(w, "license_id:  %s\n", res.LicenseID())
		fmt.Fprintf(w, "product_id:  %s\n", res.ProductID())
		fmt.Fprintf(w, "edition:     %s\n", res.Edition())
		fmt.Fprintf(w, "type:        %s\n", res.LicenseType())
		if exp := res.ExpiresAt(); exp != nil {
			fmt.Fprintf(w, "expires_at:  %s\n", exp.Format("2006-01-02T15:04:05Z07:00"))
		}
		if feats := res.Features(); len(feats) > 0 {
			fmt.Fprintf(w, "features:    %s\n", strings.Join(feats, ", "))
		}
	}
}
