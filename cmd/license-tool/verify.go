package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/soulteary/grantseal/pkg/license"
)

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	licPath := fs.String("license", "", "path to the license file (required)")
	pubPath := fs.String("pubkey", "", "path to a Base64URL public key file (required)")
	keyID := fs.String("key-id", "", "key_id for the public key (default: derive from license)")
	product := fs.String("product", "", "expected product_id (optional)")
	version := fs.String("version", "", "running product version (optional)")
	device := fs.String("device", "", "device fingerprint (optional)")
	revPath := fs.String("revocation", "", "path to a signed revocation list (optional)")
	clockSkew := fs.Duration("clock-skew", 0, "tolerated clock skew (e.g. 2s, 5m); 0 uses the default/env value")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *licPath == "" || *pubPath == "" {
		return fmt.Errorf("verify: -license and -pubkey are required")
	}

	pubB64, err := readPublicKeyFile(*pubPath)
	if err != nil {
		return err
	}

	// Determine the key_id: use the flag, else read it from the license envelope.
	licData, err := os.ReadFile(*licPath)
	if err != nil {
		return fmt.Errorf("verify: read license: %w", err)
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
		revData, rerr := os.ReadFile(*revPath)
		if rerr != nil {
			return fmt.Errorf("verify: read revocation: %w", rerr)
		}
		rp, rerr := license.LoadRevocationList(ring, revData, timeNow())
		if rerr != nil {
			return fmt.Errorf("verify: load revocation: %w", rerr)
		}
		ctx.Revocation = rp
	}

	res, verr := mgr.Validate(licData, ctx)
	printResult(res)
	if verr != nil {
		return fmt.Errorf("%s", license.CodeOf(verr))
	}
	return nil
}

func printResult(res license.ValidationResult) {
	fmt.Printf("status:      %s\n", res.Status())
	fmt.Printf("code:        %s\n", res.Code())
	if res.LicenseID() != "" {
		fmt.Printf("license_id:  %s\n", res.LicenseID())
		fmt.Printf("product_id:  %s\n", res.ProductID())
		fmt.Printf("edition:     %s\n", res.Edition())
		fmt.Printf("type:        %s\n", res.LicenseType())
		if exp := res.ExpiresAt(); exp != nil {
			fmt.Printf("expires_at:  %s\n", exp.Format("2006-01-02T15:04:05Z07:00"))
		}
		if feats := res.Features(); len(feats) > 0 {
			fmt.Printf("features:    %s\n", strings.Join(feats, ", "))
		}
	}
}
