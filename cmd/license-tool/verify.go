package main

import (
	"bytes"
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
	var pubkeys pubkeyFlags
	fs.Var(&pubkeys, "pubkey", "public key: a Base64URL key file path, or keyID=path (repeatable for a multi-key ring)")
	keyringPath := fs.String("keyring", "", "path to a JSON keyring file ({\"keys\":[{key_id,public_key,...}]}); combine with or instead of -pubkey")
	revKeyringPath := fs.String("revocation-keyring", "", "optional separate JSON keyring authenticating the revocation list (defaults to the verification keys)")
	keyID := fs.String("key-id", "", "key_id for a bare -pubkey path (default: derive from license)")
	product := fs.String("product", "", "expected product_id (required; scopes validation to a product)")
	version := fs.String("version", "", "running product version (optional)")
	device := fs.String("device", "", "device fingerprint (optional)")
	revPath := fs.String("revocation", "", "path to a signed revocation list (optional)")
	clockSkew := fs.Duration("clock-skew", 0, "tolerated clock skew (e.g. 2s, 5m); 0 uses the default/env value")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *licPath == "" || (len(pubkeys.values) == 0 && *keyringPath == "") {
		return &usageError{msg: "verify: -license and at least one of -pubkey/-keyring are required"}
	}
	// Product scoping is required: an unscoped verification could authorize a
	// license issued for a different product. Missing -product is a usage error
	// (exit code 2), distinct from a validation failure (exit code 1).
	if *product == "" {
		return &usageError{msg: "verify: -product is required (scope validation to a product)"}
	}

	// Determine the default key_id for a bare -pubkey path: use the flag, else
	// read it from the license envelope. Only needed when a bare path is given
	// (keyID=path and -keyring entries carry their own id), but computed here so
	// the single-key legacy flow is unchanged.
	licData, err := readFileBounded(*licPath, "license", license.MaxLicenseFileSize)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	defaultKeyID := *keyID
	if defaultKeyID == "" && bareKeyIDNeeded(pubkeys.values) {
		env, perr := license.ParseEnvelope(licData)
		if perr != nil {
			return perr
		}
		defaultKeyID = env.KeyID
	}

	ring, err := buildVerifyKeyRing(pubkeys.values, *keyringPath, defaultKeyID)
	if err != nil {
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
		revRing, rrerr := verifyRevocationKeyRing(ring, *revKeyringPath)
		if rrerr != nil {
			return rrerr
		}
		revData, rerr := readFileBounded(*revPath, "revocation", license.MaxRevocationFileSize)
		if rerr != nil {
			return fmt.Errorf("verify: %w", rerr)
		}
		rp, rerr := license.LoadRevocationList(revRing, revData, timeNow())
		if rerr != nil {
			return fmt.Errorf("verify: load revocation: %w", rerr)
		}
		ctx.Revocation = rp
	}

	res, verr := mgr.Validate(licData, ctx)
	if werr := printResult(stdout, res); werr != nil {
		return werr
	}
	if verr != nil {
		return fmt.Errorf("%s", license.CodeOf(verr))
	}
	return nil
}

// bareKeyIDNeeded reports whether any -pubkey value is a bare path (no
// keyID=path form), which is the only case that needs a default key_id derived
// from the license/-key-id. When -keyring alone is used (no -pubkey), no bare
// key_id is needed.
func bareKeyIDNeeded(pubkeys []string) bool {
	for _, raw := range pubkeys {
		if spec, err := parsePubkeyValue(raw); err == nil && spec.keyID == "" {
			return true
		}
	}
	return false
}

// printResult renders the validation result to w as a single checkable write so
// a stdout write failure (broken pipe, full disk) surfaces to the caller
// instead of being silently dropped.
func printResult(w io.Writer, res license.ValidationResult) error {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "status:      %s\n", res.Status())
	fmt.Fprintf(&buf, "code:        %s\n", res.Code())
	if res.LicenseID() != "" {
		fmt.Fprintf(&buf, "license_id:  %s\n", res.LicenseID())
		fmt.Fprintf(&buf, "product_id:  %s\n", res.ProductID())
		fmt.Fprintf(&buf, "edition:     %s\n", res.Edition())
		fmt.Fprintf(&buf, "type:        %s\n", res.LicenseType())
		if exp := res.ExpiresAt(); exp != nil {
			fmt.Fprintf(&buf, "expires_at:  %s\n", exp.Format("2006-01-02T15:04:05Z07:00"))
		}
		if feats := res.Features(); len(feats) > 0 {
			fmt.Fprintf(&buf, "features:    %s\n", strings.Join(feats, ", "))
		}
	}
	return writeString(w, buf.String())
}
