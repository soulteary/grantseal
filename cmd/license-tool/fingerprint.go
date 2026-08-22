package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/soulteary/grantseal/pkg/fingerprint"
)

func cmdFingerprint(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("fingerprint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ns := fs.String("namespace", "", "product namespace (required)")
	jsonOut := fs.Bool("json", false, "print full fingerprint JSON")
	code := fs.Bool("request-code", false, "print the human-friendly request code")
	useV2 := fs.Bool("v2", false, "use the v2 per-platform primary-identifier scheme")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *ns == "" {
		return usageErrorf("fingerprint: -namespace is required")
	}
	compute := fingerprint.Compute
	requestCode := fingerprint.RequestCode
	if *useV2 {
		compute = fingerprint.ComputeV2
		requestCode = fingerprint.RequestCodeV2
	}
	fp, err := compute(*ns)
	if err != nil {
		if errors.Is(err, fingerprint.ErrInsufficientInfo) {
			return fmt.Errorf("fingerprint: insufficient hardware info on this platform")
		}
		return err
	}
	if *code {
		rc, cerr := requestCode(*ns)
		if cerr != nil {
			return cerr
		}
		fmt.Fprintln(stdout, rc)
		return nil
	}
	if *jsonOut {
		b, merr := json.MarshalIndent(fp, "", "  ")
		if merr != nil {
			return merr
		}
		fmt.Fprintln(stdout, string(b))
		return nil
	}
	fmt.Fprintln(stdout, fp.Fingerprint)
	return nil
}
