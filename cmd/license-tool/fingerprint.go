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
	useV1 := fs.Bool("v1", false, "use the legacy v1 all-components scheme (default is the drift-resistant v2 scheme)")
	useV2 := fs.Bool("v2", false, "deprecated no-op: v2 is now the default (kept for backward compatibility)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *ns == "" {
		return usageErrorf("fingerprint: -namespace is required")
	}
	if *useV1 && *useV2 {
		return usageErrorf("fingerprint: -v1 and -v2 are mutually exclusive")
	}
	// Default to the drift-resistant v2 scheme; -v1 opts back into the legacy
	// all-components scheme. -v2 is retained as a no-op for compatibility.
	compute := fingerprint.ComputeDefault
	if *useV1 {
		compute = fingerprint.Compute
	}
	// Collect hardware EXACTLY ONCE. Every output mode (request-code, JSON, and
	// the plain fingerprint) is derived from this single Fingerprint so the
	// hardware is never read twice for one invocation.
	fp, err := compute(*ns)
	if err != nil {
		if errors.Is(err, fingerprint.ErrInsufficientInfo) {
			return fmt.Errorf("fingerprint: insufficient hardware info on this platform")
		}
		return err
	}
	if *code {
		return writeLine(stdout, fingerprint.RequestCodeFromFingerprint(fp))
	}
	if *jsonOut {
		b, merr := json.MarshalIndent(fp, "", "  ")
		if merr != nil {
			return merr
		}
		return writeLine(stdout, string(b))
	}
	return writeLine(stdout, fp.Fingerprint)
}
