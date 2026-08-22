package main

import (
	"flag"
	"io"
)

// version is the CLI build version. It defaults to "dev" for local builds and
// is overridden at release time via goreleaser ldflags (-X main.version=...).
var version = "dev"

func cmdVersion(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	fprintf(stdout, "license-tool %s\n", version)
	return nil
}
