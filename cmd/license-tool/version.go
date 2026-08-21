package main

import (
	"flag"
	"fmt"
)

// version is the CLI build version. It defaults to "dev" for local builds and
// is overridden at release time via goreleaser ldflags (-X main.version=...).
var version = "dev"

func cmdVersion(args []string) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	fmt.Printf("license-tool %s\n", version)
	return nil
}
