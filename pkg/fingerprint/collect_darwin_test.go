//go:build darwin

package fingerprint

import "testing"

// TestParseIOPlatformUUID covers the parse success and the skip arms (no '=',
// no opening quote, no closing quote, and the not-found fallthrough).
func TestParseIOPlatformUUID(t *testing.T) {
	good := `  "IOPlatformUUID" = "ABCDEF12-3456-7890-ABCD-EF1234567890"`
	if got := parseIOPlatformUUID(good); got != "ABCDEF12-3456-7890-ABCD-EF1234567890" {
		t.Fatalf("parse good: got %q", got)
	}
	// Line contains the key but no '=' sign.
	if got := parseIOPlatformUUID("IOPlatformUUID no equals here"); got != "" {
		t.Fatalf("no-equals should yield empty, got %q", got)
	}
	// Has '=' but no opening quote.
	if got := parseIOPlatformUUID("IOPlatformUUID = novalue"); got != "" {
		t.Fatalf("no-open-quote should yield empty, got %q", got)
	}
	// Has '=' and opening quote but no closing quote.
	if got := parseIOPlatformUUID(`IOPlatformUUID = "unterminated`); got != "" {
		t.Fatalf("no-close-quote should yield empty, got %q", got)
	}
	// No matching line at all.
	if got := parseIOPlatformUUID("SomeOtherKey = \"x\""); got != "" {
		t.Fatalf("no-match should yield empty, got %q", got)
	}
}
