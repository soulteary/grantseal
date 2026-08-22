package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readFileBounded accepts a file at exactly the cap and rejects one over it.
func TestReadFileBoundedSizeLimit(t *testing.T) {
	dir := t.TempDir()

	atCap := filepath.Join(dir, "atcap.bin")
	if err := os.WriteFile(atCap, make([]byte, 8), 0o644); err != nil {
		t.Fatal(err)
	}
	if data, err := readFileBounded(atCap, "blob", 8); err != nil {
		t.Fatalf("file exactly at the cap should be accepted: %v", err)
	} else if len(data) != 8 {
		t.Fatalf("read %d bytes, want 8", len(data))
	}

	tooBig := filepath.Join(dir, "toobig.bin")
	if err := os.WriteFile(tooBig, make([]byte, 9), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := readFileBounded(tooBig, "blob", 8)
	if err == nil {
		t.Fatal("expected an over-cap file to be rejected")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("want too-large error, got %v", err)
	}
}

// readFileBounded surfaces a wrapped open error (with the label) for a missing
// file.
func TestReadFileBoundedMissing(t *testing.T) {
	_, err := readFileBounded(filepath.Join(t.TempDir(), "nope"), "license", 16)
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
	if !strings.Contains(err.Error(), "read license") {
		t.Fatalf("want labeled read error, got %v", err)
	}
}

// readPublicKeyFile trims surrounding whitespace/newlines from the key file.
func TestReadPublicKeyFileTrims(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k.pub")
	if err := os.WriteFile(path, []byte("  ABC123  \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readPublicKeyFile(path)
	if err != nil {
		t.Fatalf("readPublicKeyFile: %v", err)
	}
	if got != "ABC123" {
		t.Fatalf("readPublicKeyFile = %q, want trimmed ABC123", got)
	}
}
