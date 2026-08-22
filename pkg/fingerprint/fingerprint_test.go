package fingerprint

import (
	"errors"
	"testing"
)

// knownCategories is the set of category names that may legitimately appear in
// ComponentsUsed.
var knownCategories = map[string]struct{}{
	CategoryMachineID:    {},
	CategoryBoardUUID:    {},
	CategoryPlatformUUID: {},
	CategoryMachineGUID:  {},
	CategoryProductUUID:  {},
}

func TestComputeEmptyNamespace(t *testing.T) {
	_, err := Compute("")
	if !errors.Is(err, ErrEmptyNamespace) {
		t.Fatalf("expected ErrEmptyNamespace, got %v", err)
	}
}

func TestComputeDeterministic(t *testing.T) {
	fp1, err := Compute("myapp")
	if err != nil {
		if errors.Is(err, ErrInsufficientInfo) {
			t.Skip("no hardware identifiers available; skipping")
		}
		t.Fatalf("unexpected error: %v", err)
	}

	fp2, err := Compute("myapp")
	if err != nil {
		t.Fatalf("second Compute failed: %v", err)
	}

	if fp1.Fingerprint != fp2.Fingerprint {
		t.Fatalf("fingerprints not deterministic: %q != %q", fp1.Fingerprint, fp2.Fingerprint)
	}
	if len(fp1.Fingerprint) < len("sha256:") || fp1.Fingerprint[:len("sha256:")] != "sha256:" {
		t.Fatalf("fingerprint missing sha256: prefix: %q", fp1.Fingerprint)
	}
	if fp1.FingerprintVersion != FingerprintVersion {
		t.Fatalf("unexpected version: %d", fp1.FingerprintVersion)
	}
}

func TestComputeHMACDiffersFromPlain(t *testing.T) {
	plain, err := Compute("myapp")
	if err != nil {
		if errors.Is(err, ErrInsufficientInfo) {
			t.Skip("no hardware identifiers available; skipping")
		}
		t.Fatalf("unexpected error: %v", err)
	}

	keyed, err := ComputeHMAC("myapp", []byte("super-secret-key"))
	if err != nil {
		t.Fatalf("ComputeHMAC failed: %v", err)
	}

	if plain.Fingerprint == keyed.Fingerprint {
		t.Fatalf("HMAC fingerprint should differ from plain SHA-256")
	}
}

func TestNormalize(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"   ", ""},
		{"ABC", "abc"},
		{"  Hello  ", "hello"},
		{"A\tB\nC", "a b c"},
		{"Multiple   Spaces", "multiple spaces"},
		{"MixED   CaSe\tValue", "mixed case value"},
	}
	for _, tc := range cases {
		if got := normalize(tc.in); got != tc.want {
			t.Errorf("normalize(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRequestCodeFormat(t *testing.T) {
	code, err := RequestCode("myapp")
	if err != nil {
		if errors.Is(err, ErrInsufficientInfo) {
			t.Skip("no hardware identifiers available; skipping")
		}
		t.Fatalf("unexpected error: %v", err)
	}

	if !containsDash(code) {
		t.Fatalf("expected grouped code containing '-', got %q", code)
	}
	for _, r := range code {
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
			t.Fatalf("code contains invalid character %q in %q", r, code)
		}
	}
}

func TestComponentsUsedNoRawValues(t *testing.T) {
	fp, err := Compute("myapp")
	if err != nil {
		if errors.Is(err, ErrInsufficientInfo) {
			t.Skip("no hardware identifiers available; skipping")
		}
		t.Fatalf("unexpected error: %v", err)
	}

	for _, cat := range fp.ComponentsUsed {
		if _, ok := knownCategories[cat]; !ok {
			t.Fatalf("ComponentsUsed contains unknown/raw entry %q", cat)
		}
	}
}

func containsDash(s string) bool {
	for _, r := range s {
		if r == '-' {
			return true
		}
	}
	return false
}
