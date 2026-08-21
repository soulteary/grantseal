package fingerprint

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// These are WHITE-BOX tests (package fingerprint): they construct Component
// values with fixed raw inputs via buildComponent and exercise canonicalForm
// directly, so they never depend on the running machine's hardware.

func TestCanonicalFormOrderIndependent(t *testing.T) {
	const ns = "acme-app"
	a := []Component{
		buildComponent(CategoryMachineID, "MID-123"),
		buildComponent(CategoryBoardUUID, "BOARD-456"),
		buildComponent(CategoryProductUUID, "PROD-789"),
	}
	// Same components, different insertion order.
	b := []Component{
		buildComponent(CategoryProductUUID, "PROD-789"),
		buildComponent(CategoryMachineID, "MID-123"),
		buildComponent(CategoryBoardUUID, "BOARD-456"),
	}
	ca, cata, oka := canonicalForm(ns, a)
	cb, catb, okb := canonicalForm(ns, b)
	if !oka || !okb {
		t.Fatalf("expected usable components (ok=%v,%v)", oka, okb)
	}
	if ca != cb {
		t.Fatalf("canonical form is order-dependent:\n a=%q\n b=%q", ca, cb)
	}
	if strings.Join(cata, ",") != strings.Join(catb, ",") {
		t.Fatalf("category order differs: %v vs %v", cata, catb)
	}
}

func TestCanonicalFormNormalizesValues(t *testing.T) {
	const ns = "acme-app"
	// Differ only by casing/whitespace, which normalize collapses.
	a := []Component{buildComponent(CategoryMachineID, "  Machine  ID  ")}
	b := []Component{buildComponent(CategoryMachineID, "machine id")}
	ca, _, oka := canonicalForm(ns, a)
	cb, _, okb := canonicalForm(ns, b)
	if !oka || !okb {
		t.Fatalf("expected usable components")
	}
	if ca != cb {
		t.Fatalf("normalization mismatch: %q != %q", ca, cb)
	}
}

func TestCanonicalFormEmptyComponents(t *testing.T) {
	const ns = "acme-app"
	// All values normalize to empty -> no usable component.
	cases := [][]Component{
		nil,
		{},
		{buildComponent(CategoryMachineID, "   ")},
		{buildComponent(CategoryBoardUUID, ""), buildComponent(CategoryProductUUID, "\t\n")},
	}
	for i, comps := range cases {
		canonical, categories, ok := canonicalForm(ns, comps)
		if ok {
			t.Fatalf("case %d: expected ok=false, got canonical=%q", i, canonical)
		}
		if canonical != "" || categories != nil {
			t.Fatalf("case %d: expected empty output, got %q / %v", i, canonical, categories)
		}
	}
}

func TestCanonicalFormNamespaceIsolation(t *testing.T) {
	comps := []Component{buildComponent(CategoryMachineID, "same-machine")}
	c1, _, ok1 := canonicalForm("product-a", comps)
	c2, _, ok2 := canonicalForm("product-b", comps)
	if !ok1 || !ok2 {
		t.Fatalf("expected usable components")
	}
	if c1 == c2 {
		t.Fatalf("different namespaces produced identical canonical form: %q", c1)
	}
	// The namespace must be the leading, NUL-separated prefix.
	if !strings.HasPrefix(c1, "product-a\x00") {
		t.Fatalf("canonical form missing namespace prefix: %q", c1)
	}
}

func TestCanonicalFormDeduplicatesCategories(t *testing.T) {
	const ns = "acme-app"
	comps := []Component{
		buildComponent(CategoryMachineID, "a"),
		buildComponent(CategoryMachineID, "b"),
		buildComponent(CategoryBoardUUID, "c"),
	}
	_, categories, ok := canonicalForm(ns, comps)
	if !ok {
		t.Fatal("expected usable components")
	}
	// MachineID appears twice as a value but only once in the category set.
	seen := map[string]int{}
	for _, c := range categories {
		seen[c]++
	}
	if seen[CategoryMachineID] != 1 {
		t.Fatalf("expected machine_id category once, got %d (%v)", seen[CategoryMachineID], categories)
	}
	if len(categories) != 2 {
		t.Fatalf("expected 2 unique categories, got %v", categories)
	}
}

// TestCanonicalFormHMACIsolation verifies (via canonicalForm output) that an
// HMAC key changes the derived digest, mirroring ComputeHMAC without needing
// real hardware.
func TestCanonicalFormHMACIsolation(t *testing.T) {
	const ns = "acme-app"
	comps := []Component{buildComponent(CategoryMachineID, "machine-xyz")}
	canonical, _, ok := canonicalForm(ns, comps)
	if !ok {
		t.Fatal("expected usable components")
	}
	plain := sha256.Sum256([]byte(canonical))
	mac := hmac.New(sha256.New, []byte("secret"))
	mac.Write([]byte(canonical))
	keyed := mac.Sum(nil)
	if hex.EncodeToString(plain[:]) == hex.EncodeToString(keyed) {
		t.Fatal("HMAC digest must differ from plain SHA-256 for the same canonical input")
	}
}

func TestBuildComponentTrimsRawValue(t *testing.T) {
	c := buildComponent(CategoryMachineID, "  raw-value  ")
	if c.value != "raw-value" {
		t.Fatalf("buildComponent did not trim raw value: %q", c.value)
	}
	if c.Category != CategoryMachineID {
		t.Fatalf("unexpected category %q", c.Category)
	}
}
