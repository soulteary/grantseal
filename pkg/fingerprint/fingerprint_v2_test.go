package fingerprint

import (
	"errors"
	"strings"
	"testing"
)

func TestIsPlaceholderValue(t *testing.T) {
	placeholders := []string{
		"",
		"none",
		"default",
		"default string",
		"to be filled by o.e.m.",
		"system serial number",
		"unknown",
		"0",
		"00000000-0000-0000-0000-000000000000",
		"ffffffff-ffff-ffff-ffff-ffffffffffff",
		"0-0-0-0",
	}
	for _, p := range placeholders {
		if !isPlaceholderValue(p) {
			t.Errorf("expected %q to be a placeholder", p)
		}
	}
	real := []string{
		"7b3f0c1e-1234-5678-9abc-def012345678",
		"a1b2c3d4",
		"machine-xyz",
	}
	for _, r := range real {
		if isPlaceholderValue(r) {
			t.Errorf("expected %q to be a real value", r)
		}
	}
}

func TestPrimaryComponentSkipsPlaceholders(t *testing.T) {
	// machine_id is a placeholder, board_uuid is real. The primary must be the
	// real one even though machine_id would normally outrank it, because the
	// placeholder is filtered before ranking.
	comps := []Component{
		buildComponent(CategoryMachineID, "00000000-0000-0000-0000-000000000000"),
		buildComponent(CategoryBoardUUID, "REAL-BOARD-123"),
	}
	got, ok := primaryComponent(comps, []string{CategoryMachineID, CategoryProductUUID, CategoryBoardUUID})
	if !ok {
		t.Fatal("expected a usable primary component")
	}
	if normalize(got.value) != "real-board-123" {
		t.Fatalf("expected board value, got %q (%s)", got.value, got.Category)
	}
}

func TestPrimaryComponentAllPlaceholders(t *testing.T) {
	comps := []Component{
		buildComponent(CategoryMachineID, "none"),
		buildComponent(CategoryBoardUUID, "   "),
	}
	if _, ok := primaryComponent(comps, []string{CategoryMachineID, CategoryBoardUUID}); ok {
		t.Fatal("expected no usable primary component when all are placeholders")
	}
}

// fakeCollector is a deterministic Collector for tests: it separates collection
// from normalization/hashing so fingerprint output can be exercised on any
// platform without touching real hardware.
type fakeCollector struct {
	components []Component
	priority   []string
}

func (f fakeCollector) Collect() []Component      { return f.components }
func (f fakeCollector) PrimaryPriority() []string { return f.priority }

// withCollector swaps the package default collector for the duration of fn.
func withCollector(t *testing.T, c Collector, fn func()) {
	t.Helper()
	prev := defaultCollector
	defaultCollector = c
	defer func() { defaultCollector = prev }()
	fn()
}

// TestCollectorAbstractionDrivesCompute verifies that Compute/ComputeV2 read
// their raw identifiers through the Collector abstraction and that the v1/v2
// hashing/normalization is unchanged: v1 folds in all components, v2 selects the
// single highest-priority primary identifier.
func TestCollectorAbstractionDrivesCompute(t *testing.T) {
	fc := fakeCollector{
		components: []Component{
			buildComponent(CategoryMachineID, "MID-123"),
			buildComponent(CategoryBoardUUID, "BOARD-999"),
		},
		priority: []string{CategoryMachineID, CategoryBoardUUID},
	}
	withCollector(t, fc, func() {
		v1, err := Compute("myapp")
		if err != nil {
			t.Fatalf("v1 compute: %v", err)
		}
		if len(v1.ComponentsUsed) != 2 {
			t.Fatalf("v1 should fold in all components, got %v", v1.ComponentsUsed)
		}
		if !strings.HasPrefix(v1.Fingerprint, "sha256:") {
			t.Fatalf("v1 prefix, got %q", v1.Fingerprint)
		}

		v2, err := ComputeV2("myapp")
		if err != nil {
			t.Fatalf("v2 compute: %v", err)
		}
		// v2 selects a single primary (machine_id outranks board_uuid).
		if len(v2.ComponentsUsed) != 1 || v2.ComponentsUsed[0] != CategoryMachineID {
			t.Fatalf("v2 should select the machine_id primary, got %v", v2.ComponentsUsed)
		}
	})
}

// TestCollectorInsufficientInfoFailsClosed verifies a Collector that returns no
// usable identifiers surfaces ErrInsufficientInfo rather than a fabricated
// fingerprint.
func TestCollectorInsufficientInfoFailsClosed(t *testing.T) {
	withCollector(t, fakeCollector{}, func() {
		if _, err := Compute("myapp"); !errors.Is(err, ErrInsufficientInfo) {
			t.Fatalf("empty collector must fail closed, got %v", err)
		}
		if _, err := ComputeV2("myapp"); !errors.Is(err, ErrInsufficientInfo) {
			t.Fatalf("empty collector must fail closed for v2, got %v", err)
		}
	})
}

func TestComputeV2EmptyNamespace(t *testing.T) {
	if _, err := ComputeV2(""); !errors.Is(err, ErrEmptyNamespace) {
		t.Fatalf("expected ErrEmptyNamespace, got %v", err)
	}
}

func TestComputeV2Deterministic(t *testing.T) {
	fp1, err := ComputeV2("myapp")
	if err != nil {
		if errors.Is(err, ErrInsufficientInfo) {
			t.Skip("no hardware identifiers available; skipping")
		}
		t.Fatalf("unexpected error: %v", err)
	}
	fp2, err := ComputeV2("myapp")
	if err != nil {
		t.Fatalf("second ComputeV2 failed: %v", err)
	}
	if fp1.Fingerprint != fp2.Fingerprint {
		t.Fatalf("v2 fingerprints not deterministic: %q != %q", fp1.Fingerprint, fp2.Fingerprint)
	}
	if fp1.FingerprintVersion != FingerprintVersionV2 {
		t.Fatalf("expected v2 version tag, got %d", fp1.FingerprintVersion)
	}
	if !strings.HasPrefix(fp1.Fingerprint, "sha256:") {
		t.Fatalf("expected sha256: prefix on plain v2 fingerprint, got %q", fp1.Fingerprint)
	}
}

func TestComputeHMACV2Prefix(t *testing.T) {
	keyed, err := ComputeHMACV2("myapp", []byte("super-secret-key"))
	if err != nil {
		if errors.Is(err, ErrInsufficientInfo) {
			t.Skip("no hardware identifiers available; skipping")
		}
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(keyed.Fingerprint, "hmac-sha256:") {
		t.Fatalf("expected hmac-sha256: prefix on keyed v2 fingerprint, got %q", keyed.Fingerprint)
	}
}

func TestRequestCodeVersionTagged(t *testing.T) {
	code, err := RequestCode("myapp")
	if err != nil {
		if errors.Is(err, ErrInsufficientInfo) {
			t.Skip("no hardware identifiers available; skipping")
		}
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(code, "V1-") {
		t.Fatalf("expected v1 request code to start with V1-, got %q", code)
	}

	code2, err := RequestCodeV2("myapp")
	if err != nil {
		if errors.Is(err, ErrInsufficientInfo) {
			t.Skip("no hardware identifiers available; skipping")
		}
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(code2, "V2-") {
		t.Fatalf("expected v2 request code to start with V2-, got %q", code2)
	}
}
