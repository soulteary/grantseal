package fingerprint

import (
	"errors"
	"strings"
	"testing"
)

// TestRequestCodeErrorArms drives the error-return arms of RequestCode and
// RequestCodeV2 using a collector that yields no usable identifiers.
func TestRequestCodeErrorArms(t *testing.T) {
	withCollector(t, fakeCollector{}, func() {
		if _, err := RequestCode("myapp"); !errors.Is(err, ErrInsufficientInfo) {
			t.Fatalf("RequestCode: want ErrInsufficientInfo, got %v", err)
		}
		if _, err := RequestCodeV2("myapp"); !errors.Is(err, ErrInsufficientInfo) {
			t.Fatalf("RequestCodeV2: want ErrInsufficientInfo, got %v", err)
		}
	})
}

// TestRequestCodeSuccessDeterministic drives the success paths deterministically
// via a fake collector so they run on any platform.
func TestRequestCodeSuccessDeterministic(t *testing.T) {
	fc := fakeCollector{
		components: []Component{buildComponent(CategoryMachineID, "MID-abc-123")},
		priority:   []string{CategoryMachineID},
	}
	withCollector(t, fc, func() {
		c1, err := RequestCode("myapp")
		if err != nil {
			t.Fatalf("RequestCode: %v", err)
		}
		if !strings.HasPrefix(c1, "V1-") {
			t.Fatalf("want V1- prefix, got %q", c1)
		}
		c2, err := RequestCodeV2("myapp")
		if err != nil {
			t.Fatalf("RequestCodeV2: %v", err)
		}
		if !strings.HasPrefix(c2, "V2-") {
			t.Fatalf("want V2- prefix, got %q", c2)
		}
	})
}

// TestPrimaryComponentUnknownCategory covers the arm where a component's
// category is not in the platform priority order (ranked last, still usable).
func TestPrimaryComponentUnknownCategory(t *testing.T) {
	comps := []Component{buildComponent(CategoryBoardUUID, "BOARD-REAL-1")}
	got, ok := primaryComponent(comps, []string{CategoryMachineID})
	if !ok {
		t.Fatal("expected the unknown-category component to still be usable")
	}
	if normalize(got.value) != "board-real-1" {
		t.Fatalf("unexpected chosen value %q", got.value)
	}
}

// TestComputeHMACV2Arms drives both the keyed and plain (empty key) branches of
// ComputeHMACV2, plus the empty-namespace error arm, deterministically.
func TestComputeHMACV2Arms(t *testing.T) {
	if _, err := ComputeHMACV2("", []byte("k")); !errors.Is(err, ErrEmptyNamespace) {
		t.Fatalf("empty namespace: want ErrEmptyNamespace, got %v", err)
	}
	fc := fakeCollector{
		components: []Component{buildComponent(CategoryMachineID, "MID-xyz")},
		priority:   []string{CategoryMachineID},
	}
	withCollector(t, fc, func() {
		keyed, err := ComputeHMACV2("myapp", []byte("secret"))
		if err != nil {
			t.Fatalf("keyed: %v", err)
		}
		if !strings.HasPrefix(keyed.Fingerprint, "hmac-sha256:") {
			t.Fatalf("want hmac-sha256: prefix, got %q", keyed.Fingerprint)
		}
		plain, err := ComputeHMACV2("myapp", nil)
		if err != nil {
			t.Fatalf("plain: %v", err)
		}
		if !strings.HasPrefix(plain.Fingerprint, "sha256:") {
			t.Fatalf("want sha256: prefix, got %q", plain.Fingerprint)
		}
	})
	// Insufficient-info arm.
	withCollector(t, fakeCollector{}, func() {
		if _, err := ComputeHMACV2("myapp", []byte("secret")); !errors.Is(err, ErrInsufficientInfo) {
			t.Fatalf("want ErrInsufficientInfo, got %v", err)
		}
	})
}
