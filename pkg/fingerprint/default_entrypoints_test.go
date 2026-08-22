package fingerprint

import (
	"errors"
	"strings"
	"testing"
)

// defaultEntryCollector is a deterministic collector whose highest-priority
// primary is a real identifier, so ComputeDefault/RequestCodeDefault resolve to
// a concrete v2 fingerprint on any platform.
func defaultEntryCollector() fakeCollector {
	return fakeCollector{
		components: []Component{
			buildComponent(CategoryMachineID, "DEFAULT-ENTRY-MID"),
			buildComponent(CategoryBoardUUID, "DEFAULT-ENTRY-BOARD"),
		},
		priority: []string{CategoryMachineID, CategoryBoardUUID},
	}
}

// TestComputeDefaultResolvesToV2 pins the contract that the version-agnostic
// default entry point produces the recommended default scheme (v2) and equals
// ComputeV2 for the same namespace, so evolving the default is a single-site
// change.
func TestComputeDefaultResolvesToV2(t *testing.T) {
	withCollector(t, defaultEntryCollector(), func() {
		def, err := ComputeDefault("myapp")
		if err != nil {
			t.Fatalf("ComputeDefault: %v", err)
		}
		if def.FingerprintVersion != DefaultFingerprintVersion {
			t.Fatalf("ComputeDefault version = %d, want %d", def.FingerprintVersion, DefaultFingerprintVersion)
		}
		if !strings.HasPrefix(def.Fingerprint, "fp:v2:sha256:") {
			t.Fatalf("ComputeDefault prefix = %q, want fp:v2:sha256:", def.Fingerprint)
		}
		v2, err := ComputeV2("myapp")
		if err != nil {
			t.Fatalf("ComputeV2: %v", err)
		}
		if def.Fingerprint != v2.Fingerprint {
			t.Fatalf("ComputeDefault %q != ComputeV2 %q", def.Fingerprint, v2.Fingerprint)
		}
	})
}

// TestComputeHMACDefaultKeyedVsPlain verifies the keyed default entry point
// tags hmac-sha256 when keyed, falls back to plain sha256 with an empty key,
// and matches ComputeHMACV2.
func TestComputeHMACDefaultKeyedVsPlain(t *testing.T) {
	withCollector(t, defaultEntryCollector(), func() {
		keyed, err := ComputeHMACDefault("myapp", []byte("k"))
		if err != nil {
			t.Fatalf("ComputeHMACDefault keyed: %v", err)
		}
		if !strings.HasPrefix(keyed.Fingerprint, "fp:v2:hmac-sha256:") {
			t.Fatalf("keyed default prefix = %q, want fp:v2:hmac-sha256:", keyed.Fingerprint)
		}

		plain, err := ComputeHMACDefault("myapp", nil)
		if err != nil {
			t.Fatalf("ComputeHMACDefault plain: %v", err)
		}
		if !strings.HasPrefix(plain.Fingerprint, "fp:v2:sha256:") {
			t.Fatalf("plain default prefix = %q, want fp:v2:sha256:", plain.Fingerprint)
		}
		if keyed.Fingerprint == plain.Fingerprint {
			t.Fatal("keyed and plain default fingerprints must differ")
		}

		ref, err := ComputeHMACV2("myapp", []byte("k"))
		if err != nil {
			t.Fatalf("ComputeHMACV2: %v", err)
		}
		if keyed.Fingerprint != ref.Fingerprint {
			t.Fatalf("ComputeHMACDefault %q != ComputeHMACV2 %q", keyed.Fingerprint, ref.Fingerprint)
		}
	})
}

func TestComputeDefaultEmptyNamespace(t *testing.T) {
	if _, err := ComputeDefault(""); !errors.Is(err, ErrEmptyNamespace) {
		t.Fatalf("ComputeDefault(\"\") = %v, want ErrEmptyNamespace", err)
	}
	if _, err := ComputeHMACDefault("", []byte("k")); !errors.Is(err, ErrEmptyNamespace) {
		t.Fatalf("ComputeHMACDefault(\"\") = %v, want ErrEmptyNamespace", err)
	}
	if _, err := RequestCodeDefault(""); !errors.Is(err, ErrEmptyNamespace) {
		t.Fatalf("RequestCodeDefault(\"\") = %v, want ErrEmptyNamespace", err)
	}
}

func TestComputeDefaultInsufficientInfo(t *testing.T) {
	withCollector(t, fakeCollector{}, func() {
		if _, err := ComputeDefault("myapp"); !errors.Is(err, ErrInsufficientInfo) {
			t.Fatalf("ComputeDefault = %v, want ErrInsufficientInfo", err)
		}
		if _, err := RequestCodeDefault("myapp"); !errors.Is(err, ErrInsufficientInfo) {
			t.Fatalf("RequestCodeDefault = %v, want ErrInsufficientInfo", err)
		}
	})
}

// TestRequestCodeDefaultMatchesFromFingerprint proves RequestCodeDefault is the
// hardware-reading counterpart of RequestCodeFromFingerprint: deriving the code
// from an already-computed default fingerprint yields the identical value
// without a second collection, and the code carries the V2 version tag.
func TestRequestCodeDefaultMatchesFromFingerprint(t *testing.T) {
	withCollector(t, defaultEntryCollector(), func() {
		code, err := RequestCodeDefault("myapp")
		if err != nil {
			t.Fatalf("RequestCodeDefault: %v", err)
		}
		if !strings.HasPrefix(code, "V2-") {
			t.Fatalf("RequestCodeDefault = %q, want a V2- prefix", code)
		}

		fp, err := ComputeDefault("myapp")
		if err != nil {
			t.Fatalf("ComputeDefault: %v", err)
		}
		derived := RequestCodeFromFingerprint(fp)
		if derived != code {
			t.Fatalf("RequestCodeFromFingerprint %q != RequestCodeDefault %q", derived, code)
		}
	})
}

// TestRequestCodeFromFingerprintVersionTag confirms the pure derivation tags a
// v1 fingerprint with a V1- prefix and a v2 fingerprint with a V2- prefix, so
// codes from different schemes stay visibly distinct.
func TestRequestCodeFromFingerprintVersionTag(t *testing.T) {
	withCollector(t, defaultEntryCollector(), func() {
		v1, err := Compute("myapp")
		if err != nil {
			t.Fatalf("Compute v1: %v", err)
		}
		if got := RequestCodeFromFingerprint(v1); !strings.HasPrefix(got, "V1-") {
			t.Fatalf("v1 code = %q, want V1- prefix", got)
		}

		v2, err := ComputeV2("myapp")
		if err != nil {
			t.Fatalf("ComputeV2: %v", err)
		}
		if got := RequestCodeFromFingerprint(v2); !strings.HasPrefix(got, "V2-") {
			t.Fatalf("v2 code = %q, want V2- prefix", got)
		}
	})
}
