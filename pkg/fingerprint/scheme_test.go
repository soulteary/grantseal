package fingerprint

import (
	"errors"
	"strings"
	"testing"
)

// goldenCollector returns a deterministic collector whose two components and
// priority order produce stable golden digests. v1 folds in both components
// (sorted by category then value), while v2 selects machine_id as the primary.
func goldenCollector() fakeCollector {
	return fakeCollector{
		components: []Component{
			buildComponent(CategoryMachineID, "MID-1"),
			buildComponent(CategoryBoardUUID, "BOARD-2"),
		},
		priority: []string{CategoryMachineID, CategoryBoardUUID},
	}
}

const goldenNamespace = "goldenapp"

var goldenKey = []byte("golden-key")

// Golden digests computed over the canonical forms produced by goldenCollector
// for productNamespace "goldenapp" and key "golden-key". These are exact,
// fixed vectors so any change to the hashing/normalization or the algorithm
// tag selection is caught precisely.
const (
	goldenV1PlainDigest = "7abef23db156aa47bde50707983a08150f3219b171d8b07b9433592ed1bf0287"
	goldenV1KeyedDigest = "bb3c8d3c0ba4c253ebcab70e5a7f5d2314670752b990b1b727fe49d599816102"
	goldenV2PlainDigest = "8b44ae447840d2b8f14ef65d27276293237a396b5ba07508e7e6dcf65c51ddaa"
	goldenV2KeyedDigest = "bd6a000661f89b51053030b293378c3401b4efc258f120e12dcf730be7b3a5ae"
)

// TestFingerprintAlgorithmTags pins the exact algorithm tag and digest emitted
// by all four fingerprint computations (v1/v2 x plain/keyed). In particular it
// guards the P1-1 fix: keyed v1 must emit "fp:v1:hmac-sha256:" (not
// "fp:v1:sha256:").
func TestFingerprintAlgorithmTags(t *testing.T) {
	cases := []struct {
		name    string
		compute func() (Fingerprint, error)
		want    string
		wantVer int
	}{
		{
			name:    "v1 plain",
			compute: func() (Fingerprint, error) { return ComputeHMAC(goldenNamespace, nil) },
			want:    "fp:v1:sha256:" + goldenV1PlainDigest,
			wantVer: FingerprintVersion,
		},
		{
			name:    "v1 keyed",
			compute: func() (Fingerprint, error) { return ComputeHMAC(goldenNamespace, goldenKey) },
			want:    "fp:v1:hmac-sha256:" + goldenV1KeyedDigest,
			wantVer: FingerprintVersion,
		},
		{
			name:    "v2 plain",
			compute: func() (Fingerprint, error) { return ComputeHMACV2(goldenNamespace, nil) },
			want:    "fp:v2:sha256:" + goldenV2PlainDigest,
			wantVer: FingerprintVersionV2,
		},
		{
			name:    "v2 keyed",
			compute: func() (Fingerprint, error) { return ComputeHMACV2(goldenNamespace, goldenKey) },
			want:    "fp:v2:hmac-sha256:" + goldenV2KeyedDigest,
			wantVer: FingerprintVersionV2,
		},
	}

	withCollector(t, goldenCollector(), func() {
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				fp, err := tc.compute()
				if err != nil {
					t.Fatalf("compute failed: %v", err)
				}
				if fp.Fingerprint != tc.want {
					t.Fatalf("fingerprint = %q, want %q", fp.Fingerprint, tc.want)
				}
				if fp.FingerprintVersion != tc.wantVer {
					t.Fatalf("version = %d, want %d", fp.FingerprintVersion, tc.wantVer)
				}
			})
		}
	})
}

func TestParseValidVersioned(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  Scheme
	}{
		{
			name:  "v1 plain",
			value: "fp:v1:sha256:" + goldenV1PlainDigest,
			want:  Scheme{Version: 1, Algorithm: "sha256", Digest: goldenV1PlainDigest},
		},
		{
			name:  "v1 keyed",
			value: "fp:v1:hmac-sha256:" + goldenV1KeyedDigest,
			want:  Scheme{Version: 1, Algorithm: "hmac-sha256", Digest: goldenV1KeyedDigest},
		},
		{
			name:  "v2 plain",
			value: "fp:v2:sha256:" + goldenV2PlainDigest,
			want:  Scheme{Version: 2, Algorithm: "sha256", Digest: goldenV2PlainDigest},
		},
		{
			name:  "v2 keyed",
			value: "fp:v2:hmac-sha256:" + goldenV2KeyedDigest,
			want:  Scheme{Version: 2, Algorithm: "hmac-sha256", Digest: goldenV2KeyedDigest},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.value)
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", tc.value, err)
			}
			if got != tc.want {
				t.Fatalf("Parse(%q) = %+v, want %+v", tc.value, got, tc.want)
			}
			if got.IsOpaque() {
				t.Fatalf("versioned scheme reported IsOpaque")
			}
		})
	}
}

func TestParseOpaque(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		wantNS  string
		wantVal string
	}{
		{
			name:    "simple",
			value:   "opaque:acme:device-42",
			wantNS:  "acme",
			wantVal: "device-42",
		},
		{
			name:    "value with extra colons preserved",
			value:   "opaque:acme:a:b:c",
			wantNS:  "acme",
			wantVal: "a:b:c",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.value)
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", tc.value, err)
			}
			if !got.IsOpaque() {
				t.Fatalf("Parse(%q) not reported as opaque: %+v", tc.value, got)
			}
			if got.Version != OpaqueVersion || got.Algorithm != OpaqueAlgorithm {
				t.Fatalf("Parse(%q) = %+v, want opaque marker", tc.value, got)
			}
			if got.Namespace != tc.wantNS {
				t.Fatalf("Parse(%q) namespace = %q, want %q", tc.value, got.Namespace, tc.wantNS)
			}
			if got.Digest != tc.wantVal {
				t.Fatalf("Parse(%q) value = %q, want %q", tc.value, got.Digest, tc.wantVal)
			}
		})
	}
}

func TestParseRejections(t *testing.T) {
	validDigest := goldenV1PlainDigest
	cases := []struct {
		name    string
		value   string
		wantErr error
	}{
		{"empty", "", ErrMalformedScheme},
		{"bare hex", validDigest, ErrMalformedScheme},
		{"legacy sha256 no version", "sha256:" + validDigest, ErrMalformedScheme},
		{"missing version number", "fp:v:sha256:" + validDigest, ErrMalformedScheme},
		{"non-numeric version", "fp:vx:sha256:" + validDigest, ErrMalformedScheme},
		{"no colon after fp:v", "fp:v1", ErrMalformedScheme},
		{"version zero", "fp:v0:sha256:" + validDigest, ErrMalformedScheme},
		{"unknown version", "fp:v3:sha256:" + validDigest, ErrUnknownVersion},
		{"unknown algorithm", "fp:v1:md5:" + validDigest, ErrUnknownAlgorithm},
		{"missing algorithm/digest separator", "fp:v1:sha256", ErrMalformedScheme},
		{"empty digest", "fp:v1:sha256:", ErrEmptyDigest},
		{"non-hex digest", "fp:v1:sha256:" + strings.Repeat("z", 64), ErrInvalidDigest},
		{"uppercase hex digest", "fp:v1:sha256:" + strings.ToUpper(validDigest), ErrInvalidDigest},
		{"digest too short", "fp:v1:sha256:abc123", ErrInvalidDigest},
		{"digest too long", "fp:v1:sha256:" + validDigest + "ab", ErrInvalidDigest},
		{"opaque missing value", "opaque:acme", ErrMalformedScheme},
		{"opaque empty value", "opaque:acme:", ErrMalformedScheme},
		{"opaque empty namespace", "opaque::device", ErrMalformedScheme},
		{"opaque only prefix", "opaque:", ErrMalformedScheme},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.value)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Parse(%q) error = %v, want %v", tc.value, err, tc.wantErr)
			}
		})
	}
}

// TestComputeVersionDispatch verifies ComputeVersion/ComputeHMACVersion
// dispatch to the correct scheme (matching the golden vectors) and fail closed
// on an unknown version.
func TestComputeVersionDispatch(t *testing.T) {
	withCollector(t, goldenCollector(), func() {
		cases := []struct {
			name    string
			compute func() (Fingerprint, error)
			want    string
		}{
			{
				name:    "v1 plain",
				compute: func() (Fingerprint, error) { return ComputeVersion(goldenNamespace, FingerprintVersion) },
				want:    "fp:v1:sha256:" + goldenV1PlainDigest,
			},
			{
				name:    "v1 keyed",
				compute: func() (Fingerprint, error) { return ComputeHMACVersion(goldenNamespace, FingerprintVersion, goldenKey) },
				want:    "fp:v1:hmac-sha256:" + goldenV1KeyedDigest,
			},
			{
				name:    "v2 plain",
				compute: func() (Fingerprint, error) { return ComputeVersion(goldenNamespace, FingerprintVersionV2) },
				want:    "fp:v2:sha256:" + goldenV2PlainDigest,
			},
			{
				name: "v2 keyed",
				compute: func() (Fingerprint, error) {
					return ComputeHMACVersion(goldenNamespace, FingerprintVersionV2, goldenKey)
				},
				want: "fp:v2:hmac-sha256:" + goldenV2KeyedDigest,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				fp, err := tc.compute()
				if err != nil {
					t.Fatalf("compute failed: %v", err)
				}
				if fp.Fingerprint != tc.want {
					t.Fatalf("fingerprint = %q, want %q", fp.Fingerprint, tc.want)
				}
			})
		}
	})
}

func TestComputeVersionUnknownFailsClosed(t *testing.T) {
	withCollector(t, goldenCollector(), func() {
		if _, err := ComputeVersion(goldenNamespace, 3); !errors.Is(err, ErrUnknownVersion) {
			t.Fatalf("ComputeVersion unknown version error = %v, want ErrUnknownVersion", err)
		}
		if _, err := ComputeHMACVersion(goldenNamespace, 0, goldenKey); !errors.Is(err, ErrUnknownVersion) {
			t.Fatalf("ComputeHMACVersion unknown version error = %v, want ErrUnknownVersion", err)
		}
	})
}

func TestComputeVersionEmptyNamespace(t *testing.T) {
	withCollector(t, goldenCollector(), func() {
		if _, err := ComputeVersion("", FingerprintVersion); !errors.Is(err, ErrEmptyNamespace) {
			t.Fatalf("expected ErrEmptyNamespace, got %v", err)
		}
	})
}

// TestComputeVersionRoundTripsThroughParse checks that a freshly computed
// versioned fingerprint parses back into a matching Scheme, confirming the
// producer and parser agree on format.
func TestComputeVersionRoundTripsThroughParse(t *testing.T) {
	withCollector(t, goldenCollector(), func() {
		for _, v := range []int{FingerprintVersion, FingerprintVersionV2} {
			fp, err := ComputeVersion(goldenNamespace, v)
			if err != nil {
				t.Fatalf("ComputeVersion v%d: %v", v, err)
			}
			s, err := Parse(fp.Fingerprint)
			if err != nil {
				t.Fatalf("Parse(%q): %v", fp.Fingerprint, err)
			}
			if s.Version != v || s.Algorithm != "sha256" {
				t.Fatalf("round trip v%d: got %+v", v, s)
			}
		}
	})
}
