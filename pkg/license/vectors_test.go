package license_test

// Consumer of the cross-implementation vectors under testdata/vectors/v2/.
//
// This runs on every `go test` (no -update needed) and is the Go side of the
// cross-implementation contract: it proves the current Go implementation still
// agrees, byte-for-byte and decision-for-decision, with the committed vectors.
// A foreign implementation (Rust/Python/Java/Node) runs the analogous loop
// against the SAME files to prove protocol compatibility.
//
// If this test fails after a code change, the change moved the frozen v2 wire
// bytes or altered a validation decision — treat it as a breaking protocol
// change, not a test to "fix".

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/soulteary/grantseal/pkg/license"
)

// loadVector reads and decodes a single vector file.
func loadVector(t *testing.T, path string) *vectorFile {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return &v
}

// vectorPubKey decodes the vector's Base64URL public key.
func vectorPubKey(t *testing.T, v *vectorFile) ed25519.PublicKey {
	t.Helper()
	b, err := b64url.DecodeString(v.PublicKey)
	if err != nil || len(b) != ed25519.PublicKeySize {
		t.Fatalf("vector %q: bad public_key: err=%v len=%d", v.Name, err, len(b))
	}
	return ed25519.PublicKey(b)
}

// TestVectorsPresent guards against an empty testdata directory (e.g. a bad
// merge that dropped the fixtures), which would otherwise let the conformance
// loop silently pass with zero assertions.
func TestVectorsPresent(t *testing.T) {
	if _, err := os.Stat(filepath.Join(vectorsDir, "vectors.json")); err != nil {
		t.Fatalf("missing vectors.json (regenerate with: go test ./pkg/license -run TestGenerateCrossImplVectors -update): %v", err)
	}
	files, err := filepath.Glob(filepath.Join(vectorsDir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	// vectors.json + at least the documented positive/negative set.
	if len(files) < 6 {
		t.Fatalf("expected the vector set to be present, found only %d json files", len(files))
	}
}

// TestManifestMatchesSeedAndKey confirms the manifest's published seed derives
// the published public key, so a foreign issuer that seeds from seed_hex gets
// the same verifying key the vectors were signed under.
func TestManifestMatchesSeedAndKey(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorsDir, "vectors.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var man vectorsManifest
	if err := json.Unmarshal(raw, &man); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	seed, err := hex.DecodeString(man.SeedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("manifest seed_hex invalid: err=%v len=%d", err, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	if got := base64.URLEncoding.EncodeToString(pub); got != man.PublicKey {
		t.Fatalf("manifest public_key does not match seed: got %s want %s", got, man.PublicKey)
	}
	if man.SchemaVersion != license.LicenseSchemaVersion {
		t.Fatalf("manifest schema_version = %d, want %d", man.SchemaVersion, license.LicenseSchemaVersion)
	}
	if man.SigningDomain != license.LicenseSigningDomain {
		t.Fatalf("manifest signing_domain mismatch")
	}
}

// TestCrossImplVectors runs the full conformance loop over every vector file:
// signature verification against the recorded public key + full policy
// validation, asserting the recorded expected outcome and stable error code.
func TestCrossImplVectors(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(vectorsDir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no vector files found")
	}

	for _, path := range files {
		if filepath.Base(path) == "vectors.json" {
			continue
		}
		v := loadVector(t, path)
		t.Run(v.Name, func(t *testing.T) {
			assertVector(t, v)
		})
	}
}

// assertVector checks one vector against the Go implementation.
func assertVector(t *testing.T, v *vectorFile) {
	t.Helper()

	// Sanity: for a valid vector, the recorded signing_input must actually be
	// domain || canonical, and the recorded signature must verify against the
	// recorded public key. This pins the exact bytes a foreign implementation
	// reproduces.
	pub := vectorPubKey(t, v)
	if v.SigningInputHex != "" && v.Canonical != "" {
		wantInput := license.LicenseSigningInput([]byte(v.Canonical))
		gotInput, err := hex.DecodeString(v.SigningInputHex)
		if err != nil {
			t.Fatalf("bad signing_input_hex: %v", err)
		}
		if string(gotInput) != string(wantInput) {
			t.Fatalf("signing_input_hex is not domain||canonical")
		}
		sig, err := b64url.DecodeString(v.Signature)
		if err != nil {
			t.Fatalf("bad signature b64: %v", err)
		}
		sigVerifies := len(sig) == ed25519.SignatureSize && ed25519.Verify(pub, wantInput, sig)
		// For a bad-signature vector the raw signature must NOT verify; for
		// every other vector (including non-canonical / duplicate-key, whose
		// bytes are re-signed) it must verify over the recorded input.
		if v.Name == "invalid-signature" {
			if sigVerifies {
				t.Fatalf("invalid-signature vector unexpectedly verifies")
			}
		} else if !sigVerifies {
			t.Fatalf("recorded signature does not verify over recorded signing_input")
		}
	}

	// Build a verifier + manager keyed on the vector's real SIGNING key
	// (always vectorKeyID), then feed the envelope through the full client
	// path exactly as a real deployment would. Negative vectors that rewrite
	// the envelope key_id to an unknown value therefore fail key lookup, as
	// intended (the ring only trusts the genuine signer).
	ring := license.NewKeyRing()
	if err := ring.AddPublicKey(vectorKeyID, pub); err != nil {
		t.Fatalf("add public key: %v", err)
	}
	// Register a second trusted key id bound to the SAME public key so the
	// invalid-keyid vector (envelope key_id swapped to vectorSubstituteKeyID)
	// still resolves a key and verifies the signature, then fails on the
	// payload<->envelope key_id binding (CodeKeyIDMismatch) rather than an
	// unknown-key lookup.
	if err := ring.AddPublicKey(vectorSubstituteKeyID, pub); err != nil {
		t.Fatalf("add substitute key: %v", err)
	}

	now, err := time.Parse(time.RFC3339, v.Validation.Now)
	if err != nil {
		t.Fatalf("bad validation.now: %v", err)
	}
	mgr := license.NewManager(ring,
		license.WithClock(license.FixedClock{T: now}),
		license.WithClockSkew(time.Duration(v.Validation.ClockSkewSeconds)*time.Second),
	)

	res, err := mgr.Validate(v.Envelope, license.ValidationContext{
		ProductID:         v.Validation.ProductID,
		DeviceFingerprint: v.Validation.DeviceFingerprint,
	})

	switch v.Expected {
	case "valid":
		if err != nil || !res.Valid() {
			t.Fatalf("expected valid, got err=%v code=%s", err, res.Code())
		}
	case "invalid":
		if err == nil && res.Valid() {
			t.Fatalf("expected invalid (%s), but validation succeeded", v.ExpectedCode)
		}
		if v.ExpectedCode != "" {
			gotCode := string(license.CodeOf(err))
			if gotCode == "" {
				gotCode = string(res.Code())
			}
			if gotCode != v.ExpectedCode {
				t.Fatalf("expected code %s, got %s (err=%v)", v.ExpectedCode, gotCode, err)
			}
		}
	default:
		t.Fatalf("unknown expected value %q", v.Expected)
	}
}
