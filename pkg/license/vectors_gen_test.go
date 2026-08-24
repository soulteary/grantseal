package license_test

// Cross-implementation test vector generator.
//
// This file GENERATES the language-agnostic protocol conformance vectors under
// testdata/vectors/v2/. The vectors are NOT for Go's own benefit: they exist so
// that a Rust / Python / Java / Node (or any other) implementation of the
// grantseal v2 wire protocol can prove byte-for-byte + signature compatibility
// without linking any Go code.
//
// Determinism is the whole point. Every vector is derived from a single, fixed
// 32-byte Ed25519 seed (VectorSeedHex below). Any implementation that seeds an
// Ed25519 key from those exact bytes will reproduce the identical public key,
// canonical bytes, signing input, and signature recorded in the vectors. A
// verifier-only implementation can ignore the seed and simply check the
// recorded signature against the recorded public key.
//
// The generator is gated behind `-update` so ordinary `go test` runs never
// rewrite the committed fixtures; vectors_test.go consumes them on every run
// and fails if the Go implementation drifts from the recorded bytes.
//
//	regenerate: go test ./pkg/license -run TestGenerateCrossImplVectors -update
//
// If a regeneration changes any committed vector, that is a WIRE-VISIBLE change
// to the frozen v2 protocol (see docs/enUS/protocol-v2.md) and must be reviewed
// as a breaking change, not rubber-stamped.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/soulteary/grantseal/pkg/license"
)

// updateVectors, when set via `-update`, rewrites the committed vector files
// from the current Go implementation instead of only consuming them.
var updateVectors = flag.Bool("update", false, "regenerate cross-implementation test vectors under testdata/vectors/v2")

// VectorSeedHex is the FIXED 32-byte Ed25519 seed every vector is derived from.
// It is published in vectors.json so other-language issuers can reproduce the
// exact same signatures. It is a throwaway test key and MUST NEVER be used to
// sign real licenses.
const VectorSeedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

// vectorKeyID is the key_id embedded in every generated vector.
const vectorKeyID = "vector-key-1"

// vectorSubstituteKeyID is a second key id the verifier's ring also trusts
// (bound to the SAME public key as vectorKeyID). The invalid-keyid vector
// swaps the envelope key_id to this value so the signature still verifies but
// the payload's embedded key_id no longer matches the envelope, exercising the
// payload<->envelope binding rejection (CodeKeyIDMismatch).
const vectorSubstituteKeyID = "vector-key-2"

// vectorsDir is the on-disk location of the generated fixtures, relative to the
// pkg/license package directory.
var vectorsDir = filepath.Join("testdata", "vectors", "v2")

// The wire encoding (URL alphabet, padded) is provided by the package-level
// b64url var declared in envelope_strictjson_test.go.

// vectorFile is one cross-implementation vector as serialized to its own
// <name>.json file and embedded in the vectors.json manifest.
//
// The field set is deliberately self-contained so a foreign implementation
// needs nothing but this JSON: it carries the full envelope, the decoded
// canonical payload string, the exact signing input (hex), the signature, the
// verifying public key, and the expected outcome + stable error code.
type vectorFile struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	SchemaVersion int    `json:"schema_version"`
	// SigningDomain is the domain-separation prefix (with its trailing NUL
	// rendered as \u0000 in JSON) prepended to the canonical bytes before
	// signing/verification.
	SigningDomain string `json:"signing_domain"`
	KeyID         string `json:"key_id"`
	// PublicKey is Base64URL(32-byte Ed25519 public key) — what a verifier
	// loads into its key ring.
	PublicKey string `json:"public_key"`
	// Canonical is the exact canonical JSON payload string that gets signed
	// (present for vectors that have a well-formed decodable payload).
	Canonical string `json:"canonical,omitempty"`
	// SigningInputHex is hex(signing_domain_bytes || canonical_bytes) — the
	// exact byte sequence passed to Ed25519.Verify. Provided so a foreign
	// implementation can compare its own concatenation byte-for-byte.
	SigningInputHex string `json:"signing_input_hex,omitempty"`
	// Signature is Base64URL(64-byte Ed25519 signature) as carried in the
	// envelope. For tampered-signature vectors it is the corrupted value.
	Signature string `json:"signature,omitempty"`
	// Envelope is the complete on-the-wire license envelope object a verifier
	// receives. It is the primary input a foreign verifier should feed to its
	// parser.
	Envelope json.RawMessage `json:"envelope"`
	// Validation carries the policy-layer inputs a full validator needs.
	Validation vectorValidation `json:"validation"`
	// Expected is "valid" or "invalid".
	Expected string `json:"expected"`
	// ExpectedCode is the stable license error code an invalid vector must
	// produce (empty for valid vectors). These strings are the public contract
	// (pkg/license/errors.go) and every implementation must map to them.
	ExpectedCode string `json:"expected_code,omitempty"`
	// Layer indicates where a foreign implementation should expect the outcome
	// to be decided: "verify" (signature/key layer), "parse" (envelope/JSON
	// structural layer), or "validate" (policy layer). Purely informational.
	Layer string `json:"layer"`
}

// vectorValidation holds the policy-layer inputs required to reproduce a
// validation decision deterministically (no wall-clock dependence).
type vectorValidation struct {
	// ProductID scopes validation; grantseal fails closed without it.
	ProductID string `json:"product_id"`
	// DeviceFingerprint is the current device identity supplied to the
	// validator; required (and matched) for device-bound licenses, empty
	// otherwise.
	DeviceFingerprint string `json:"device_fingerprint,omitempty"`
	// Now is the RFC3339 UTC instant the validator should treat as "now" so
	// time-based checks (expiry, not-before) are reproducible.
	Now string `json:"now"`
	// ClockSkewSeconds is the tolerated skew in seconds.
	ClockSkewSeconds int `json:"clock_skew_seconds"`
}

// vectorsManifest is the top-level vectors.json: metadata + every vector inline
// so a foreign test runner can consume a single file if it prefers.
type vectorsManifest struct {
	Protocol      string `json:"protocol"`
	SchemaVersion int    `json:"schema_version"`
	Description   string `json:"description"`
	SeedHex       string `json:"seed_hex"`
	KeyID         string `json:"key_id"`
	PublicKey     string `json:"public_key"`
	SigningDomain string `json:"signing_domain"`
	// TrustedKeyIDs lists every key_id a conforming verifier must register in
	// its key ring (all bound to the SAME public key above) to reproduce the
	// recorded decisions. The invalid-keyid vector relies on the substitute id
	// being trusted so its failure is a payload<->envelope binding mismatch
	// rather than an unknown-key lookup.
	TrustedKeyIDs []string          `json:"trusted_key_ids"`
	Files         []string          `json:"files"`
	Vectors       []json.RawMessage `json:"vectors"`
}

// fixedIssuedAt is the single issuance instant reused across vectors so the
// signed bytes are stable.
var fixedIssuedAt = time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)

// vectorSpec describes how to build one vector before it is signed/mutated.
type vectorSpec struct {
	name        string
	description string
	payload     *license.Payload
	validation  vectorValidation
	// mutate optionally rewrites the freshly built, correctly-signed vector to
	// produce a negative case (bad signature, wrong key_id, non-canonical
	// bytes, duplicate keys, ...). It receives the signer's private key so it
	// can re-sign mutated bytes where needed.
	mutate func(t *testing.T, v *vectorFile, priv ed25519.PrivateKey)
	// expected/expectedCode/layer default to a valid outcome unless mutate (or
	// the spec) overrides them.
	expected     string
	expectedCode string
	layer        string
}

// TestGenerateCrossImplVectors builds every vector from the fixed seed and,
// under -update, writes them to testdata/vectors/v2/. Without -update it is a
// no-op generator (the consuming assertions live in vectors_test.go), so a
// normal `go test` never rewrites committed fixtures.
func TestGenerateCrossImplVectors(t *testing.T) {
	if !*updateVectors {
		t.Skip("generator only runs with -update; vectors_test.go consumes the committed fixtures")
	}

	seed, err := hex.DecodeString(VectorSeedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("bad VectorSeedHex: err=%v len=%d", err, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	pubB64 := b64url.EncodeToString(pub)

	specs := vectorSpecs()

	if err := os.MkdirAll(vectorsDir, 0o755); err != nil {
		t.Fatalf("mkdir vectors dir: %v", err)
	}

	manifest := vectorsManifest{
		Protocol:      "grantseal",
		SchemaVersion: license.LicenseSchemaVersion,
		Description:   "Cross-implementation conformance vectors for the grantseal v2 license wire protocol. Derived from a fixed Ed25519 seed so any implementation can reproduce identical signatures. See README.md.",
		SeedHex:       VectorSeedHex,
		KeyID:         vectorKeyID,
		PublicKey:     pubB64,
		SigningDomain: license.LicenseSigningDomain,
		TrustedKeyIDs: []string{vectorKeyID, vectorSubstituteKeyID},
	}

	for _, spec := range specs {
		v := buildVector(t, spec, priv, pub, pubB64)
		fileName := spec.name + ".json"
		raw, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatalf("marshal vector %q: %v", spec.name, err)
		}
		raw = append(raw, '\n')
		if err := os.WriteFile(filepath.Join(vectorsDir, fileName), raw, 0o644); err != nil {
			t.Fatalf("write vector %q: %v", spec.name, err)
		}
		manifest.Files = append(manifest.Files, fileName)
		// Re-marshal compactly for the inline manifest copy.
		compact, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("compact vector %q: %v", spec.name, err)
		}
		manifest.Vectors = append(manifest.Vectors, compact)
	}

	manRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	manRaw = append(manRaw, '\n')
	if err := os.WriteFile(filepath.Join(vectorsDir, "vectors.json"), manRaw, 0o644); err != nil {
		t.Fatalf("write vectors.json: %v", err)
	}
	t.Logf("wrote %d vectors + manifest to %s", len(specs), vectorsDir)
}

// buildVector produces a fully-signed vector from a spec, then applies any
// mutation to derive a negative case.
func buildVector(t *testing.T, spec vectorSpec, priv ed25519.PrivateKey, pub ed25519.PublicKey, pubB64 string) *vectorFile {
	t.Helper()

	// Every vector's payload carries the vector key_id and schema version.
	spec.payload.KeyID = vectorKeyID
	if spec.payload.SchemaVersion == 0 {
		spec.payload.SchemaVersion = license.LicenseSchemaVersion
	}

	canonical, err := license.CanonicalBytes(spec.payload)
	if err != nil {
		t.Fatalf("vector %q: canonical: %v", spec.name, err)
	}
	signingInput := license.LicenseSigningInput(canonical)
	sig := ed25519.Sign(priv, signingInput)
	env := license.NewEnvelope(license.AlgorithmEd25519, vectorKeyID, canonical, sig)
	envJSON, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("vector %q: marshal envelope: %v", spec.name, err)
	}

	expected := spec.expected
	if expected == "" {
		expected = "valid"
	}
	layer := spec.layer
	if layer == "" {
		layer = "validate"
	}

	v := &vectorFile{
		Name:            spec.name,
		Description:     spec.description,
		SchemaVersion:   license.LicenseSchemaVersion,
		SigningDomain:   license.LicenseSigningDomain,
		KeyID:           vectorKeyID,
		PublicKey:       pubB64,
		Canonical:       string(canonical),
		SigningInputHex: hex.EncodeToString(signingInput),
		Signature:       b64url.EncodeToString(sig),
		Envelope:        json.RawMessage(envJSON),
		Validation:      spec.validation,
		Expected:        expected,
		ExpectedCode:    spec.expectedCode,
		Layer:           layer,
	}

	if spec.mutate != nil {
		spec.mutate(t, v, priv)
	}
	return v
}

// vectorSpecs returns the full matrix of positive and negative vectors. Times
// are chosen so the recorded `now` sits comfortably inside every valid
// vector's window with the default skew.
func vectorSpecs() []vectorSpec {
	now := "2024-06-01T00:00:00Z"
	skew := 300

	baseValidation := vectorValidation{ProductID: "p1", Now: now, ClockSkewSeconds: skew}

	expires := fixedIssuedAt.Add(365 * 24 * time.Hour)
	deviceExpires := expires

	return []vectorSpec{
		{
			name:        "valid-basic",
			description: "Minimal lifetime license, no device binding, sorted keys, omitempty fields absent.",
			payload: &license.Payload{
				LicenseID:     "lic-basic",
				ProductID:     "p1",
				Edition:       license.EditionBasic,
				LicenseType:   license.LicenseTypeLifetime,
				IssuedAt:      fixedIssuedAt,
				DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
			},
			validation: baseValidation,
		},
		{
			name:        "valid-lifetime",
			description: "Lifetime license with features, limits, and metadata exercising nested sorted maps and large integers.",
			payload: &license.Payload{
				LicenseID:     "lic-lifetime",
				SerialNumber:  "SN-0001",
				ProductID:     "p1",
				CustomerID:    "cust-1",
				CustomerName:  "Ünïcode <b>&amp;</b> 日本語",
				Edition:       license.EditionEnterprise,
				LicenseType:   license.LicenseTypeLifetime,
				IssuedAt:      fixedIssuedAt,
				Features:      []string{"export", "api", "sso"},
				Limits:        map[string]int64{"z": 3, "a": 1099511627776, "m": 0},
				Metadata:      map[string]string{"z": "1", "a": "2"},
				DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
			},
			validation: baseValidation,
		},
		{
			name:        "valid-subscription",
			description: "Subscription license with an explicit expires_at in the future relative to `now`.",
			payload: &license.Payload{
				LicenseID:     "lic-sub",
				ProductID:     "p1",
				Edition:       license.EditionProfessional,
				LicenseType:   license.LicenseTypeSubscription,
				IssuedAt:      fixedIssuedAt,
				ExpiresAt:     ptrTime(expires),
				DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
			},
			validation: baseValidation,
		},
		{
			name:        "valid-device-bound",
			description: "Subscription license bound to a single device via a versioned fingerprint device_id.",
			payload: &license.Payload{
				LicenseID:   "lic-device",
				ProductID:   "p1",
				Edition:     license.EditionProfessional,
				LicenseType: license.LicenseTypeSubscription,
				IssuedAt:    fixedIssuedAt,
				ExpiresAt:   ptrTime(deviceExpires),
				DeviceBinding: license.DeviceBinding{
					Mode:      license.DeviceModeSingle,
					DeviceIDs: []string{"fp:v2:sha256:" + sampleDigest()},
				},
			},
			validation: vectorValidation{
				ProductID:         "p1",
				DeviceFingerprint: "fp:v2:sha256:" + sampleDigest(),
				Now:               now,
				ClockSkewSeconds:  skew,
			},
		},
		{
			name:        "invalid-signature",
			description: "Well-formed envelope whose signature bytes have been flipped; must fail signature verification.",
			payload: &license.Payload{
				LicenseID:     "lic-badsig",
				ProductID:     "p1",
				Edition:       license.EditionBasic,
				LicenseType:   license.LicenseTypeLifetime,
				IssuedAt:      fixedIssuedAt,
				DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
			},
			validation:   baseValidation,
			expected:     "invalid",
			expectedCode: string(license.CodeSignatureInvalid),
			layer:        "verify",
			mutate: func(t *testing.T, v *vectorFile, _ ed25519.PrivateKey) {
				flipSignatureBit(t, v)
			},
		},
		{
			name:        "invalid-keyid",
			description: "Envelope key_id was substituted to a different (known) key so it no longer matches the signed payload's embedded key_id; must fail payload<->envelope key_id binding.",
			payload: &license.Payload{
				LicenseID:     "lic-keyid",
				ProductID:     "p1",
				Edition:       license.EditionBasic,
				LicenseType:   license.LicenseTypeLifetime,
				IssuedAt:      fixedIssuedAt,
				DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
			},
			validation:   baseValidation,
			expected:     "invalid",
			expectedCode: string(license.CodeKeyIDMismatch),
			layer:        "verify",
			mutate: func(t *testing.T, v *vectorFile, _ ed25519.PrivateKey) {
				// Rewrite ONLY the envelope key_id to a DIFFERENT key id. The
				// signature still covers the original payload (whose embedded
				// key_id is vectorKeyID). A conformant verifier that trusts the
				// substituted key id must still reject the license because the
				// payload's embedded key_id no longer matches the envelope
				// (CodeKeyIDMismatch) — the payload<->envelope binding defense
				// (protocol-v2 §5).
				setEnvelopeField(t, v, "key_id", vectorSubstituteKeyID)
			},
		},
		{
			name:        "invalid-noncanonical",
			description: "Payload bytes are validly signed but not in canonical form (keys reordered); must be rejected as non-canonical.",
			payload: &license.Payload{
				LicenseID:     "lic-noncanon",
				ProductID:     "p1",
				Edition:       license.EditionBasic,
				LicenseType:   license.LicenseTypeLifetime,
				IssuedAt:      fixedIssuedAt,
				DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
			},
			validation:   baseValidation,
			expected:     "invalid",
			expectedCode: string(license.CodeNonCanonicalPayload),
			layer:        "verify",
			mutate: func(t *testing.T, v *vectorFile, priv ed25519.PrivateKey) {
				makeNonCanonical(t, v, priv)
			},
		},
		{
			name:        "invalid-duplicate-key",
			description: "Payload JSON contains a duplicate object key; the strict parser must reject it (JSON smuggling defense).",
			payload: &license.Payload{
				LicenseID:     "lic-dupkey",
				ProductID:     "p1",
				Edition:       license.EditionBasic,
				LicenseType:   license.LicenseTypeLifetime,
				IssuedAt:      fixedIssuedAt,
				DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
			},
			validation:   baseValidation,
			expected:     "invalid",
			expectedCode: string(license.CodeMalformed),
			layer:        "verify",
			mutate: func(t *testing.T, v *vectorFile, priv ed25519.PrivateKey) {
				makeDuplicateKey(t, v, priv)
			},
		},
	}
}

// ptrTime returns a pointer to t (for optional *time.Time payload fields).
func ptrTime(t time.Time) *time.Time { return &t }

// sampleDigest returns a fixed 64-hex-char SHA-256-shaped digest for a stable
// device fingerprint vector.
func sampleDigest() string {
	return "3fdba35f04dc8c462986c992bcf875546257113072a909c162f7e470e581e278"
}
