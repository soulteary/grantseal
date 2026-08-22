package license_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/soulteary/grantseal/internal/issuer"
	"github.com/soulteary/grantseal/pkg/license"
)

// errStateStore returns a *license.Error from its atomic transaction so
// checkRevocationReplay propagates it.
type errStateStore struct{}

func (errStateStore) LoadRevocationState(string) (*license.RevocationState, error) {
	return nil, license.ErrRevocationStateIntegrityFailure
}
func (errStateStore) SaveRevocationState(*license.RevocationState) error { return nil }
func (errStateStore) CheckAndSaveRevocationState(*license.RevocationState) error {
	return license.ErrRevocationStateIntegrityFailure
}

// TestStaticRevocationNil covers the nil-receiver IsRevoked arm.
func TestStaticRevocationNil(t *testing.T) {
	var s *license.StaticRevocation
	if s.IsRevoked("x") {
		t.Fatal("nil StaticRevocation must report not revoked")
	}
	sr := license.NewStaticRevocation("a", "b")
	if !sr.IsRevoked("a") || sr.IsRevoked("c") {
		t.Fatal("static revocation membership wrong")
	}
}

// TestLoadRevocationUnsupportedAlgorithm covers the env.Algorithm.Valid() arm.
func TestLoadRevocationUnsupportedAlgorithm(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", pub)
	now := time.Now().UTC()
	data := revV2(t, s, 1, now, now.Add(24*time.Hour), "lic_x")

	var env license.RevocationEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	env.Algorithm = "RSA"
	bad, _ := json.Marshal(env)
	if _, err := license.LoadRevocationListWithPolicy(ring, bad, now, license.RevocationPolicy{}); license.CodeOf(err) != license.CodeUnsupportedAlgorithm {
		t.Fatalf("want CodeUnsupportedAlgorithm, got %s", license.CodeOf(err))
	}
}

// TestLoadRevocationBadBase64 covers the base64-decode error arms for payload
// and signature.
func TestLoadRevocationBadBase64(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", pub)
	now := time.Now().UTC()
	data := revV2(t, s, 1, now, now.Add(24*time.Hour), "lic_x")

	var env license.RevocationEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}

	badPayload := env
	badPayload.Payload = "!!!not-base64!!!"
	bp, _ := json.Marshal(badPayload)
	if _, err := license.LoadRevocationListWithPolicy(ring, bp, now, license.RevocationPolicy{}); license.CodeOf(err) != license.CodeMalformed {
		t.Fatalf("bad payload base64: want CodeMalformed, got %s", license.CodeOf(err))
	}

	badSig := env
	badSig.Signature = "!!!not-base64!!!"
	bs, _ := json.Marshal(badSig)
	if _, err := license.LoadRevocationListWithPolicy(ring, bs, now, license.RevocationPolicy{}); license.CodeOf(err) != license.CodeMalformed {
		t.Fatalf("bad sig base64: want CodeMalformed, got %s", license.CodeOf(err))
	}
}

// TestLoadRevocationBadSigLength covers the signature-size arm.
func TestLoadRevocationBadSigLength(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", pub)
	now := time.Now().UTC()
	data := revV2(t, s, 1, now, now.Add(24*time.Hour), "lic_x")

	var env license.RevocationEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	env.Signature = base64.URLEncoding.EncodeToString([]byte("short"))
	bad, _ := json.Marshal(env)
	if _, err := license.LoadRevocationListWithPolicy(ring, bad, now, license.RevocationPolicy{}); license.CodeOf(err) != license.CodeSignatureInvalid {
		t.Fatalf("want CodeSignatureInvalid, got %s", license.CodeOf(err))
	}
}

// TestLoadRevocationSignatureMismatch covers the "signature does not match" arm
// by signing with a different key than the ring holds.
func TestLoadRevocationSignatureMismatch(t *testing.T) {
	s, _ := testKeyPair(t, "k1")
	_, otherPub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", otherPub) // ring holds a DIFFERENT public key
	now := time.Now().UTC()
	data := revV2(t, s, 1, now, now.Add(24*time.Hour), "lic_x")
	if _, err := license.LoadRevocationListWithPolicy(ring, data, now, license.RevocationPolicy{}); license.CodeOf(err) != license.CodeSignatureInvalid {
		t.Fatalf("want CodeSignatureInvalid, got %s", license.CodeOf(err))
	}
}

// TestLoadRevocationV2LegacySignedRejected covers the arm rejecting a v2-schema
// list whose signature only verifies under the legacy (undomained) input.
func TestLoadRevocationV2LegacySignedRejected(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", pub)
	now := time.Now().UTC()

	// Build a v2 list body, but sign the bare canonical bytes (legacy domain).
	rl := &license.RevocationList{
		SchemaVersion: license.RevocationSchemaVersion,
		Sequence:      1,
		IssuedAt:      now,
		ExpiresAt:     ptr(now.Add(24 * time.Hour)),
		KeyID:         "k1",
		RevokedIDs:    []string{"lic_x"},
	}
	canonical, err := license.CanonicalRevocationBytes(rl)
	if err != nil {
		t.Fatal(err)
	}
	sig := s.SignCanonical(canonical) // legacy: no domain prefix
	env := &license.RevocationEnvelope{
		Algorithm: license.AlgorithmEd25519,
		KeyID:     "k1",
		Payload:   base64.URLEncoding.EncodeToString(canonical),
		Signature: base64.URLEncoding.EncodeToString(sig),
	}
	data, _ := json.Marshal(env)
	if _, err := license.LoadRevocationListWithPolicy(ring, data, now, license.RevocationPolicy{}); license.CodeOf(err) != license.CodeSignatureInvalid {
		t.Fatalf("v2 signed with legacy domain: want CodeSignatureInvalid, got %s", license.CodeOf(err))
	}
}

// TestLoadRevocationKeyIDMismatch covers the payload key_id vs envelope key_id
// arm inside verifyRevocationSignature.
func TestLoadRevocationKeyIDMismatch(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", pub)
	now := time.Now().UTC()

	// Sign a list whose payload key_id is "k1" but present it under envelope
	// key_id "k1" too — instead we tamper: build with key_id k1 then re-wrap so
	// the payload embeds a mismatching key_id. Simplest: craft payload key_id !=
	// envelope key_id by hand.
	rl := &license.RevocationList{
		SchemaVersion: license.RevocationSchemaVersion,
		Sequence:      1,
		IssuedAt:      now,
		ExpiresAt:     ptr(now.Add(24 * time.Hour)),
		KeyID:         "different", // payload says a different key
		RevokedIDs:    []string{"lic_x"},
	}
	canonical, err := license.CanonicalRevocationBytes(rl)
	if err != nil {
		t.Fatal(err)
	}
	sig := issuer.SignRevocationBytes(s, canonical)
	env := &license.RevocationEnvelope{
		Algorithm: license.AlgorithmEd25519,
		KeyID:     "k1", // envelope says k1 (the ring key)
		Payload:   base64.URLEncoding.EncodeToString(canonical),
		Signature: base64.URLEncoding.EncodeToString(sig),
	}
	data, _ := json.Marshal(env)
	if _, err := license.LoadRevocationListWithPolicy(ring, data, now, license.RevocationPolicy{}); license.CodeOf(err) != license.CodeKeyIDMismatch {
		t.Fatalf("want CodeKeyIDMismatch, got %s", license.CodeOf(err))
	}
}

// TestLoadRevocationFreshnessArms drives the from-future and MaxAge arms.
func TestLoadRevocationFreshnessArms(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", pub)
	now := time.Now().UTC()

	// Issued far in the future -> CodeRevocationFromFuture.
	future := revV2(t, s, 1, now.Add(72*time.Hour), now.Add(96*time.Hour), "lic_x")
	if _, err := license.LoadRevocationListWithPolicy(ring, future, now, license.RevocationPolicy{}); license.CodeOf(err) != license.CodeRevocationFromFuture {
		t.Fatalf("from future: want CodeRevocationFromFuture, got %s", license.CodeOf(err))
	}

	// Older than MaxAge -> CodeRevocationExpired (via the MaxAge arm).
	old := revV2(t, s, 1, now.Add(-48*time.Hour), now.Add(24*time.Hour), "lic_x")
	pol := license.RevocationPolicy{MaxAge: time.Hour}
	if _, err := license.LoadRevocationListWithPolicy(ring, old, now, pol); license.CodeOf(err) != license.CodeRevocationExpired {
		t.Fatalf("older than MaxAge: want CodeRevocationExpired, got %s", license.CodeOf(err))
	}
}

// TestLoadRevocationReplayStoreError covers the LoadRevocationState error
// propagation arm in checkRevocationReplay.
func TestLoadRevocationReplayStoreError(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", pub)
	now := time.Now().UTC()
	data := revV2(t, s, 1, now, now.Add(24*time.Hour), "lic_x")
	pol := license.RevocationPolicy{StateStore: errStateStore{}}
	if _, err := license.LoadRevocationListWithPolicy(ring, data, now, pol); license.CodeOf(err) != license.CodeRevocationStateIntegrityFailure {
		t.Fatalf("store load error: want CodeRevocationStateIntegrityFailure, got %s", license.CodeOf(err))
	}
}

// TestLoadRevocationRollbackDigestMismatch covers the reused-sequence,
// different-digest arm (CodeRevocationRollback).
func TestLoadRevocationRollbackDigestMismatch(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", pub)
	now := time.Now().UTC()
	store := license.NewMemRevocationStateStore()
	pol := license.RevocationPolicy{StateStore: store}

	// Accept sequence 3 with content {lic_a}.
	if _, err := license.LoadRevocationListWithPolicy(ring, revV2(t, s, 3, now, now.Add(24*time.Hour), "lic_a"), now, pol); err != nil {
		t.Fatalf("accept seq=3: %v", err)
	}
	// Reuse sequence 3 with DIFFERENT content {lic_b} -> rollback.
	if _, err := license.LoadRevocationListWithPolicy(ring, revV2(t, s, 3, now, now.Add(24*time.Hour), "lic_b"), now, pol); license.CodeOf(err) != license.CodeRevocationRollback {
		t.Fatalf("reused seq different content: want CodeRevocationRollback, got %s", license.CodeOf(err))
	}
}

// TestVerifyKeyIDMismatch covers the verifier's payload-key_id vs envelope arm
// and the canonical-mismatch arm.
func TestVerifyKeyIDMismatch(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", pub)
	// Sign a payload whose embedded key_id ("k1") is then presented under a
	// different envelope key. We add the same public key under a second id.
	if err := ring.AddPublicKey("k2", pub); err != nil {
		t.Fatal(err)
	}
	req := baseRequest()
	req.LicenseType = license.LicenseTypeLifetime
	req.ExpiresAt = nil
	env, err := issuer.Issue(s, req)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// The envelope key_id is k1 (the signer). Force it to k2 so payload.KeyID
	// (k1) != envelope.KeyID (k2), hitting the mismatch arm after signature
	// verification (which uses the k2 entry = same public key).
	env.KeyID = "k2"
	data, err := env.MarshalJSONIndent()
	if err != nil {
		t.Fatal(err)
	}
	mgr := license.NewManager(ring, license.WithUnscopedProductValidation())
	if _, err := mgr.Inspect(data); license.CodeOf(err) != license.CodeKeyIDMismatch {
		t.Fatalf("want CodeKeyIDMismatch, got %s", license.CodeOf(err))
	}
}
