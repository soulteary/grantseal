package license_test

// Mutation helpers used by the cross-implementation vector generator
// (vectors_gen_test.go) to derive negative vectors from a correctly-signed
// baseline. Each helper rewrites the envelope in-place and keeps the vector's
// recorded metadata (canonical / signing_input / signature) consistent with
// what a foreign implementation will actually parse.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"
	"testing"

	"github.com/soulteary/grantseal/pkg/license"
)

// sortedKeys returns m's keys in byte-wise lexicographic order, matching the
// canonicalization's sort.Strings ordering.
func sortedKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// envelopeMap decodes the vector's envelope JSON into an ordered-agnostic map
// for field-level mutation, then the caller re-encodes it.
func envelopeMap(t *testing.T, v *vectorFile) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(v.Envelope, &m); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	return m
}

// writeEnvelope re-encodes m back into the vector's Envelope field.
func writeEnvelope(t *testing.T, v *vectorFile, m map[string]any) {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	v.Envelope = json.RawMessage(raw)
}

// setEnvelopeField rewrites a single top-level envelope field (e.g. key_id).
func setEnvelopeField(t *testing.T, v *vectorFile, field, value string) {
	t.Helper()
	m := envelopeMap(t, v)
	m[field] = value
	if field == "key_id" {
		v.KeyID = value
	}
	writeEnvelope(t, v, m)
}

// flipSignatureBit flips the low bit of the last signature byte so the 64-byte
// length stays valid but Ed25519.Verify fails. It updates both the envelope's
// signature field and the vector's recorded Signature.
func flipSignatureBit(t *testing.T, v *vectorFile) {
	t.Helper()
	m := envelopeMap(t, v)
	sigB64, _ := m["signature"].(string)
	sig, err := base64.URLEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		t.Fatalf("bad baseline signature: err=%v len=%d", err, len(sig))
	}
	sig[len(sig)-1] ^= 0x01
	corrupted := base64.URLEncoding.EncodeToString(sig)
	m["signature"] = corrupted
	writeEnvelope(t, v, m)
	v.Signature = corrupted
	// The signing input is unchanged (same canonical bytes); leave it recorded
	// so a foreign implementation can confirm the signature simply does not
	// verify over it.
}

// makeNonCanonical replaces the envelope payload with a non-canonical but
// otherwise decodable JSON encoding of the same fields (object keys reversed),
// signs THOSE bytes with the license domain so the signature verifies, and
// records the new signature. A conformant verifier must still reject it at the
// canonical-equality check (CodeNonCanonicalPayload).
func makeNonCanonical(t *testing.T, v *vectorFile, priv ed25519.PrivateKey) {
	t.Helper()
	m := envelopeMap(t, v)
	payloadB64, _ := m["payload"].(string)
	canonical, err := base64.URLEncoding.DecodeString(payloadB64)
	if err != nil {
		t.Fatalf("decode baseline payload: %v", err)
	}
	noncanon := reverseObjectKeys(t, canonical)
	if string(noncanon) == string(canonical) {
		t.Fatal("reversed payload equals canonical; cannot build non-canonical vector")
	}
	sig := ed25519.Sign(priv, license.LicenseSigningInput(noncanon))
	m["payload"] = base64.URLEncoding.EncodeToString(noncanon)
	m["signature"] = base64.URLEncoding.EncodeToString(sig)
	writeEnvelope(t, v, m)
	// Record the actually-signed (non-canonical) bytes so a foreign
	// implementation sees exactly what the signature covers.
	v.Canonical = string(noncanon)
	v.SigningInputHex = hex.EncodeToString(license.LicenseSigningInput(noncanon))
	v.Signature = base64.URLEncoding.EncodeToString(sig)
}

// makeDuplicateKey injects a duplicate top-level object key into the payload
// JSON, signs those exact bytes, and records them. The strict JSON parser must
// reject the duplicate key (CodeMalformed) before any value interpretation.
func makeDuplicateKey(t *testing.T, v *vectorFile, priv ed25519.PrivateKey) {
	t.Helper()
	m := envelopeMap(t, v)
	payloadB64, _ := m["payload"].(string)
	canonical, err := base64.URLEncoding.DecodeString(payloadB64)
	if err != nil {
		t.Fatalf("decode baseline payload: %v", err)
	}
	dup := injectDuplicateKey(t, canonical)
	sig := ed25519.Sign(priv, license.LicenseSigningInput(dup))
	m["payload"] = base64.URLEncoding.EncodeToString(dup)
	m["signature"] = base64.URLEncoding.EncodeToString(sig)
	writeEnvelope(t, v, m)
	v.Canonical = string(dup)
	v.SigningInputHex = hex.EncodeToString(license.LicenseSigningInput(dup))
	v.Signature = base64.URLEncoding.EncodeToString(sig)
}

// reverseObjectKeys re-encodes the TOP-LEVEL JSON object with its keys in
// reverse-sorted order (nested values kept as-is), producing bytes that are
// valid JSON but not grantseal-canonical. Order preservation is achieved with a
// json.Decoder token walk since Go maps do not preserve order.
func reverseObjectKeys(t *testing.T, canonical []byte) []byte {
	t.Helper()
	keys, values := decodeTopLevelObject(t, canonical)
	// Reverse the (already sorted) key order.
	out := []byte{'{'}
	for i := len(keys) - 1; i >= 0; i-- {
		if len(out) > 1 {
			out = append(out, ',')
		}
		kb, _ := json.Marshal(keys[i])
		out = append(out, kb...)
		out = append(out, ':')
		out = append(out, values[i]...)
	}
	out = append(out, '}')
	return out
}

// injectDuplicateKey emits the canonical object with its first key duplicated
// (same key appearing twice), producing a JSON-smuggling payload.
func injectDuplicateKey(t *testing.T, canonical []byte) []byte {
	t.Helper()
	keys, values := decodeTopLevelObject(t, canonical)
	if len(keys) == 0 {
		t.Fatal("empty object; cannot inject duplicate key")
	}
	out := []byte{'{'}
	// Duplicate the first key/value pair up front, then emit all pairs.
	kb0, _ := json.Marshal(keys[0])
	out = append(out, kb0...)
	out = append(out, ':')
	out = append(out, values[0]...)
	for i := range keys {
		out = append(out, ',')
		kb, _ := json.Marshal(keys[i])
		out = append(out, kb...)
		out = append(out, ':')
		out = append(out, values[i]...)
	}
	out = append(out, '}')
	return out
}

// decodeTopLevelObject returns the top-level object's keys (in file order) and
// each key's raw value bytes, using encoding/json's RawMessage to preserve the
// exact value encoding.
func decodeTopLevelObject(t *testing.T, obj []byte) (keys []string, values []json.RawMessage) {
	t.Helper()
	// json.Unmarshal into a map loses order; instead unmarshal into an ordered
	// slice via a small manual decode: unmarshal to map for values, then take
	// the sorted key order that canonical bytes already guarantee.
	var m map[string]json.RawMessage
	if err := json.Unmarshal(obj, &m); err != nil {
		t.Fatalf("decode top-level object: %v", err)
	}
	// Canonical bytes are sorted, so recover order by scanning the raw bytes
	// for each key position is overkill; instead sort keys to match canonical.
	keys = sortedKeys(m)
	values = make([]json.RawMessage, len(keys))
	for i, k := range keys {
		values[i] = m[k]
	}
	return keys, values
}
