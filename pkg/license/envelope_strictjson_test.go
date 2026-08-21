package license_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/soulteary/grantseal/pkg/license"
)

// b64url mirrors the package's Base64URL alphabet used for envelope fields.
var b64url = base64.URLEncoding

// TestParseEnvelopeOversized rejects input beyond the file-size cap with
// CodeFileTooLarge (checked before any JSON parsing).
func TestParseEnvelopeOversized(t *testing.T) {
	big := make([]byte, license.MaxLicenseFileSize+1)
	for i := range big {
		big[i] = 'x'
	}
	if _, err := license.ParseEnvelope(big); license.CodeOf(err) != license.CodeFileTooLarge {
		t.Fatalf("oversized envelope: want CodeFileTooLarge, got %s", license.CodeOf(err))
	}
}

// TestParseEnvelopeTruncated rejects a truncated JSON object as malformed
// rather than panicking.
func TestParseEnvelopeTruncated(t *testing.T) {
	data := []byte(`{"algorithm":"Ed25519","key_id":"k","payload":"AAAA"`)
	if _, err := license.ParseEnvelope(data); license.CodeOf(err) != license.CodeMalformed {
		t.Fatalf("truncated envelope: want CodeMalformed, got %s", license.CodeOf(err))
	}
}

// TestParseEnvelopeWrongFieldType rejects a value whose JSON type does not match
// the target struct field (string field carrying a number/array/object).
func TestParseEnvelopeWrongFieldType(t *testing.T) {
	cases := []string{
		`{"algorithm":123,"key_id":"k","payload":"AAAA","signature":"AAAA"}`,
		`{"algorithm":"Ed25519","key_id":["k"],"payload":"AAAA","signature":"AAAA"}`,
		`{"algorithm":"Ed25519","key_id":"k","payload":{"x":1},"signature":"AAAA"}`,
		`{"algorithm":"Ed25519","key_id":"k","payload":"AAAA","signature":true}`,
	}
	for i, c := range cases {
		if _, err := license.ParseEnvelope([]byte(c)); license.CodeOf(err) != license.CodeMalformed {
			t.Fatalf("case %d wrong field type: want CodeMalformed, got %s", i, license.CodeOf(err))
		}
	}
}

// TestDecodeCanonicalBadBase64 rejects an envelope whose payload is not valid
// Base64URL.
func TestDecodeCanonicalBadBase64(t *testing.T) {
	e := &license.Envelope{
		Algorithm: "Ed25519",
		KeyID:     "k",
		Payload:   "!!!not-base64!!!",
		Signature: "AAAA",
	}
	if _, err := e.DecodeCanonical(); license.CodeOf(err) != license.CodeMalformed {
		t.Fatalf("bad base64 payload: want CodeMalformed, got %s", license.CodeOf(err))
	}
}

// TestDecodeCanonicalEmptyPayload rejects an envelope whose payload decodes to
// zero bytes.
func TestDecodeCanonicalEmptyPayload(t *testing.T) {
	e := &license.Envelope{
		Algorithm: "Ed25519",
		KeyID:     "k",
		Payload:   b64url.EncodeToString([]byte{}),
		Signature: "AAAA",
	}
	if _, err := e.DecodeCanonical(); license.CodeOf(err) != license.CodeMalformed {
		t.Fatalf("empty payload: want CodeMalformed, got %s", license.CodeOf(err))
	}
}

// TestDecodePayloadBadBase64 propagates the DecodeCanonical error path.
func TestDecodePayloadBadBase64(t *testing.T) {
	e := &license.Envelope{
		Algorithm: "Ed25519",
		KeyID:     "k",
		Payload:   "@@@",
		Signature: "AAAA",
	}
	if _, err := e.DecodePayload(); license.CodeOf(err) != license.CodeMalformed {
		t.Fatalf("bad base64 in DecodePayload: want CodeMalformed, got %s", license.CodeOf(err))
	}
}

// TestDecodePayloadMalformedJSON rejects a valid-base64 payload whose decoded
// bytes are not a well-formed Payload JSON object.
func TestDecodePayloadMalformedJSON(t *testing.T) {
	e := &license.Envelope{
		Algorithm: "Ed25519",
		KeyID:     "k",
		Payload:   b64url.EncodeToString([]byte(`{"schema_version":`)), // truncated JSON
		Signature: "AAAA",
	}
	if _, err := e.DecodePayload(); license.CodeOf(err) != license.CodeMalformed {
		t.Fatalf("truncated payload JSON: want CodeMalformed, got %s", license.CodeOf(err))
	}
}

// TestDecodePayloadUnknownField rejects a payload carrying an unknown object
// field (DisallowUnknownFields via the strict decoder).
func TestDecodePayloadUnknownField(t *testing.T) {
	e := &license.Envelope{
		Algorithm: "Ed25519",
		KeyID:     "k",
		Payload:   b64url.EncodeToString([]byte(`{"surprise":1}`)),
		Signature: "AAAA",
	}
	if _, err := e.DecodePayload(); license.CodeOf(err) != license.CodeMalformed {
		t.Fatalf("unknown payload field: want CodeMalformed, got %s", license.CodeOf(err))
	}
}

// TestDecodePayloadWrongFieldType rejects a payload whose field JSON type does
// not match the struct.
func TestDecodePayloadWrongFieldType(t *testing.T) {
	e := &license.Envelope{
		Algorithm: "Ed25519",
		KeyID:     "k",
		Payload:   b64url.EncodeToString([]byte(`{"schema_version":"not-a-number"}`)),
		Signature: "AAAA",
	}
	if _, err := e.DecodePayload(); license.CodeOf(err) != license.CodeMalformed {
		t.Fatalf("wrong-type payload field: want CodeMalformed, got %s", license.CodeOf(err))
	}
}

// ---------------------------------------------------------------------------
// DecodeStrictJSON error branches (exported strict decoder).
// ---------------------------------------------------------------------------

func TestDecodeStrictJSONEmpty(t *testing.T) {
	var dst map[string]any
	if err := license.DecodeStrictJSON(nil, &dst, 0); license.CodeOf(err) != license.CodeMalformed {
		t.Fatalf("empty input: want CodeMalformed, got %s", license.CodeOf(err))
	}
}

func TestDecodeStrictJSONOversized(t *testing.T) {
	var dst map[string]any
	data := []byte(strings.Repeat("x", 20))
	if err := license.DecodeStrictJSON(data, &dst, 5); license.CodeOf(err) != license.CodeFileTooLarge {
		t.Fatalf("oversized input: want CodeFileTooLarge, got %s", license.CodeOf(err))
	}
}

func TestDecodeStrictJSONTruncated(t *testing.T) {
	var dst map[string]any
	if err := license.DecodeStrictJSON([]byte(`{"a":`), &dst, 0); license.CodeOf(err) != license.CodeMalformed {
		t.Fatalf("truncated input: want CodeMalformed, got %s", license.CodeOf(err))
	}
}

func TestDecodeStrictJSONTrailingData(t *testing.T) {
	var dst map[string]any
	if err := license.DecodeStrictJSON([]byte(`{"a":1} {}`), &dst, 0); license.CodeOf(err) != license.CodeMalformed {
		t.Fatalf("trailing data: want CodeMalformed, got %s", license.CodeOf(err))
	}
}

func TestDecodeStrictJSONDuplicateKeys(t *testing.T) {
	var dst map[string]any
	if err := license.DecodeStrictJSON([]byte(`{"a":1,"a":2}`), &dst, 0); license.CodeOf(err) != license.CodeMalformed {
		t.Fatalf("duplicate keys: want CodeMalformed, got %s", license.CodeOf(err))
	}
}

func TestDecodeStrictJSONNonStringKeyBareDelim(t *testing.T) {
	var dst map[string]any
	// A bare closing delimiter is malformed and must be rejected, not panic.
	if err := license.DecodeStrictJSON([]byte(`}`), &dst, 0); license.CodeOf(err) != license.CodeMalformed {
		t.Fatalf("bare delimiter: want CodeMalformed, got %s", license.CodeOf(err))
	}
}
