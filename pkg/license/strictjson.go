package license

import (
	"bytes"
	"encoding/json"
	"io"
)

// DecodeStrictJSON decodes exactly one JSON value from data into dst with the
// strictest settings this package uses internally: non-empty input within
// maxSize (0 disables the size cap), no unknown object fields, exactly one
// top-level value with no trailing bytes, and no duplicate object keys anywhere
// in the tree. It returns a *Error (CodeMalformed/CodeFileTooLarge) on failure
// rather than panicking. Exposed so issuer-side tooling can parse configuration
// with identical strictness to the client's on-the-wire parsing.
func DecodeStrictJSON(data []byte, dst any, maxSize int) error {
	return decodeStrictJSON(data, dst, maxSize)
}

// decodeStrictJSON decodes exactly one JSON value from data into dst with the
// strictest available settings, then rejects anything that follows it. It is
// the single choke point for parsing untrusted JSON in this package so every
// entry point (envelopes, payloads, revocation lists, rollback state, issuer
// config) gets identical, auditable strictness.
//
// Guarantees, in order:
//   - data must be non-empty and within maxSize (0 disables the size check).
//   - Unknown object fields are rejected (DisallowUnknownFields).
//   - Exactly one top-level JSON value is decoded; a trailing second value,
//     token, or any non-whitespace byte after it is rejected (strict io.EOF).
//   - Duplicate object keys are rejected anywhere in the value tree, closing a
//     classic JSON smuggling/ambiguity vector where two producers/consumers
//     disagree on which duplicate wins.
//
// It returns a *Error with CodeMalformed on any failure rather than panicking.
func decodeStrictJSON(data []byte, dst any, maxSize int) error {
	if len(data) == 0 {
		return newError(CodeMalformed, "empty JSON input", nil)
	}
	if maxSize > 0 && len(data) > maxSize {
		return newError(CodeFileTooLarge, "JSON input exceeds size cap", nil)
	}
	// Reject duplicate object keys before structural decoding. This scan uses a
	// token-level decoder so it sees the raw key stream (encoding/json's struct
	// decode silently keeps the last duplicate).
	if err := rejectDuplicateKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return newError(CodeMalformed, "decode JSON", err)
	}
	// Exactly one value: the next token must be a clean EOF. Any trailing
	// value, number, garbage, or NUL byte is rejected.
	if _, err := dec.Token(); err != io.EOF {
		return newError(CodeMalformed, "trailing data after JSON value", nil)
	}
	return nil
}

// rejectDuplicateKeys walks the JSON token stream and returns a *Error with
// CodeMalformed if any object contains a duplicate key. It also enforces that
// the input is a single well-formed JSON value with nothing trailing.
func rejectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walkNoDupKeys(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return newError(CodeMalformed, "trailing data after JSON value", nil)
	}
	return nil
}

// walkNoDupKeys consumes exactly one JSON value from dec, recursively verifying
// that no object contains a duplicate key.
func walkNoDupKeys(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return newError(CodeMalformed, "scan JSON token", err)
	}
	switch d := tok.(type) {
	case json.Delim:
		switch d {
		case '{':
			return walkObject(dec)
		case '[':
			return walkArray(dec)
		default:
			// A bare '}' or ']' is malformed here.
			return newError(CodeMalformed, "unexpected JSON delimiter", nil)
		}
	default:
		// Scalar value already consumed.
		return nil
	}
}

// walkObject consumes an object body (the opening '{' was already read),
// rejecting duplicate keys.
func walkObject(dec *json.Decoder) error {
	seen := make(map[string]struct{})
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return newError(CodeMalformed, "scan object key", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return newError(CodeMalformed, "non-string object key", nil)
		}
		if _, dup := seen[key]; dup {
			return newError(CodeMalformed, "duplicate object key: "+key, nil)
		}
		seen[key] = struct{}{}
		if err := walkNoDupKeys(dec); err != nil {
			return err
		}
	}
	// Consume the closing '}'.
	if _, err := dec.Token(); err != nil {
		return newError(CodeMalformed, "scan object close", err)
	}
	return nil
}

// walkArray consumes an array body (the opening '[' was already read).
func walkArray(dec *json.Decoder) error {
	for dec.More() {
		if err := walkNoDupKeys(dec); err != nil {
			return err
		}
	}
	// Consume the closing ']'.
	if _, err := dec.Token(); err != nil {
		return newError(CodeMalformed, "scan array close", err)
	}
	return nil
}
