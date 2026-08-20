package license

import (
	"bytes"
	"encoding/json"
	"sort"
)

// CanonicalBytes returns the deterministic, sorted-key JSON encoding of the
// payload. This exact byte sequence is what gets signed and verified, so it
// MUST be stable regardless of Go map iteration order or struct field order.
//
// Determinism is achieved by:
//   - marshaling into a generic value tree,
//   - recursively sorting every object's keys,
//   - re-encoding with HTML escaping disabled and no extra whitespace.
//
// The signature covers this complete canonical payload (security red line).
func CanonicalBytes(p *Payload) ([]byte, error) {
	if p == nil {
		return nil, newError(CodeMalformed, "nil payload", nil)
	}
	// Marshal to bytes first so time.Time etc. use their canonical JSON form.
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, newError(CodeMalformed, "marshal payload", err)
	}
	var tree any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // preserve number fidelity; avoid float re-formatting
	if err := dec.Decode(&tree); err != nil {
		return nil, newError(CodeMalformed, "decode payload tree", err)
	}
	var buf bytes.Buffer
	if err := encodeCanonical(&buf, tree); err != nil {
		return nil, newError(CodeMalformed, "encode canonical", err)
	}
	return buf.Bytes(), nil
}

// encodeCanonical writes v to buf as canonical JSON: object keys sorted,
// no insignificant whitespace, HTML escaping disabled.
func encodeCanonical(buf *bytes.Buffer, v any) error {
	switch val := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := encodeCanonical(buf, val[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	case []any:
		buf.WriteByte('[')
		for i, item := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	default:
		return encodeScalar(buf, v)
	}
}

// encodeScalar writes a JSON scalar (string, json.Number, bool, nil) without
// HTML escaping, matching the object/array formatting above.
func encodeScalar(buf *bytes.Buffer, v any) error {
	switch s := v.(type) {
	case string:
		return encodeString(buf, s)
	case json.Number:
		buf.WriteString(s.String())
		return nil
	case bool:
		if s {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil
	case nil:
		buf.WriteString("null")
		return nil
	default:
		// Fallback: use encoding/json for any unexpected scalar type.
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(false)
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		buf.Write(bytes.TrimRight(b, "\n"))
		return nil
	}
}

// encodeString writes a JSON string with HTML escaping disabled.
func encodeString(buf *bytes.Buffer, s string) error {
	b, err := marshalStringNoHTMLEscape(s)
	if err != nil {
		return err
	}
	buf.Write(b)
	return nil
}

func marshalStringNoHTMLEscape(s string) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}
