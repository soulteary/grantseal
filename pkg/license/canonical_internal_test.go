package license

import (
	"bytes"
	"encoding/json"
	"testing"
)

// customScalar is a JSON-marshalable type not handled by any explicit
// encodeScalar case, so it exercises the default (reflect via encoding/json)
// branch.
type customScalar struct {
	A int    `json:"a"`
	B string `json:"b"`
}

// TestEncodeScalarBranches drives encodeScalar directly across all of its
// explicit type switch arms plus the default fallback.
func TestEncodeScalarBranches(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"string", "hi", `"hi"`},
		{"string_html_not_escaped", "a<b>&c", `"a<b>&c"`},
		{"json_number_int", json.Number("42"), "42"},
		{"json_number_float", json.Number("3.14"), "3.14"},
		{"bool_true", true, "true"},
		{"bool_false", false, "false"},
		{"nil", nil, "null"},
		{"default_custom_type", customScalar{A: 1, B: "x"}, `{"a":1,"b":"x"}`},
		{"default_int", 7, "7"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := encodeScalar(&buf, tc.in); err != nil {
				t.Fatalf("encodeScalar(%v): unexpected error %v", tc.in, err)
			}
			if got := buf.String(); got != tc.want {
				t.Fatalf("encodeScalar(%v): want %s, got %s", tc.in, tc.want, got)
			}
		})
	}
}

// TestEncodeScalarDefaultError confirms the default branch propagates a
// marshal error rather than panicking, for a value encoding/json cannot encode.
func TestEncodeScalarDefaultError(t *testing.T) {
	var buf bytes.Buffer
	// A channel is not JSON-marshalable; the default branch must surface the
	// error from json.Marshal.
	if err := encodeScalar(&buf, make(chan int)); err == nil {
		t.Fatal("expected error for unmarshalable value, got nil")
	}
}
