package license_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/soulteary/grantseal/pkg/license"
)

// TestCanonicalBytesGoldenVectors pins the exact canonical byte sequence for a
// set of payloads. The signature covers these bytes verbatim, so any change to
// the canonicalization (key sorting, HTML escaping, number fidelity, null
// handling) is a security-relevant break and must fail this test.
func TestCanonicalBytesGoldenVectors(t *testing.T) {
	issued := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)

	cases := []struct {
		name string
		p    *license.Payload
		want string
	}{
		{
			name: "minimal_sorted_keys",
			p: &license.Payload{
				SchemaVersion: 1,
				LicenseID:     "l1",
				ProductID:     "p1",
				KeyID:         "k1",
				Edition:       license.EditionBasic,
				LicenseType:   license.LicenseTypeLifetime,
				IssuedAt:      issued,
				DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
			},
			// Keys are emitted in sorted order; omitempty fields absent.
			want: `{"customer_id":"","device_binding":{"mode":"none"},"edition":"basic","grace_period_days":0,"issued_at":"2024-01-02T03:04:05Z","key_id":"k1","license_id":"l1","license_type":"lifetime","product_id":"p1","schema_version":1,"serial_number":"","version_constraint":{}}`,
		},
		{
			name: "html_and_unicode_not_escaped",
			p: &license.Payload{
				SchemaVersion: 1,
				LicenseID:     "l<&>2",
				ProductID:     "p1",
				KeyID:         "k1",
				CustomerName:  "Ünïcode <b>&amp;</b> 日本語",
				Edition:       license.EditionBasic,
				LicenseType:   license.LicenseTypeLifetime,
				IssuedAt:      issued,
				DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
			},
			want: `{"customer_id":"","customer_name":"Ünïcode <b>&amp;</b> 日本語","device_binding":{"mode":"none"},"edition":"basic","grace_period_days":0,"issued_at":"2024-01-02T03:04:05Z","key_id":"k1","license_id":"l<&>2","license_type":"lifetime","product_id":"p1","schema_version":1,"serial_number":"","version_constraint":{}}`,
		},
		{
			name: "nested_maps_sorted_and_numbers_preserved",
			p: &license.Payload{
				SchemaVersion: 1,
				LicenseID:     "l3",
				ProductID:     "p1",
				KeyID:         "k1",
				Edition:       license.EditionProfessional,
				LicenseType:   license.LicenseTypeLifetime,
				IssuedAt:      issued,
				DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
				Limits:        map[string]int64{"z": 3, "a": 1099511627776, "m": 0},
				Metadata:      map[string]string{"z": "1", "a": "2"},
			},
			want: `{"customer_id":"","device_binding":{"mode":"none"},"edition":"professional","grace_period_days":0,"issued_at":"2024-01-02T03:04:05Z","key_id":"k1","license_id":"l3","license_type":"lifetime","limits":{"a":1099511627776,"m":0,"z":3},"metadata":{"a":"2","z":"1"},"product_id":"p1","schema_version":1,"serial_number":"","version_constraint":{}}`,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := license.CanonicalBytes(tc.p)
			if err != nil {
				t.Fatalf("CanonicalBytes: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("canonical mismatch:\n got:  %s\n want: %s", got, tc.want)
			}
			// The canonical output must itself be valid JSON.
			var tmp any
			if err := json.Unmarshal(got, &tmp); err != nil {
				t.Fatalf("canonical output is not valid json: %v", err)
			}
		})
	}
}

// TestCanonicalBytesNilRejected confirms a nil payload is rejected (never panics).
func TestCanonicalBytesNilRejected(t *testing.T) {
	if _, err := license.CanonicalBytes(nil); license.CodeOf(err) != license.CodeMalformed {
		t.Fatalf("nil payload: want CodeMalformed, got %s", license.CodeOf(err))
	}
}

// TestCanonicalBytesStableAcrossMapOrder builds two structurally identical
// payloads (Go map iteration order is randomized) and confirms identical bytes.
func TestCanonicalBytesStableAcrossMapOrder(t *testing.T) {
	build := func() *license.Payload {
		return &license.Payload{
			SchemaVersion: 1,
			LicenseID:     "l1",
			ProductID:     "p1",
			KeyID:         "k1",
			Edition:       license.EditionBasic,
			LicenseType:   license.LicenseTypeLifetime,
			IssuedAt:      time.Unix(0, 0).UTC(),
			DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
			Metadata:      map[string]string{"a": "1", "b": "2", "c": "3", "d": "4", "e": "5"},
			Limits:        map[string]int64{"x": 1, "y": 2, "z": 3, "w": 4},
		}
	}
	a, err := license.CanonicalBytes(build())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		b, err := license.CanonicalBytes(build())
		if err != nil {
			t.Fatal(err)
		}
		if string(a) != string(b) {
			t.Fatalf("canonical bytes unstable on iteration %d", i)
		}
	}
}
