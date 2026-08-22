package license_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/soulteary/grantseal/internal/issuer"
	"github.com/soulteary/grantseal/pkg/license"
)

// FuzzCanonicalBytes ensures CanonicalBytes never panics on any payload
// decoded from arbitrary JSON and, when it succeeds, always emits valid JSON.
// This guards the security red line that the signed bytes are deterministic
// and well-formed for any structurally decodable payload.
func FuzzCanonicalBytes(f *testing.F) {
	// Seed with a real canonical payload plus assorted edge inputs.
	s, _ := testKeyPairF(f, "k1")
	valid := issueBytesF(f, s)
	if env, err := license.ParseEnvelope(valid); err == nil {
		if raw, derr := env.DecodeCanonical(); derr == nil {
			f.Add(raw)
		}
	}
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"schema_version":1,"license_id":"l","product_id":"p","key_id":"k"}`))
	f.Add([]byte(`{"limits":{"a":1,"z":9007199254740993},"metadata":{"<":">"}}`))
	f.Add([]byte(`{"customer_name":"日本語 <b>&amp;</b>"}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		var p license.Payload
		if err := json.Unmarshal(data, &p); err != nil {
			return // only exercise structurally decodable payloads
		}
		out, err := license.CanonicalBytes(&p)
		if err != nil {
			return // a returned error is acceptable; a panic is not
		}
		var tmp any
		if jerr := json.Unmarshal(out, &tmp); jerr != nil {
			t.Fatalf("canonical output is not valid JSON: %v\ninput: %q\noutput: %q", jerr, data, out)
		}
		// Canonicalization must be idempotent for the same payload.
		out2, err2 := license.CanonicalBytes(&p)
		if err2 != nil || string(out) != string(out2) {
			t.Fatalf("canonical bytes not deterministic: %q vs %q (err=%v)", out, out2, err2)
		}
	})
}

// FuzzLoadRevocationList ensures the revocation loader never panics on
// arbitrary input and only ever returns a *license.Error on failure.
func FuzzLoadRevocationList(f *testing.F) {
	s, pub := testKeyPairF(f, "k1")

	// A real, valid signed revocation list is the most useful seed.
	seedNow := time.Now().UTC()
	if env, err := issuer.BuildRevocationListV2(s, issuer.RevocationListOptions{
		ListID:     "list-fuzz",
		Sequence:   1,
		IssuedAt:   seedNow,
		ExpiresAt:  seedNow.Add(365 * 24 * time.Hour),
		RevokedIDs: []string{"lic_a", "lic_b"},
	}); err == nil {
		if data, merr := json.Marshal(env); merr == nil {
			f.Add(data)
		}
	}
	f.Add([]byte(``))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"algorithm":"Ed25519","key_id":"k1","payload":"AAAA","signature":"AAAA"}`))
	f.Add([]byte(`{"algorithm":"Ed25519","key_id":"k1","payload":"!!!","signature":"###"}`))
	f.Add([]byte(`not json at all`))

	ring := license.NewKeyRing()
	_ = ring.AddPublicKey("k1", pub)
	now := time.Now().UTC()

	f.Fuzz(func(t *testing.T, data []byte) {
		rp, err := license.LoadRevocationList(ring, data, now)
		if err == nil {
			if rp == nil {
				t.Fatal("nil provider with nil error")
			}
			// A successfully loaded provider must be queryable without panic.
			_ = rp.IsRevoked("anything")
			return
		}
		if license.CodeOf(err) == "" {
			t.Fatalf("error is not a license *Error: %v", err)
		}
	})
}

// FuzzRollbackStateLoad ensures the anti-rollback state parser never panics on
// arbitrary on-disk bytes and only ever returns a *license.Error on failure.
func FuzzRollbackStateLoad(f *testing.F) {
	f.Add([]byte(``))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"last_trusted_time":"2024-01-01T00:00:00Z","last_verified_at":"2024-01-01T00:00:00Z","mac":"00"}`))
	f.Add([]byte(`{"last_trusted_time":`))
	f.Add([]byte(`{"last_trusted_time":"x","last_verified_at":"y","mac":"zz","extra":1}`))
	f.Add([]byte(`garbage`))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "rollback.state")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skip() // filesystem-level failure is not what we are fuzzing
		}
		store, err := license.NewRollbackStore(path, []byte("fuzz-key"), 0)
		if err != nil {
			t.Fatalf("store construction should not fail: %v", err)
		}
		st, lerr := store.Load()
		if lerr == nil {
			// A nil error with nil state means "no prior state"; both are fine.
			_ = st
			return
		}
		if license.CodeOf(lerr) == "" {
			t.Fatalf("error is not a license *Error: %v", lerr)
		}
	})
}
