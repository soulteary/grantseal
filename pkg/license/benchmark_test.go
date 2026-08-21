package license_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/soulteary/grantseal/internal/issuer"
	"github.com/soulteary/grantseal/pkg/license"
)

// The benchmarks below intentionally build every input (keys, payloads,
// envelopes, revocation lists) BEFORE the timed loop and call b.ReportAllocs()
// so the reported ns/op, B/op and allocs/op reflect only the operation under
// test. Return values are checked (b.Fatal on error) so the compiler cannot
// elide the work and so a regression that starts returning errors is caught.

// benchSigner builds an ephemeral signer + public key for a benchmark. Key
// generation happens outside the timed region.
func benchSigner(b *testing.B, keyID string) (*issuer.Signer, ed25519.PublicKey) {
	b.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("generate key: %v", err)
	}
	s, err := issuer.NewSigner(keyID, priv)
	if err != nil {
		b.Fatalf("new signer: %v", err)
	}
	return s, pub
}

// benchRequest returns a minimal valid issue request (mirrors baseRequest but
// takes *testing.B).
func benchRequest() issuer.IssueRequest {
	now := time.Now().UTC()
	exp := now.Add(365 * 24 * time.Hour)
	return issuer.IssueRequest{
		ProductID:     "acme-app",
		CustomerID:    "cust_1",
		Edition:       license.EditionProfessional,
		LicenseType:   license.LicenseTypeSubscription,
		IssuedAt:      &now,
		ExpiresAt:     &exp,
		DeviceBinding: license.DeviceBinding{Mode: license.DeviceModeNone},
	}
}

// benchIssueBytes issues a license and returns its envelope JSON bytes.
func benchIssueBytes(b *testing.B, s *issuer.Signer, req issuer.IssueRequest) []byte {
	b.Helper()
	env, err := issuer.Issue(s, req)
	if err != nil {
		b.Fatalf("issue: %v", err)
	}
	data, err := env.MarshalJSONIndent()
	if err != nil {
		b.Fatalf("marshal envelope: %v", err)
	}
	return data
}

// BenchmarkParseEnvelope measures parsing (JSON decode + field checks) of a
// well-formed envelope. It does NOT include signature verification.
func BenchmarkParseEnvelope(b *testing.B) {
	s, _ := benchSigner(b, "k1")
	data := benchIssueBytes(b, s, benchRequest())

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		env, err := license.ParseEnvelope(data)
		if err != nil {
			b.Fatalf("parse: %v", err)
		}
		if env == nil {
			b.Fatal("nil envelope")
		}
	}
}

// BenchmarkVerifySignature measures a full cryptographic verification via
// Manager.Inspect (parse + Ed25519 verify + payload decode), with no anti-
// rollback store and no policy checks.
func BenchmarkVerifySignature(b *testing.B) {
	s, pub := benchSigner(b, "k1")
	data := benchIssueBytes(b, s, benchRequest())
	ring := license.NewKeyRing()
	if err := ring.AddPublicKey("k1", pub); err != nil {
		b.Fatalf("add pubkey: %v", err)
	}
	mgr := license.NewManager(ring, license.WithClock(license.SystemClock{}))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p, err := mgr.Inspect(data)
		if err != nil {
			b.Fatalf("inspect: %v", err)
		}
		if p == nil {
			b.Fatal("nil payload")
		}
	}
}

// BenchmarkValidateMemory measures a full in-memory validation (verify +
// policy) with a fixed trusted clock and no rollback file I/O, no revocation.
// This is the "complete policy check, pure memory" path.
func BenchmarkValidateMemory(b *testing.B) {
	s, pub := benchSigner(b, "k1")
	data := benchIssueBytes(b, s, benchRequest())
	ring := license.NewKeyRing()
	if err := ring.AddPublicKey("k1", pub); err != nil {
		b.Fatalf("add pubkey: %v", err)
	}
	fixed := license.FixedClock{T: time.Now().UTC()}
	mgr := license.NewManager(ring, license.WithClock(fixed))
	ctx := license.ValidationContext{ProductID: "acme-app"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := mgr.Validate(data, ctx)
		if err != nil {
			b.Fatalf("validate: %v", err)
		}
		if !res.Valid() {
			b.Fatalf("unexpected invalid result: %s", res.Code())
		}
	}
}

// benchRevocationProvider builds a verified revocation provider containing n
// distinct license ids (none of which is the license under test).
func benchRevocationProvider(b *testing.B, s *issuer.Signer, ring *license.KeyRing, n int) license.RevocationProvider {
	b.Helper()
	if n == 0 {
		return nil
	}
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		ids = append(ids, fmt.Sprintf("lic_revoked_%08d", i))
	}
	env, err := issuer.BuildRevocationList(s, ids)
	if err != nil {
		b.Fatalf("build revocation list: %v", err)
	}
	data, err := json.Marshal(env)
	if err != nil {
		b.Fatalf("marshal revocation envelope: %v", err)
	}
	rp, err := license.LoadRevocationList(ring, data, time.Now().UTC())
	if err != nil {
		b.Fatalf("load revocation list: %v", err)
	}
	return rp
}

// BenchmarkValidateWithRevocation measures validation while consulting a
// revocation provider of the given size (0/100/10000 entries). The provider is
// built and verified once, before the timed loop.
func BenchmarkValidateWithRevocation(b *testing.B) {
	sizes := []int{0, 100, 10000}
	for _, n := range sizes {
		n := n
		b.Run(fmt.Sprintf("entries=%d", n), func(b *testing.B) {
			s, pub := benchSigner(b, "k1")
			data := benchIssueBytes(b, s, benchRequest())
			ring := license.NewKeyRing()
			if err := ring.AddPublicKey("k1", pub); err != nil {
				b.Fatalf("add pubkey: %v", err)
			}
			rp := benchRevocationProvider(b, s, ring, n)
			fixed := license.FixedClock{T: time.Now().UTC()}
			mgr := license.NewManager(ring, license.WithClock(fixed))
			ctx := license.ValidationContext{ProductID: "acme-app", Revocation: rp}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				res, err := mgr.Validate(data, ctx)
				if err != nil {
					b.Fatalf("validate: %v", err)
				}
				if !res.Valid() {
					b.Fatalf("unexpected invalid result: %s", res.Code())
				}
			}
		})
	}
}

// benchLargePayload constructs a payload near the entry-count caps so the
// "large" CanonicalBytes case exercises meaningful map/slice sorting work.
func benchLargePayload(b *testing.B) *license.Payload {
	b.Helper()
	s, _ := benchSigner(b, "k1")
	req := benchRequest()
	req.Features = make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		req.Features = append(req.Features, fmt.Sprintf("feature_%03d", i))
	}
	req.Limits = make(map[string]int64, 200)
	req.Metadata = make(map[string]string, 200)
	for i := 0; i < 200; i++ {
		req.Limits[fmt.Sprintf("limit_%03d", i)] = int64(i)
		req.Metadata[fmt.Sprintf("meta_%03d", i)] = fmt.Sprintf("value_%03d", i)
	}
	env, err := issuer.Issue(s, req)
	if err != nil {
		b.Fatalf("issue large: %v", err)
	}
	p, err := env.DecodePayload()
	if err != nil {
		b.Fatalf("decode payload: %v", err)
	}
	return p
}

// BenchmarkCanonicalBytes measures deterministic canonicalization for a small
// and a large payload. The signature covers exactly these bytes, so this is on
// the hot path for both issuing and verification.
func BenchmarkCanonicalBytes(b *testing.B) {
	s, pub := benchSigner(b, "k1")
	data := benchIssueBytes(b, s, benchRequest())
	ring := license.NewKeyRing()
	if err := ring.AddPublicKey("k1", pub); err != nil {
		b.Fatalf("add pubkey: %v", err)
	}
	mgr := license.NewManager(ring)
	small, err := mgr.Inspect(data)
	if err != nil {
		b.Fatalf("inspect small: %v", err)
	}
	large := benchLargePayload(b)

	cases := []struct {
		name string
		p    *license.Payload
	}{
		{"small", small},
		{"large", large},
	}
	for _, c := range cases {
		c := c
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out, err := license.CanonicalBytes(c.p)
				if err != nil {
					b.Fatalf("canonical: %v", err)
				}
				if len(out) == 0 {
					b.Fatal("empty canonical bytes")
				}
			}
		})
	}
}

// BenchmarkCachedResult measures the read-only cache fast path under
// contention (b.RunParallel). The cache is primed once before the timed loop;
// CachedResult performs no cryptographic work.
func BenchmarkCachedResult(b *testing.B) {
	s, pub := benchSigner(b, "k1")
	data := benchIssueBytes(b, s, benchRequest())
	ring := license.NewKeyRing()
	if err := ring.AddPublicKey("k1", pub); err != nil {
		b.Fatalf("add pubkey: %v", err)
	}
	fixed := license.FixedClock{T: time.Now().UTC()}
	mgr := license.NewManager(ring, license.WithClock(fixed))
	res, err := mgr.Validate(data, license.ValidationContext{ProductID: "acme-app"})
	if err != nil || !res.Valid() {
		b.Fatalf("prime cache: %v (code %s)", err, res.Code())
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cached, ok := mgr.CachedResult()
			if !ok {
				b.Fatal("expected a cached result")
			}
			if !cached.Valid() {
				b.Fatal("cached result not valid")
			}
		}
	})
}

// BenchmarkKeyRingLookup measures a key lookup against rings of increasing size
// (1/10/100). The ring is fully populated before the timed loop.
func BenchmarkKeyRingLookup(b *testing.B) {
	sizes := []int{1, 10, 100}
	now := time.Now().UTC()
	for _, n := range sizes {
		n := n
		b.Run(fmt.Sprintf("keys=%d", n), func(b *testing.B) {
			ring := license.NewKeyRing()
			var target string
			for i := 0; i < n; i++ {
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					b.Fatalf("generate key: %v", err)
				}
				id := fmt.Sprintf("k%03d", i)
				if err := ring.AddPublicKey(id, pub); err != nil {
					b.Fatalf("add pubkey: %v", err)
				}
				// Look up the last key so the map probe is representative.
				target = id
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				entry, err := ring.Lookup(target, now)
				if err != nil {
					b.Fatalf("lookup: %v", err)
				}
				if entry.KeyID != target {
					b.Fatalf("unexpected key id %q", entry.KeyID)
				}
			}
		})
	}
}
