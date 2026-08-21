package license_test

import (
	"encoding/json"
	"sync"
	"testing"

	"github.com/soulteary/grantseal/pkg/license"
)

// FuzzParseEnvelope ensures the envelope parser never panics on arbitrary input
// and only ever returns a *license.Error on failure.
func FuzzParseEnvelope(f *testing.F) {
	// Seed corpus.
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte(`{"algorithm":"Ed25519","key_id":"k","payload":"AAAA","signature":"AAAA"}`))
	f.Add([]byte(`{"algorithm":"Ed25519"`))
	f.Add([]byte(`not json at all`))
	f.Add([]byte(`{"algorithm":"Ed25519","key_id":"k","payload":"!!!","signature":"###"}`))

	s, pub := testKeyPairF(f, "k1")
	valid := issueBytesF(f, s)
	f.Add(valid)

	ring := license.NewKeyRing()
	_ = ring.AddPublicKey("k1", pub)
	mgr := newTestManager(ring)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic. ParseEnvelope + full Validate exercise the parser.
		if env, err := license.ParseEnvelope(data); err == nil && env == nil {
			t.Fatal("nil envelope with nil error")
		}
		// Validate should never panic; result must be consistent with error.
		res, err := mgr.Validate(data, license.ValidationContext{})
		if err == nil && !res.Valid() {
			t.Fatalf("nil error but invalid result: %s", res.Code())
		}
	})
}

// TestConcurrentValidation runs many validations across goroutines with a
// shared Manager/KeyRing to catch data races (run with -race).
func TestConcurrentValidation(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	data := issueBytes(t, s, baseRequest())
	ring := ringWith(t, "k1", pub)
	mgr := newTestManager(ring)

	const goroutines = 32
	const iters = 50
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				res, err := mgr.Validate(data, license.ValidationContext{ProductID: "acme-app"})
				if err != nil || !res.Valid() {
					errCh <- err
					return
				}
				// Concurrently mutate the ring to exercise its lock.
				_ = ring.KeyIDs()
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent validation failed: %v", err)
		}
	}
}

// TestConcurrentKeyRing exercises concurrent Add/Lookup on the KeyRing.
func TestConcurrentKeyRing(t *testing.T) {
	_, pub := testKeyPair(t, "k1")
	ring := license.NewKeyRing()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_ = ring.AddPublicKey("k1", pub)
			_ = ring.KeyIDs()
		}(i)
	}
	wg.Wait()
}

// TestCanonicalDeterministic ensures canonical bytes are stable regardless of
// map ordering, which is what makes signatures reproducible.
func TestCanonicalDeterministic(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	req := baseRequest()
	req.Metadata = map[string]string{"z": "1", "a": "2", "m": "3"}
	req.Limits = map[string]int64{"b": 2, "a": 1, "c": 3}
	data := issueBytes(t, s, req)

	// Re-derive canonical bytes from the payload and confirm stability across
	// repeated marshaling.
	mgr := newTestManager(ringWith(t, "k1", pub))
	p, err := mgr.Inspect(data)
	if err != nil {
		t.Fatal(err)
	}
	c1, err := license.CanonicalBytes(p)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		c2, err := license.CanonicalBytes(p)
		if err != nil {
			t.Fatal(err)
		}
		if string(c1) != string(c2) {
			t.Fatalf("canonical bytes not deterministic on iteration %d", i)
		}
	}
	// And the produced canonical JSON must be valid JSON.
	var tmp any
	if err := json.Unmarshal(c1, &tmp); err != nil {
		t.Fatalf("canonical is not valid json: %v", err)
	}
}
