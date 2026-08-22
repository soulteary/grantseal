package license_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/soulteary/grantseal/internal/issuer"
	"github.com/soulteary/grantseal/pkg/license"
)

// P1-1: cache fail-closed --------------------------------------------------

// TestValidateClearsCacheOnFailure asserts that after a successful validation
// populates the cache, a SUBSEQUENT failing validation clears it so a stale
// good decision can never be read back via CachedResult.
func TestValidateClearsCacheOnFailure(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", pub)
	now := time.Now().UTC()
	mgr := newTestManager(ring, license.WithClock(license.FixedClock{T: now}))

	good := issueBytes(t, s, baseRequest())
	if _, err := mgr.Validate(good, license.ValidationContext{}); err != nil {
		t.Fatalf("initial valid: %v", err)
	}
	if _, ok := mgr.CachedResult(); !ok {
		t.Fatal("cache should be populated after a successful validation")
	}

	failures := map[string][]byte{
		"malformed": []byte("{not-json"),
		"empty":     []byte(""),
	}
	for name, data := range failures {
		t.Run(name, func(t *testing.T) {
			// Re-seed a good cache entry before each failure case.
			if _, err := mgr.Validate(good, license.ValidationContext{}); err != nil {
				t.Fatalf("re-seed valid: %v", err)
			}
			if _, ok := mgr.CachedResult(); !ok {
				t.Fatal("cache should be populated before failure case")
			}
			if _, err := mgr.Validate(data, license.ValidationContext{}); err == nil {
				t.Fatalf("%s should fail validation", name)
			}
			if _, ok := mgr.CachedResult(); ok {
				t.Fatalf("%s: cache must be cleared on failure (fail closed)", name)
			}
		})
	}
}

// TestLoadAndValidateEarlyFailuresClearCache asserts the stat/size/read early
// returns in LoadAndValidate clear a previously good cache.
func TestLoadAndValidateEarlyFailuresClearCache(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", pub)
	now := time.Now().UTC()
	mgr := newTestManager(ring, license.WithClock(license.FixedClock{T: now}))
	good := issueBytes(t, s, baseRequest())

	dir := t.TempDir()

	// Missing file.
	if _, err := mgr.Validate(good, license.ValidationContext{}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := mgr.LoadAndValidate(filepath.Join(dir, "missing.json"), license.ValidationContext{}); err == nil {
		t.Fatal("missing file should fail")
	}
	if _, ok := mgr.CachedResult(); ok {
		t.Fatal("missing file must clear cache")
	}

	// Too large.
	if _, err := mgr.Validate(good, license.ValidationContext{}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, make([]byte, license.MaxLicenseFileSize+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.LoadAndValidate(big, license.ValidationContext{}); err == nil {
		t.Fatal("too-large file should fail")
	}
	if _, ok := mgr.CachedResult(); ok {
		t.Fatal("too-large file must clear cache")
	}
}

// TestValidateCacheRaceReadWrite exercises concurrent Validate + CachedResult
// for the race detector (go test -race). It asserts no torn reads/writes.
func TestValidateCacheRaceReadWrite(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", pub)
	now := time.Now().UTC()
	mgr := newTestManager(ring, license.WithClock(license.FixedClock{T: now}))
	good := issueBytes(t, s, baseRequest())
	bad := []byte("{broken")

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if (i+j)%2 == 0 {
					_, _ = mgr.Validate(good, license.ValidationContext{})
				} else {
					_, _ = mgr.Validate(bad, license.ValidationContext{})
				}
				_, _ = mgr.CachedResult()
			}
		}(i)
	}
	wg.Wait()
}

// P2-3: reject future issued_at -------------------------------------------

// TestValidateRejectsFutureIssuedAt asserts issued_at beyond now+skew is
// rejected with CodeNotYetValid, while issued_at exactly at now+skew passes.
func TestValidateRejectsFutureIssuedAt(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", pub)
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	skew := license.DefaultClockSkew
	mgr := newTestManager(ring, license.WithClock(license.FixedClock{T: now}))

	build := func(issued time.Time) []byte {
		req := baseRequest()
		req.IssuedAt = ptr(issued)
		req.ExpiresAt = ptr(issued.Add(365 * 24 * time.Hour))
		return issueBytes(t, s, req)
	}

	tests := []struct {
		name     string
		issued   time.Time
		wantCode license.Code
	}{
		{"past", now.Add(-time.Hour), license.CodeOK},
		{"now", now, license.CodeOK},
		{"at now+skew boundary", now.Add(skew), license.CodeOK},
		{"just past now+skew", now.Add(skew + time.Second), license.CodeNotYetValid},
		{"far future", now.Add(48 * time.Hour), license.CodeNotYetValid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := mgr.Validate(build(tc.issued), license.ValidationContext{})
			if tc.wantCode == license.CodeOK {
				if !res.Valid() {
					t.Fatalf("%s: want valid, got code %s", tc.name, res.Code())
				}
				return
			}
			if res.Code() != tc.wantCode {
				t.Fatalf("%s: want %s, got %s", tc.name, tc.wantCode, res.Code())
			}
		})
	}
}

// P1-4: v2 static invariants always enforced ------------------------------

// craftRevocation builds an authentic (issuer-domain-signed) v2 list after
// mutating a field via `mutate`, so the crafted list is cryptographically valid
// but may be structurally invalid — exercising validateRevocationV2Static.
func craftRevocation(t *testing.T, s *issuer.Signer, mutate func(rl *license.RevocationList)) []byte {
	t.Helper()
	now := time.Now().UTC()
	exp := now.Add(24 * time.Hour)
	rl := &license.RevocationList{
		SchemaVersion: license.RevocationSchemaVersion,
		ListID:        "list-a",
		Sequence:      1,
		IssuedAt:      now,
		ExpiresAt:     &exp,
		KeyID:         "k1",
		RevokedIDs:    []string{"lic_x"},
	}
	mutate(rl)
	canonical, err := license.CanonicalRevocationBytes(rl)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	sig := issuer.SignRevocationBytes(s, canonical)
	env := &license.RevocationEnvelope{
		Algorithm: license.AlgorithmEd25519,
		KeyID:     "k1",
		Payload:   base64.URLEncoding.EncodeToString(canonical),
		Signature: base64.URLEncoding.EncodeToString(sig),
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

// TestRevocationV2StaticEnforcedEvenWithoutFreshness asserts the structural v2
// invariants fail with CodeMalformed even when the caller relaxes freshness.
func TestRevocationV2StaticEnforcedEvenWithoutFreshness(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", pub)
	now := time.Now().UTC()

	tests := []struct {
		name   string
		mutate func(rl *license.RevocationList)
	}{
		{"empty list_id", func(rl *license.RevocationList) { rl.ListID = "" }},
		{"zero sequence", func(rl *license.RevocationList) { rl.Sequence = 0 }},
		{"zero issued_at", func(rl *license.RevocationList) { rl.IssuedAt = time.Time{} }},
		{"nil expires_at", func(rl *license.RevocationList) { rl.ExpiresAt = nil }},
		{"expires<=issued", func(rl *license.RevocationList) {
			before := rl.IssuedAt.Add(-time.Hour)
			rl.ExpiresAt = &before
		}},
	}
	pol := license.RevocationPolicy{}.WithoutFreshness()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := craftRevocation(t, s, tc.mutate)
			if _, err := license.LoadRevocationListWithPolicy(ring, data, now, pol); license.CodeOf(err) != license.CodeMalformed {
				t.Fatalf("%s under WithoutFreshness: want CodeMalformed, got %s", tc.name, license.CodeOf(err))
			}
		})
	}
}

// TestRevocationExpiredArchivePassesUnderWithoutFreshness asserts a
// structurally valid but time-expired archived list is rejected by default and
// accepted under WithoutFreshness (freshness relaxed, structure still valid).
func TestRevocationExpiredArchivePassesUnderWithoutFreshness(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", pub)
	now := time.Now().UTC()

	// Expired window relative to now, but structurally valid.
	expired := revV2(t, s, 1, now.Add(-72*time.Hour), now.Add(-48*time.Hour), "lic_x")

	if _, err := license.LoadRevocationListWithPolicy(ring, expired, now, license.RevocationPolicy{}); license.CodeOf(err) != license.CodeRevocationExpired {
		t.Fatalf("default policy must reject expired archive, got %s", license.CodeOf(err))
	}
	rp, err := license.LoadRevocationListWithPolicy(ring, expired, now, license.RevocationPolicy{}.WithoutFreshness())
	if err != nil {
		t.Fatalf("WithoutFreshness should accept structurally valid archive: %v", err)
	}
	if !rp.IsRevoked("lic_x") {
		t.Fatal("accepted archive should report lic_x revoked")
	}
}
