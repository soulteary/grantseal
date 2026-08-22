package license_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/soulteary/grantseal/pkg/license"
)

// makeEntry builds a KeyEntry with a real Ed25519 public key plus a validity
// window, so the deep-copy assertions have non-nil pointer fields to mutate.
func makeEntry(t *testing.T, keyID string) license.KeyEntry {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	nb := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	na := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	return license.KeyEntry{
		KeyID:     keyID,
		PublicKey: pub,
		Enabled:   true,
		NotBefore: &nb,
		NotAfter:  &na,
	}
}

// TestKeyRingAddDeepCopiesInput asserts that mutating the caller's KeyEntry
// after Add (its PublicKey bytes or NotBefore/NotAfter pointers) does not alter
// the entry stored in the ring.
func TestKeyRingAddDeepCopiesInput(t *testing.T) {
	ring := license.NewKeyRing()
	e := makeEntry(t, "k1")
	origByte := e.PublicKey[0]
	origNB := *e.NotBefore
	origNA := *e.NotAfter

	if err := ring.Add(e); err != nil {
		t.Fatalf("add: %v", err)
	}

	// Mutate the caller's copy after Add.
	e.PublicKey[0] ^= 0xFF
	*e.NotBefore = e.NotBefore.Add(48 * time.Hour)
	*e.NotAfter = e.NotAfter.Add(48 * time.Hour)

	got, err := ring.LookupPublicKey("k1")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got.PublicKey[0] != origByte {
		t.Fatalf("ring public key mutated via caller input: got %d want %d", got.PublicKey[0], origByte)
	}
	if !got.NotBefore.Equal(origNB) {
		t.Fatalf("ring NotBefore mutated via caller input: got %v want %v", *got.NotBefore, origNB)
	}
	if !got.NotAfter.Equal(origNA) {
		t.Fatalf("ring NotAfter mutated via caller input: got %v want %v", *got.NotAfter, origNA)
	}
}

// TestKeyRingLookupReturnsDeepCopy asserts that mutating the entry returned by
// LookupPublicKey / Lookup cannot corrupt the ring's internal state.
func TestKeyRingLookupReturnsDeepCopy(t *testing.T) {
	ring := license.NewKeyRing()
	e := makeEntry(t, "k1")
	if err := ring.Add(e); err != nil {
		t.Fatalf("add: %v", err)
	}

	first, err := ring.LookupPublicKey("k1")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	origByte := first.PublicKey[0]
	origNB := *first.NotBefore
	origNA := *first.NotAfter

	// Mutate the returned entry aggressively.
	first.PublicKey[0] ^= 0xFF
	*first.NotBefore = first.NotBefore.Add(72 * time.Hour)
	*first.NotAfter = first.NotAfter.Add(72 * time.Hour)

	second, err := ring.LookupPublicKey("k1")
	if err != nil {
		t.Fatalf("second lookup: %v", err)
	}
	if second.PublicKey[0] != origByte {
		t.Fatalf("ring public key mutated via returned entry: got %d want %d", second.PublicKey[0], origByte)
	}
	if !second.NotBefore.Equal(origNB) {
		t.Fatalf("ring NotBefore mutated via returned entry: got %v want %v", *second.NotBefore, origNB)
	}
	if !second.NotAfter.Equal(origNA) {
		t.Fatalf("ring NotAfter mutated via returned entry: got %v want %v", *second.NotAfter, origNA)
	}

	// The now-based Lookup path must also return a decoupled copy.
	within := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	third, err := ring.Lookup("k1", within)
	if err != nil {
		t.Fatalf("Lookup within window: %v", err)
	}
	third.PublicKey[0] ^= 0xFF
	fourth, err := ring.Lookup("k1", within)
	if err != nil {
		t.Fatalf("Lookup within window (2): %v", err)
	}
	if fourth.PublicKey[0] != origByte {
		t.Fatalf("ring mutated via Lookup return: got %d want %d", fourth.PublicKey[0], origByte)
	}
}

// TestKeyRingCloneRaceUsage exercises concurrent Add/Lookup to prove the deep
// copy keeps the ring race-free (run under go test -race).
func TestKeyRingCloneRaceUsage(t *testing.T) {
	ring := license.NewKeyRing()
	if err := ring.Add(makeEntry(t, "k1")); err != nil {
		t.Fatalf("add: %v", err)
	}
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 200; j++ {
				if e, err := ring.LookupPublicKey("k1"); err == nil && len(e.PublicKey) > 0 {
					e.PublicKey[0] ^= 0xFF // mutate the returned copy only
				}
				_ = ring.Add(makeEntry(t, "k1"))
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}
