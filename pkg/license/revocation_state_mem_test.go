package license_test

import (
	"testing"
	"time"

	"github.com/soulteary/grantseal/pkg/license"
)

// TestMemRevocationStateStoreSaveNil asserts SaveRevocationState(nil) fails
// closed with CodeRevocationStateIntegrityFailure and stores nothing.
func TestMemRevocationStateStoreSaveNil(t *testing.T) {
	store := license.NewMemRevocationStateStore()
	if err := store.SaveRevocationState(nil); license.CodeOf(err) != license.CodeRevocationStateIntegrityFailure {
		t.Fatalf("nil state: want CodeRevocationStateIntegrityFailure, got %s", license.CodeOf(err))
	}
}

// TestMemRevocationStateStoreSaveRoundTrip covers the SaveRevocationState happy
// path: a saved entry round-trips field-for-field via LoadRevocationState, a
// repeated save for the same list_id overwrites the prior value, and an unsaved
// list_id loads as (nil, nil).
func TestMemRevocationStateStoreSaveRoundTrip(t *testing.T) {
	store := license.NewMemRevocationStateStore()
	issued := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	first := &license.RevocationState{
		ListID:        "list-mem",
		Sequence:      7,
		IssuedAt:      issued,
		PayloadDigest: "deadbeef",
	}
	if err := store.SaveRevocationState(first); err != nil {
		t.Fatalf("save first: %v", err)
	}

	got, err := store.LoadRevocationState("list-mem")
	if err != nil {
		t.Fatalf("load first: %v", err)
	}
	if got == nil {
		t.Fatal("load first: want a state, got nil")
	}
	if got.ListID != first.ListID || got.Sequence != first.Sequence || !got.IssuedAt.Equal(first.IssuedAt) || got.PayloadDigest != first.PayloadDigest {
		t.Fatalf("round-trip mismatch: got %+v want %+v", *got, *first)
	}

	// Re-saving the same list_id with a different sequence/content overwrites
	// the prior value (SaveRevocationState is a plain put, no anti-replay).
	second := &license.RevocationState{
		ListID:        "list-mem",
		Sequence:      3,
		IssuedAt:      issued.Add(time.Hour),
		PayloadDigest: "feedface",
	}
	if err := store.SaveRevocationState(second); err != nil {
		t.Fatalf("save second: %v", err)
	}
	got2, err := store.LoadRevocationState("list-mem")
	if err != nil {
		t.Fatalf("load second: %v", err)
	}
	if got2 == nil {
		t.Fatal("load second: want a state, got nil")
	}
	if got2.Sequence != second.Sequence || !got2.IssuedAt.Equal(second.IssuedAt) || got2.PayloadDigest != second.PayloadDigest {
		t.Fatalf("overwrite mismatch: got %+v want %+v", *got2, *second)
	}

	// An unsaved list_id reads as no-state.
	if st, lerr := store.LoadRevocationState("does-not-exist"); lerr != nil || st != nil {
		t.Fatalf("unknown list_id should be (nil,nil), got st=%v err=%v", st, lerr)
	}
}
