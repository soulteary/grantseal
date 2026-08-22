package license_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/soulteary/grantseal/internal/issuer"
	"github.com/soulteary/grantseal/pkg/license"
)

// TestRevocationRequireFreshDefaultsTrue asserts that the zero-value policy and
// a policy that never touches freshness both enforce the v2 issued_at/expires_at
// window (an expired list is rejected).
func TestRevocationRequireFreshDefaultsTrue(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", pub)
	now := time.Now().UTC()
	expired := revV2(t, s, 1, now.Add(-72*time.Hour), now.Add(-48*time.Hour), "lic_x")

	cases := []struct {
		name string
		pol  license.RevocationPolicy
	}{
		{"zero value", license.RevocationPolicy{}},
		{"explicit true", license.RevocationPolicy{RequireFresh: true}},
		// Setting the field to false directly is fail-closed: freshness is still
		// enforced unless WithoutFreshness routed the opt-out.
		{"bare false is fail-closed", license.RevocationPolicy{RequireFresh: false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := license.LoadRevocationListWithPolicy(ring, expired, now, tc.pol); license.CodeOf(err) != license.CodeRevocationExpired {
				t.Fatalf("expected CodeRevocationExpired, got %s", license.CodeOf(err))
			}
		})
	}
}

// TestRevocationWithoutFreshnessRelaxesWindow asserts that WithoutFreshness
// accepts an expired-but-authentic v2 list while still leaving signature and
// anti-replay checks intact.
func TestRevocationWithoutFreshnessRelaxesWindow(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", pub)
	now := time.Now().UTC()
	expired := revV2(t, s, 1, now.Add(-72*time.Hour), now.Add(-48*time.Hour), "lic_x")

	pol := license.RevocationPolicy{}.WithoutFreshness()
	if pol.RequireFresh {
		t.Fatalf("WithoutFreshness must clear RequireFresh")
	}
	rp, err := license.LoadRevocationListWithPolicy(ring, expired, now, pol)
	if err != nil {
		t.Fatalf("WithoutFreshness should accept expired-but-authentic list: %v", err)
	}
	if !rp.IsRevoked("lic_x") {
		t.Fatalf("relaxed list should still report lic_x revoked")
	}

	// Anti-replay still applies under relaxed freshness.
	store := license.NewMemRevocationStateStore()
	replayPol := license.RevocationPolicy{StateStore: store}.WithoutFreshness()
	if _, err := license.LoadRevocationListWithPolicy(ring, revV2(t, s, 5, now, now.Add(24*time.Hour), "lic_a"), now, replayPol); err != nil {
		t.Fatalf("accept seq=5 under relaxed freshness: %v", err)
	}
	if _, err := license.LoadRevocationListWithPolicy(ring, revV2(t, s, 4, now, now.Add(24*time.Hour), "lic_a"), now, replayPol); license.CodeOf(err) != license.CodeRevocationStale {
		t.Fatalf("older sequence must still be stale under relaxed freshness, got %s", license.CodeOf(err))
	}
}

// TestAllowLegacyV1RevocationHelper asserts the AllowLegacyV1Revocation helper is
// equivalent to setting the AllowLegacyV1 field: v1 is accepted with it and
// rejected without it.
func TestAllowLegacyV1RevocationHelper(t *testing.T) {
	s, pub := testKeyPair(t, "k1")
	ring := ringWith(t, "k1", pub)
	now := time.Now().UTC()

	v1env, err := issuer.BuildRevocationList(s, []string{"lic_x"}) //nolint:staticcheck // intentionally builds a legacy v1 list
	if err != nil {
		t.Fatalf("build v1 revocation: %v", err)
	}
	data, err := json.Marshal(v1env)
	if err != nil {
		t.Fatalf("marshal v1 envelope: %v", err)
	}

	// Helper sets the field.
	pol := license.RevocationPolicy{}.AllowLegacyV1Revocation()
	if !pol.AllowLegacyV1 {
		t.Fatalf("AllowLegacyV1Revocation must set AllowLegacyV1")
	}
	rp, aerr := license.LoadRevocationListWithPolicy(ring, data, now, pol)
	if aerr != nil {
		t.Fatalf("v1 with helper opt-in should load: %v", aerr)
	}
	if !rp.IsRevoked("lic_x") {
		t.Fatalf("v1 opt-in list should report lic_x revoked")
	}

	// Without the helper: rejected.
	if _, derr := license.LoadRevocationListWithPolicy(ring, data, now, license.RevocationPolicy{}); license.CodeOf(derr) != license.CodeUnsupportedSchema {
		t.Fatalf("v1 must be rejected without opt-in, got %s", license.CodeOf(derr))
	}
}
