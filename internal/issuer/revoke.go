package issuer

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/soulteary/grantseal/pkg/license"
)

// BuildRevocationList signs a LEGACY v1 revocation list containing the given
// license IDs. v1 lists carry no sequence/expires_at and are rejected by
// clients unless RevocationPolicy.AllowLegacyV1 is set. New issuers should use
// BuildRevocationListV2.
//
// Deprecated: use BuildRevocationListV2 for replay-resistant lists.
func BuildRevocationList(s *Signer, revokedIDs []string) (*license.RevocationEnvelope, error) {
	if s == nil {
		return nil, fmt.Errorf("issuer: nil signer")
	}
	rl := &license.RevocationList{
		SchemaVersion: 1,
		IssuedAt:      time.Now().UTC(),
		KeyID:         s.KeyID(),
		RevokedIDs:    dedupeNonEmpty(revokedIDs),
	}
	canonical, err := license.CanonicalRevocationBytes(rl)
	if err != nil {
		return nil, fmt.Errorf("issuer: canonical revocation: %w", err)
	}
	// Legacy v1 signs the bare canonical bytes (no domain separation).
	sig := s.SignCanonical(canonical)
	return &license.RevocationEnvelope{
		Algorithm: license.AlgorithmEd25519,
		KeyID:     s.KeyID(),
		Payload:   base64.URLEncoding.EncodeToString(canonical),
		Signature: base64.URLEncoding.EncodeToString(sig),
	}, nil
}

// RevocationListOptions configures a v2 revocation list. ListID is required (a
// logical list identifier that lets independent lists keep separate client
// high-water marks); Sequence must be set (a monotonically increasing
// publication counter); IssuedAt/ExpiresAt define the freshness window
// (ExpiresAt must be after IssuedAt).
type RevocationListOptions struct {
	ListID     string
	Sequence   uint64
	IssuedAt   time.Time
	ExpiresAt  time.Time
	RevokedIDs []string
}

// BuildRevocationListV2 signs a replay-resistant v2 revocation list. The list is
// canonicalized and signed with the revocation signing domain so clients verify
// it against the same public KeyRing and enforce sequence/freshness.
//
// It validates that ListID is non-empty, Sequence > 0, IssuedAt is set, and
// ExpiresAt is after IssuedAt, mirroring the client's acceptance rules so an
// issuer cannot mint a list the client would reject as malformed.
func BuildRevocationListV2(s *Signer, opts RevocationListOptions) (*license.RevocationEnvelope, error) {
	if s == nil {
		return nil, fmt.Errorf("issuer: nil signer")
	}
	if opts.ListID == "" {
		return nil, fmt.Errorf("issuer: revocation list_id required")
	}
	if opts.Sequence == 0 {
		return nil, fmt.Errorf("issuer: revocation sequence must be > 0")
	}
	issued := opts.IssuedAt.UTC()
	if issued.IsZero() {
		return nil, fmt.Errorf("issuer: revocation issued_at required")
	}
	expires := opts.ExpiresAt.UTC()
	if !expires.After(issued) {
		return nil, fmt.Errorf("issuer: revocation expires_at must be after issued_at")
	}
	exp := expires
	rl := &license.RevocationList{
		SchemaVersion: license.RevocationSchemaVersion,
		ListID:        opts.ListID,
		Sequence:      opts.Sequence,
		IssuedAt:      issued,
		ExpiresAt:     &exp,
		KeyID:         s.KeyID(),
		RevokedIDs:    dedupeNonEmpty(opts.RevokedIDs),
	}
	canonical, err := license.CanonicalRevocationBytes(rl)
	if err != nil {
		return nil, fmt.Errorf("issuer: canonical revocation: %w", err)
	}
	sig := SignRevocationBytes(s, canonical)
	return &license.RevocationEnvelope{
		Algorithm: license.AlgorithmEd25519,
		KeyID:     s.KeyID(),
		Payload:   base64.URLEncoding.EncodeToString(canonical),
		Signature: base64.URLEncoding.EncodeToString(sig),
	}, nil
}

func dedupeNonEmpty(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
