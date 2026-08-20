package issuer

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/soulteary/grantseal/pkg/license"
)

// BuildRevocationList signs a revocation list containing the given license IDs.
// The list is canonicalized and signed exactly like a license so clients verify
// it against the same public KeyRing before trusting it.
func BuildRevocationList(s *Signer, revokedIDs []string) (*license.RevocationEnvelope, error) {
	if s == nil {
		return nil, fmt.Errorf("issuer: nil signer")
	}
	rl := &license.RevocationList{
		SchemaVersion: license.SchemaVersion,
		IssuedAt:      time.Now().UTC(),
		KeyID:         s.KeyID(),
		RevokedIDs:    dedupeNonEmpty(revokedIDs),
	}
	canonical, err := license.CanonicalRevocationBytes(rl)
	if err != nil {
		return nil, fmt.Errorf("issuer: canonical revocation: %w", err)
	}
	sig := s.SignCanonical(canonical)
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
