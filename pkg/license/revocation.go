package license

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"
)

// RevocationProvider reports whether a given license_id has been revoked. It is
// consulted during validation; a nil provider means "nothing revoked".
type RevocationProvider interface {
	IsRevoked(licenseID string) bool
}

// RevocationList is the signed body of an offline revocation list. It is
// authenticated exactly like a license: canonicalized, signed with the issuer's
// Ed25519 private key (revocation signing domain), and verified client-side
// against the KeyRing.
//
// Schema v2 adds replay-resistance metadata over the legacy v1 shape:
//   - Sequence: a monotonically increasing publication counter. Clients keep a
//     local high-water mark and reject any list with a lower sequence (replay).
//   - ExpiresAt: the instant after which this distribution is considered too
//     stale to trust (defense against indefinitely serving an old list).
//   - ListID: a stable identifier for the logical list, allowing multiple
//     independent lists to keep separate high-water marks.
//
// v1 lists (SchemaVersion == 1, no sequence/expires_at) are rejected by default
// and only accepted via RevocationPolicy.AllowLegacyV1 (or, more legibly, the
// RevocationPolicy.AllowLegacyV1Revocation helper).
type RevocationList struct {
	SchemaVersion int        `json:"schema_version"`
	ListID        string     `json:"list_id,omitempty"`
	Sequence      uint64     `json:"sequence,omitempty"`
	IssuedAt      time.Time  `json:"issued_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	KeyID         string     `json:"key_id"`
	RevokedIDs    []string   `json:"revoked_license_ids"`
}

// RevocationEnvelope wraps a signed revocation list on the wire.
type RevocationEnvelope struct {
	Algorithm Algorithm `json:"algorithm"`
	KeyID     string    `json:"key_id"`
	Payload   string    `json:"payload"`   // Base64URL(canonical revocation list)
	Signature string    `json:"signature"` // Base64URL(ed25519 signature)
}

// signedRevocation is the concrete RevocationProvider produced after verifying
// a RevocationEnvelope. Its lookup set is immutable after construction.
type signedRevocation struct {
	set map[string]struct{}
}

// IsRevoked reports whether licenseID is present in the verified list.
func (s *signedRevocation) IsRevoked(licenseID string) bool {
	if s == nil {
		return false
	}
	_, ok := s.set[licenseID]
	return ok
}

// CanonicalRevocationBytes returns the deterministic canonical bytes of a
// revocation list, used by issuers for signing and by the client for
// verification.
func CanonicalRevocationBytes(rl *RevocationList) ([]byte, error) { return canonicalRevocation(rl) }

// canonicalRevocation returns deterministic bytes for signing/verification.
func canonicalRevocation(rl *RevocationList) ([]byte, error) {
	raw, err := json.Marshal(rl)
	if err != nil {
		return nil, newError(CodeMalformed, "marshal revocation list", err)
	}
	var tree any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&tree); err != nil {
		return nil, newError(CodeMalformed, "decode revocation tree", err)
	}
	var buf bytes.Buffer
	if err := encodeCanonical(&buf, tree); err != nil {
		return nil, newError(CodeMalformed, "encode canonical revocation", err)
	}
	return buf.Bytes(), nil
}

// ParseRevocationEnvelope decodes a revocation envelope from JSON.
func ParseRevocationEnvelope(data []byte) (*RevocationEnvelope, error) {
	if len(data) == 0 {
		return nil, newError(CodeMalformed, "empty revocation data", nil)
	}
	if len(data) > MaxRevocationFileSize {
		return nil, newError(CodeFileTooLarge, "revocation data exceeds size cap", nil)
	}
	var env RevocationEnvelope
	if err := decodeStrictJSON(data, &env, MaxRevocationFileSize); err != nil {
		return nil, err
	}
	if env.Algorithm == "" || env.KeyID == "" || env.Payload == "" || env.Signature == "" {
		return nil, newError(CodeMalformed, "revocation envelope missing fields", nil)
	}
	return &env, nil
}

// RevocationPolicy configures how a revocation list is accepted. The zero value
// is safe and strict: v2 freshness (issued_at/expires_at) is enforced, v1 lists
// are rejected, and MaxAge/ClockSkew fall back to sane defaults.
type RevocationPolicy struct {
	// ClockSkew tolerates minor clock drift when checking issued_at/expires_at.
	// Non-positive uses DefaultClockSkew.
	ClockSkew time.Duration
	// MaxAge, when > 0, additionally rejects a list whose issued_at is older
	// than now-MaxAge even if it has not reached expires_at. Zero disables the
	// extra age bound (expires_at is still enforced).
	MaxAge time.Duration
	// StateStore, when set, enables local high-water anti-replay: the accepted
	// sequence/digest is persisted and future lists must not regress.
	StateStore RevocationStateStore
	// AllowLegacyV1 opts INTO accepting legacy v1 revocation lists (no
	// sequence/expires_at, no replay resistance). Default false: v1 is rejected
	// with CodeUnsupportedSchema. Only enable for migration windows. Prefer the
	// AllowLegacyV1Revocation constructor helper for a self-documenting call site.
	AllowLegacyV1 bool
	// RequireFresh reports whether the v2 issued_at/expires_at freshness window
	// is enforced. The production default is true, and the zero value of
	// RevocationPolicy resolves to true, so freshness is enforced unless a caller
	// explicitly relaxes it via WithoutFreshness (e.g. offline replay of an
	// archived list). Setting this field to false directly is fail-closed and
	// does NOT by itself disable freshness — use WithoutFreshness for the
	// deliberate opt-out, which also sets this field to false so it mirrors the
	// resolved value. Relaxing freshness never disables signature authenticity or
	// anti-replay state checks.
	RequireFresh bool

	// relaxFresh, when true, means the caller explicitly opted out of freshness.
	// It exists because a plain bool cannot distinguish "unset" (which must
	// resolve to the strict default true) from "explicitly false"; the exported
	// RequireFresh field mirrors the resolved value.
	relaxFresh bool
}

func (p RevocationPolicy) skew() time.Duration {
	if p.ClockSkew > 0 {
		return p.ClockSkew
	}
	return DefaultClockSkew
}

// requireFresh resolves whether the v2 freshness window must be enforced. It is
// fail-closed: freshness is required unless the caller explicitly relaxed it via
// RevocationPolicy{RequireFresh: false, ...} routed through a relaxing helper, so
// the zero value and any policy that does not touch freshness stays strict.
func (p RevocationPolicy) requireFresh() bool {
	return !p.relaxFresh
}

// AllowLegacyV1Revocation returns a copy of the policy that opts INTO accepting
// legacy v1 revocation lists (no sequence/expires_at, no replay resistance).
// This is the self-documenting equivalent of setting RevocationPolicy.AllowLegacyV1
// to true, intended for explicit migration windows. It is fail-closed by
// default: without this opt-in a v1 list is rejected with CodeUnsupportedSchema.
func (p RevocationPolicy) AllowLegacyV1Revocation() RevocationPolicy {
	p.AllowLegacyV1 = true
	return p
}

// WithoutFreshness returns a copy of the policy with the v2 freshness window
// (issued_at/expires_at) disabled. Use it only for deliberate offline replay of
// an archived list; signature authenticity and anti-replay state checks still
// apply. The default policy enforces freshness.
func (p RevocationPolicy) WithoutFreshness() RevocationPolicy {
	p.relaxFresh = true
	p.RequireFresh = false
	return p
}

// RevocationState is the local anti-replay high-water record for a logical
// revocation list. It records the highest accepted sequence, that list's
// issued_at, and a digest of the accepted canonical payload so a reused
// sequence with different content is detected.
type RevocationState struct {
	ListID        string    `json:"list_id"`
	Sequence      uint64    `json:"sequence"`
	IssuedAt      time.Time `json:"issued_at"`
	PayloadDigest string    `json:"payload_digest"` // hex(sha256(canonical))
}

// RevocationStateStore persists the anti-replay high-water mark for revocation
// lists. Implementations must be safe for concurrent use. Load returns
// (nil, nil) when no prior state exists for the given ListID.
type RevocationStateStore interface {
	// LoadRevocationState returns the stored state for listID, or (nil, nil) if
	// none exists. A corrupt/tampered store returns
	// CodeRevocationStateIntegrityFailure.
	LoadRevocationState(listID string) (*RevocationState, error)
	// SaveRevocationState atomically persists st (keyed by st.ListID).
	SaveRevocationState(st *RevocationState) error
}

// LoadRevocationList verifies a revocation envelope against the ring and returns
// a RevocationProvider using the default strict policy: v2 required, v1
// rejected, no local state store. Signature verification uses the revocation
// signing domain and canonical-equality checks. For replay resistance or v1
// opt-in, use LoadRevocationListWithPolicy.
func LoadRevocationList(ring *KeyRing, data []byte, now time.Time) (RevocationProvider, error) {
	return LoadRevocationListWithPolicy(ring, data, now, RevocationPolicy{RequireFresh: true})
}

// LoadRevocationListWithPolicy verifies a revocation envelope and applies the
// given policy (freshness, anti-replay state, v1 opt-in). On success it returns
// a RevocationProvider whose membership set is the verified list, and (when a
// StateStore is configured) advances the local high-water mark.
//
// Acceptance conditions for a v2 list:
//   - Ed25519 signature valid over the revocation signing domain + canonical
//     bytes, key known/enabled/in-window.
//   - Carried bytes are exactly canonical (no ambiguity).
//   - schema_version == RevocationSchemaVersion, key_id matches envelope,
//     expires_at present and after issued_at.
//   - issued_at <= now + skew (not from the future).
//   - now <= expires_at + skew (not expired); and, when MaxAge > 0,
//     issued_at >= now - MaxAge.
//   - With a StateStore: sequence >= stored high-water; a reused sequence must
//     carry the same payload digest; on success the high-water mark is advanced.
func LoadRevocationListWithPolicy(ring *KeyRing, data []byte, now time.Time, pol RevocationPolicy) (RevocationProvider, error) {
	// Resolve the exported RequireFresh field to the value actually enforced so
	// it never misreports (fail-closed: only WithoutFreshness relaxes it).
	pol.RequireFresh = pol.requireFresh()
	now = now.UTC()
	env, err := ParseRevocationEnvelope(data)
	if err != nil {
		return nil, err
	}
	if !env.Algorithm.Valid() {
		return nil, newError(CodeUnsupportedAlgorithm, "unsupported algorithm "+string(env.Algorithm), nil)
	}
	entry, err := ring.Lookup(env.KeyID, now)
	if err != nil {
		return nil, err
	}
	canonical, err := base64.URLEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, newError(CodeMalformed, "invalid base64 revocation payload", err)
	}
	sig, err := base64.URLEncoding.DecodeString(env.Signature)
	if err != nil {
		return nil, newError(CodeMalformed, "invalid base64 revocation signature", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, newError(CodeSignatureInvalid, "bad revocation signature length", nil)
	}

	rl, legacySigned, err := verifyRevocationSignature(entry.PublicKey, canonical, sig, env.KeyID)
	if err != nil {
		return nil, err
	}

	// Legacy v1: only proceed when explicitly opted in. v1 carries no
	// freshness/replay metadata, so freshness and anti-replay are skipped.
	if rl.SchemaVersion == 1 {
		if !pol.AllowLegacyV1 {
			return nil, newError(CodeUnsupportedSchema, "legacy v1 revocation list rejected (enable RevocationPolicy.AllowLegacyV1 to accept)", nil)
		}
		return buildProvider(rl)
	}

	// A v2 list MUST be signed with the v2 domain, never the legacy bare-bytes
	// input. Reject a v2-schema payload that only verified as legacy.
	if legacySigned {
		return nil, newError(CodeSignatureInvalid, "v2 revocation must use domain-separated signature", nil)
	}

	if pol.requireFresh() {
		if err := checkRevocationFreshness(rl, now, pol); err != nil {
			return nil, err
		}
	}
	if err := checkRevocationReplay(rl, canonical, pol); err != nil {
		return nil, err
	}
	return buildProvider(rl)
}

// verifyRevocationSignature checks the Ed25519 signature, decodes the list, and
// enforces canonical equality plus structural field checks common to both
// schema versions. It reports whether the signature verified only against the
// legacy (undomained) input so the caller can enforce that v2 payloads use
// domain separation. Trying both inputs here lets the schema-version policy be
// enforced AFTER authentication (a legitimately-signed v1 list is reported as
// CodeUnsupportedSchema rather than a signature error when not opted in).
func verifyRevocationSignature(pub ed25519.PublicKey, canonical, sig []byte, envKeyID string) (*RevocationList, bool, error) {
	legacySigned := false
	if !ed25519.Verify(pub, revocationSigningInput(canonical), sig) {
		if !ed25519.Verify(pub, canonical, sig) {
			return nil, false, newError(CodeSignatureInvalid, "revocation signature does not match", nil)
		}
		legacySigned = true
	}

	var rl RevocationList
	dec := json.NewDecoder(bytes.NewReader(canonical))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rl); err != nil {
		return nil, false, newError(CodeMalformed, "decode revocation list", err)
	}
	// Canonical equality: re-encode and constant-time compare so the carried
	// bytes are unambiguously the canonical form of the decoded list.
	recanon, err := canonicalRevocation(&rl)
	if err != nil {
		return nil, false, err
	}
	if subtle.ConstantTimeCompare(recanon, canonical) != 1 {
		return nil, false, newError(CodeNonCanonicalPayload, "revocation payload bytes are not canonical", nil)
	}
	if rl.SchemaVersion != RevocationSchemaVersion && rl.SchemaVersion != 1 {
		return nil, false, newError(CodeUnsupportedSchema, "unsupported revocation schema", nil)
	}
	if rl.KeyID != envKeyID {
		return nil, false, newError(CodeKeyIDMismatch, "revocation payload key_id mismatch", nil)
	}
	if len(rl.RevokedIDs) > MaxRevokedIDs {
		return nil, false, newError(CodeFileTooLarge, "revocation list exceeds entry cap", nil)
	}
	return &rl, legacySigned, nil
}

// checkRevocationFreshness enforces the issued_at/expires_at time window for a
// v2 list.
func checkRevocationFreshness(rl *RevocationList, now time.Time, pol RevocationPolicy) error {
	if rl.ExpiresAt == nil {
		return newError(CodeMalformed, "v2 revocation list requires expires_at", nil)
	}
	if rl.IssuedAt.IsZero() {
		return newError(CodeMalformed, "v2 revocation list requires issued_at", nil)
	}
	if !rl.ExpiresAt.After(rl.IssuedAt) {
		return newError(CodeMalformed, "revocation expires_at must be after issued_at", nil)
	}
	skew := pol.skew()
	if rl.IssuedAt.After(now.Add(skew)) {
		return newError(CodeRevocationFromFuture, "revocation list issued in the future", nil)
	}
	if now.After(rl.ExpiresAt.Add(skew)) {
		return newError(CodeRevocationExpired, "revocation list has expired", nil)
	}
	if pol.MaxAge > 0 && rl.IssuedAt.Before(now.Add(-pol.MaxAge)) {
		return newError(CodeRevocationExpired, "revocation list older than MaxAge", nil)
	}
	return nil
}

// checkRevocationReplay enforces the local high-water anti-replay contract when
// a StateStore is configured, and advances the mark on success.
func checkRevocationReplay(rl *RevocationList, canonical []byte, pol RevocationPolicy) error {
	if pol.StateStore == nil {
		return nil
	}
	prev, err := pol.StateStore.LoadRevocationState(rl.ListID)
	if err != nil {
		return err
	}
	digest := hex.EncodeToString(sha256Sum(canonical))
	if prev != nil {
		if rl.Sequence < prev.Sequence {
			return newError(CodeRevocationStale, "revocation sequence older than last accepted", nil)
		}
		if rl.Sequence == prev.Sequence && prev.PayloadDigest != digest {
			return newError(CodeRevocationRollback, "revocation sequence reused with different content", nil)
		}
	}
	return pol.StateStore.SaveRevocationState(&RevocationState{
		ListID:        rl.ListID,
		Sequence:      rl.Sequence,
		IssuedAt:      rl.IssuedAt,
		PayloadDigest: digest,
	})
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// buildProvider constructs the immutable membership provider from a verified list.
func buildProvider(rl *RevocationList) (RevocationProvider, error) {
	set := make(map[string]struct{}, len(rl.RevokedIDs))
	for _, id := range rl.RevokedIDs {
		if id != "" {
			set[id] = struct{}{}
		}
	}
	return &signedRevocation{set: set}, nil
}

// StaticRevocation is a simple in-memory RevocationProvider for tests/embedding.
type StaticRevocation struct{ IDs map[string]struct{} }

// NewStaticRevocation builds a StaticRevocation from a list of license IDs.
func NewStaticRevocation(ids ...string) *StaticRevocation {
	m := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		m[id] = struct{}{}
	}
	return &StaticRevocation{IDs: m}
}

// IsRevoked reports membership in the static set.
func (s *StaticRevocation) IsRevoked(licenseID string) bool {
	if s == nil {
		return false
	}
	_, ok := s.IDs[licenseID]
	return ok
}
