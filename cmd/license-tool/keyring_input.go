package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/soulteary/grantseal/pkg/license"
)

// keyringFileEntry is one key in a -keyring JSON file. It mirrors the fields of
// license.KeyEntry that make sense on disk: the public key is a Base64URL
// string (never a private key), enabled/revoked are lifecycle kill switches,
// and not_before/not_after bound the issuance window (RFC3339, optional).
//
// enabled defaults to true when omitted so a minimal `{"key_id","public_key"}`
// entry behaves like the single-key AddPublicKeyBase64 path. Set it explicitly
// to false to model a disabled key.
type keyringFileEntry struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Enabled   *bool  `json:"enabled,omitempty"`
	Revoked   bool   `json:"revoked,omitempty"`
	NotBefore string `json:"not_before,omitempty"`
	NotAfter  string `json:"not_after,omitempty"`
}

// keyringFile is the top-level schema of a -keyring JSON file.
type keyringFile struct {
	Keys []keyringFileEntry `json:"keys"`
}

// pubkeyFlags collects repeated -pubkey values so both the legacy single
// `-pubkey path` form and the new `-pubkey keyID=path` form can be supplied
// (repeatable). Each raw value is stored verbatim and interpreted later once
// the license's key_id is known (the bare form derives its key_id from the
// license/-key-id flag, exactly as before).
type pubkeyFlags struct {
	values []string
}

func (p *pubkeyFlags) String() string { return strings.Join(p.values, ",") }

func (p *pubkeyFlags) Set(v string) error {
	p.values = append(p.values, v)
	return nil
}

// pubkeySpec is a parsed -pubkey value: an explicit keyID (empty for the bare
// `-pubkey path` form) and the file path.
type pubkeySpec struct {
	keyID string
	path  string
}

// parsePubkeyValue splits a -pubkey value into an optional keyID and a path.
// The keyID=path form binds the key to a specific key_id; the bare path form
// leaves keyID empty (the caller resolves it from the license/-key-id, matching
// the historical single-key behavior). A leading `keyID=` with an empty path,
// or an empty keyID before `=`, is rejected as a usage error.
func parsePubkeyValue(v string) (pubkeySpec, error) {
	// Only treat the FIRST '=' as the separator so a path containing '=' still
	// works in the bare form is not misparsed: the keyID form requires a
	// non-empty, path-free identifier before the '='.
	if i := strings.IndexByte(v, '='); i >= 0 {
		keyID := v[:i]
		path := v[i+1:]
		// A value like "/a=b/c" is a path, not a keyID: a real keyID has no
		// path separators. Fall through to bare-path handling in that case.
		if keyID != "" && !strings.ContainsAny(keyID, "/\\") {
			if path == "" {
				return pubkeySpec{}, usageErrorf("verify: -pubkey %q has an empty path (want keyID=path)", v)
			}
			return pubkeySpec{keyID: keyID, path: path}, nil
		}
	}
	if v == "" {
		return pubkeySpec{}, usageErrorf("verify: empty -pubkey value")
	}
	return pubkeySpec{path: v}, nil
}

// buildVerifyKeyRing assembles the verification key ring from the repeatable
// -pubkey flags and an optional -keyring file. It is additive over the legacy
// single-key behavior:
//   - a single bare `-pubkey path` (no -keyring) reproduces the old flow: the
//     key is added under defaultKeyID (derived from the license/-key-id).
//   - `-pubkey keyID=path` (repeatable) and/or `-keyring file` populate a
//     multi-key ring.
//
// A duplicate key_id (same id supplied twice across any source) is rejected as
// a usage error so an ambiguous ring can never silently shadow a key.
func buildVerifyKeyRing(pubkeys []string, keyringPath, defaultKeyID string) (*license.KeyRing, error) {
	ring := license.NewKeyRing()
	seen := make(map[string]struct{})

	addEntry := func(e license.KeyEntry) error {
		if _, dup := seen[e.KeyID]; dup {
			return usageErrorf("verify: duplicate key_id %q in keyring input", e.KeyID)
		}
		if err := ring.Add(e); err != nil {
			return err
		}
		seen[e.KeyID] = struct{}{}
		return nil
	}

	for _, raw := range pubkeys {
		spec, err := parsePubkeyValue(raw)
		if err != nil {
			return nil, err
		}
		pubB64, err := readPublicKeyFile(spec.path)
		if err != nil {
			return nil, err
		}
		kid := spec.keyID
		if kid == "" {
			kid = defaultKeyID
			if kid == "" {
				return nil, usageErrorf("verify: cannot derive key_id for -pubkey %q (pass keyID=path or -key-id)", spec.path)
			}
		}
		pub, err := decodePublicKeyBase64(pubB64)
		if err != nil {
			return nil, err
		}
		if err := addEntry(license.KeyEntry{KeyID: kid, PublicKey: pub, Enabled: true}); err != nil {
			return nil, err
		}
	}

	if keyringPath != "" {
		entries, err := loadKeyringFile(keyringPath)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if err := addEntry(e); err != nil {
				return nil, err
			}
		}
	}

	if len(ring.KeyIDs()) == 0 {
		return nil, usageErrorf("verify: no verification keys provided (-pubkey and/or -keyring)")
	}
	return ring, nil
}

// loadKeyringFile reads and decodes a -keyring JSON file into KeyEntry values,
// validating each entry (non-empty key_id, decodable Base64URL public key,
// RFC3339 windows). It uses the same bounded, strict-JSON reader as the rest of
// the CLI so an oversized or malformed keyring is rejected before use.
func loadKeyringFile(path string) ([]license.KeyEntry, error) {
	data, err := readFileBounded(path, "keyring", license.MaxLicenseFileSize)
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}
	var kf keyringFile
	if derr := license.DecodeStrictJSON(data, &kf, license.MaxLicenseFileSize); derr != nil {
		return nil, &usageError{msg: "verify: parse keyring", err: derr}
	}
	if len(kf.Keys) == 0 {
		return nil, usageErrorf("verify: keyring %q contains no keys", path)
	}
	out := make([]license.KeyEntry, 0, len(kf.Keys))
	for i, fe := range kf.Keys {
		if fe.KeyID == "" {
			return nil, usageErrorf("verify: keyring entry %d has an empty key_id", i)
		}
		pub, derr := decodePublicKeyBase64(fe.PublicKey)
		if derr != nil {
			return nil, fmt.Errorf("verify: keyring key %q: %w", fe.KeyID, derr)
		}
		nb, derr := parseOptTime(fe.NotBefore)
		if derr != nil {
			return nil, &usageError{msg: fmt.Sprintf("verify: keyring key %q not_before", fe.KeyID), err: derr}
		}
		na, derr := parseOptTime(fe.NotAfter)
		if derr != nil {
			return nil, &usageError{msg: fmt.Sprintf("verify: keyring key %q not_after", fe.KeyID), err: derr}
		}
		enabled := true
		if fe.Enabled != nil {
			enabled = *fe.Enabled
		}
		out = append(out, license.KeyEntry{
			KeyID:     fe.KeyID,
			PublicKey: pub,
			Enabled:   enabled,
			Revoked:   fe.Revoked,
			NotBefore: nb,
			NotAfter:  na,
		})
	}
	return out, nil
}

// verifyRevocationKeyRing builds the key ring used to authenticate a revocation
// list. When -revocation-keyring is set it is loaded independently (revocation
// lists may be signed by a different key than licenses); otherwise the license
// verification ring is reused so the prior single-key behavior is preserved.
func verifyRevocationKeyRing(licenseRing *license.KeyRing, revocationKeyringPath string) (*license.KeyRing, error) {
	if revocationKeyringPath == "" {
		return licenseRing, nil
	}
	entries, err := loadKeyringFile(revocationKeyringPath)
	if err != nil {
		return nil, err
	}
	ring := license.NewKeyRing()
	seen := make(map[string]struct{})
	for _, e := range entries {
		if _, dup := seen[e.KeyID]; dup {
			return nil, usageErrorf("verify: duplicate key_id %q in revocation keyring", e.KeyID)
		}
		if aerr := ring.Add(e); aerr != nil {
			return nil, aerr
		}
		seen[e.KeyID] = struct{}{}
	}
	return ring, nil
}

// decodePublicKeyBase64 strictly decodes a Base64URL-encoded Ed25519 public key
// and validates its length. It mirrors KeyRing.AddPublicKeyBase64's strict
// URL-alphabet decoding but returns the raw key so callers can build a
// KeyEntry with additional lifecycle fields (revoked/window).
func decodePublicKeyBase64(encoded string) (ed25519.PublicKey, error) {
	b, err := base64.URLEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("invalid base64 public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key size (%d bytes)", len(b))
	}
	return ed25519.PublicKey(b), nil
}
