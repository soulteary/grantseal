# grantseal — Offline Software Licensing (English)

grantseal is a commercial-grade offline software licensing system built with
Go 1.26 and **only the standard library**. It issues, verifies, and manages
Ed25519-signed licenses with device binding, feature/limit gating, expiry with
grace periods, clock-rollback detection, and signed revocation lists.

## Architecture

```
pkg/license/       client-side verification (public keys only, fail-closed)
pkg/fingerprint/   cross-platform device fingerprint
internal/issuer/   issuer-side signing (private keys; unimportable by clients)
cmd/license-tool/  issuer CLI
examples/          client integration + batch-issue config
```

The Go `internal/` mechanism guarantees a client that imports `pkg/license`
cannot import `internal/issuer`, so private-key logic never links into a client
binary.

## Data model (`pkg/license.Payload`)

| Field                | Notes                                                      |
| -------------------- | ---------------------------------------------------------- |
| `schema_version`     | Only `1` is accepted; unknown versions rejected.           |
| `license_id`         | Unique, crypto-random when issued.                         |
| `serial_number`      | Human-friendly grouped serial.                             |
| `product_id`         | Must match the client's product when provided.             |
| `customer_id/name`   | Customer identity.                                         |
| `edition`            | `trial`/`basic`/`professional`/`enterprise` (whitelist).   |
| `license_type`       | `trial`/`subscription`/`lifetime` (whitelist). `trial` and `subscription` **require** `expires_at`; `lifetime` **must not** carry `expires_at` and never expires. |
| `issued_at`          | RFC3339 UTC. Must not be later than `expires_at`; `not_before` must not precede it. |
| `not_before`         | Optional activation time.                                  |
| `expires_at`         | Required for `trial`/`subscription`; absent (perpetual) for `lifetime`. |
| `grace_period_days`  | 0–3650; extends usability past expiry.                     |
| `features`           | Unioned with edition defaults.                             |
| `limits`             | Range-validated non-negative integers.                     |
| `device_binding`     | `none`/`single`/`multi` + device fingerprint list.         |
| `version_constraint` | `min/max_version` + `maintenance_until` + `covered_max_version`. While `maintenance_until` is active all in-range versions are covered. After it lapses, only versions `<= covered_max_version` remain covered; newer builds are rejected as `LICENSE_VERSION_UNSUPPORTED`. Licenses without `covered_max_version` fall back to the legacy behavior (versions strictly newer than `min_version`, the maintained baseline, are not covered; if `min_version` is also empty the gate is skipped). **Fail-closed:** if the license declares any version constraint but the caller supplies no running version — or a running version that cannot be parsed — validation is rejected with `LICENSE_VERSION_UNSUPPORTED`. Callers must pass `ProductVersion` whenever a version constraint may be present. |
| `metadata`           | Free-form string map.                                      |
| `key_id`             | Must match the signing key and envelope.                   |

Signatures cover the deterministic **canonical** (sorted-key) JSON of the
payload. The wire format is an `Envelope{algorithm,key_id,payload,signature}`
where `payload` and `signature` are Base64URL. Public and private key files are
parsed as **URL-safe Base64 only** (`AddPublicKeyBase64` / `DecodePrivateKey`);
standard-alphabet Base64 (with `+`/`/`) is rejected to avoid ambiguous parsing.

## Verification flow

1. Read file (≤ 64 KiB) → 2. parse envelope → 3. check algorithm `Ed25519` →
4. resolve `key_id` in the ring (enabled/not revoked/in window) →
5. verify signature over canonical payload → 6. check payload `key_id` and
schema → **7. anti-rollback (state loaded/checked/saved only *after* the
signature is proven authentic, so forged input cannot pollute the trusted-time
high-water mark)** → 8. enum whitelist + `license_type` time semantics →
9. revocation → 10. time (not_before / expiry / grace) → 11. device binding →
12. product/version → 13. return a **read-only** `ValidationResult`.

If the anti-rollback state file is corrupt, the policy is fail-closed by
`license_type`: `trial`/`subscription` are rejected
(`LICENSE_STATE_INTEGRITY_FAILURE`), while `lifetime` (time-independent) is
tolerated and reset. Any failure is **fail-closed** with a stable `LICENSE_*`
code; malformed input returns an error and **never panics**.

## CLI usage

```bash
# Generate a key pair (private key stays local, mode 0600)
go run ./cmd/license-tool keygen -key-id k1 -out-dir ./keys

# Print the public key from a private key
go run ./cmd/license-tool public-key -key ./keys/k1-private.key

# Issue a license from JSON config
go run ./cmd/license-tool issue -config examples/issue-config.json \
  -key ./keys/k1-private.key -out customer.lic

# Verify + policy-validate (client-side)
go run ./cmd/license-tool verify -license customer.lic -pubkey ./keys/k1-public.key \
  -product acme-app -version 1.4.0

# Inspect (signature only, no policy checks) — diagnostics only
go run ./cmd/license-tool inspect -license customer.lic -pubkey ./keys/k1-public.key

# Device fingerprint / request code
go run ./cmd/license-tool fingerprint -namespace acme-app -json
go run ./cmd/license-tool fingerprint -namespace acme-app -request-code

# Build a signed revocation list
go run ./cmd/license-tool revoke-list -key ./keys/k1-private.key -key-id k1 \
  -ids lic_abc,lic_def -out revoked.json
```

## Client integration (library)

```go
ring := license.NewKeyRing()
_ = ring.AddPublicKeyBase64("k1", embeddedPublicKeyB64)

mgr := license.NewManager(ring)
res, err := mgr.LoadAndValidate("customer.lic", license.ValidationContext{
    ProductID:      "acme-app",
    ProductVersion: "1.4.0",
})
if err != nil {
    // license.CodeOf(err) yields a stable LICENSE_* code for UX
    return
}

// Read-only result facade for gating:
if err := res.RequireFeature("api"); err != nil {
    // license.CodeOf(err) == license.CodeFeatureDenied ("LICENSE_FEATURE_DENIED")
}
if err := res.CheckLimit("max_seats", seatsInUse); err != nil {
    // license.CodeOf(err) == license.CodeLimitExceeded ("LICENSE_LIMIT_EXCEEDED")
    // Note: an undeclared limit key is treated as UNLIMITED (returns nil).
}
_ = res.GetEdition()        // Edition
_ = res.GetExpiration()     // *time.Time (nil for lifetime)
_ = res.GetRemainingDays()  // -1 (license.PerpetualRemainingDays) for lifetime
_ = res.RemainingTime()     // time.Duration
_ = res.KeyID()             // verified signing key id
_ = res.DeviceMatched()     // device binding satisfied?
```

### Result facade & error codes

`ValidationResult` is read-only. Prefer the facade helpers over inspecting raw
fields:

- `RequireFeature(name) error` — returns `CodeFeatureDenied`
  (`LICENSE_FEATURE_DENIED`) when a feature is not granted.
- `CheckLimit(key, current) error` — returns `CodeLimitExceeded`
  (`LICENSE_LIMIT_EXCEEDED`) when exceeded. A key that the license does not
  declare is treated as **unlimited**.
- `GetLimit`, `GetEdition`, `GetExpiration`, `GetRemainingDays` (returns `-1`
  for perpetual), `RemainingTime`, `KeyID`, `DeviceMatched`.

`Manager` caches the most recent successful result; use
`Manager.CachedResult()` to query it without re-verifying and
`Manager.InvalidateCache()` to clear it. `Manager.GetDeviceRequestCode(ns)`
delegates to `pkg/fingerprint` for an activation/request code.

> Note: `CodeFeatureDenied` replaces the older
> `LICENSE_FEATURE_UNAVAILABLE`. The `CodeFeatureUnavailable` constant is
> retained as a backward-compatible alias.


See [`../../examples/client/main.go`](../../examples/client/main.go).

## Online activation (future)

- Inject a network-backed `TrustedTimeProvider` for authoritative time.
- Fetch signed revocation lists / public-key updates over a signed OTA channel.
- Add a device re-binding endpoint so users can move licenses between machines.

See [`../../SECURITY.md`](../../SECURITY.md) for the full threat model.
