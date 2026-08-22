# grantseal — Offline Software Licensing (English)

[English](./README.md) | [中文文档](../zhCN/README.md) — back to the [project README](../../README.md)

Related docs: [architecture](./architecture.md) · [quality & coverage](./quality.md) · [performance](./performance.md) · [security](../../SECURITY.md)

grantseal is an offline software licensing library and CLI built with
Go 1.26 and **only the standard library**. It issues, verifies, and manages
Ed25519-signed licenses with device binding, feature/limit gating, expiry with
grace periods, clock-rollback detection, and signed revocation lists. Its goal
is to raise the cost of forgery and offline tampering — not to make software
uncrackable; see [`../../SECURITY.md`](../../SECURITY.md) for the honest limits.

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

Runnable examples and multi-scenario issue/verify configs live in
[`../../examples/README.md`](../../examples/README.md).

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
code; malformed input returns an error on every supported entry point instead
of panicking (continuously fuzz/race verified in CI).

## Issue config

The `issue` command reads a JSON config and signs it into a license. See
[`../../examples/issue-config.json`](../../examples/issue-config.json) for a full
example and [`../../examples/scenarios/`](../../examples/scenarios/) for
scenario-specific variants. Fields:

- **`key_id`** *(required)* — ID of the signing key; must match the private key
  passed to `issue` and is recorded in the envelope. Example: `"k1"`.
- **`product_id`** *(recommended)* — Product this license is for; the client
  rejects a mismatch with `LICENSE_PRODUCT_MISMATCH`. Example: `"acme-app"`.
- **`customer_id`** — Stable customer identifier. Example: `"cust_00042"`.
- **`customer_name`** — Human-friendly customer name. Example:
  `"ACME Corporation"`.
- **`edition`** *(required)* — One of `trial`/`basic`/`professional`/
  `enterprise` (whitelist). Drives the default feature set.
- **`license_type`** *(required)* — One of `trial`/`subscription`/`lifetime`
  (whitelist). **Time constraint:** `trial` and `subscription` **must** carry
  `expires_at`; `lifetime` **must not** carry `expires_at` and never expires.
- **`not_before`** *(optional)* — RFC3339 UTC activation time. Before it the
  license yields `LICENSE_NOT_YET_VALID`. Must not precede `issued_at`.
- **`expires_at`** — RFC3339 UTC hard expiry. **Required** for `trial`/
  `subscription`; **omit** for `lifetime`. Must not be earlier than `issued_at`
  (the issuer statically rejects such configs as `LICENSE_MALFORMED`).
- **`grace_period_days`** — Integer `0`–`3650`; extends usability past
  `expires_at` (status `grace`) before `LICENSE_EXPIRED`.
- **`features`** — String array of granted feature flags; unioned with the
  edition defaults. Example: `["export_pdf", "webhooks"]`.
- **`limits`** — Map of non-negative integer quotas, range-validated. Example:
  `{"max_seats": 50, "max_projects": 200}`. An undeclared key is treated as
  **unlimited** by `CheckLimit`.
- **`device_binding`** — `{"mode": "none"|"single"|"multi", "device_ids": [...]}`.
  `single`/`multi` bind to the listed fingerprints; a non-matching device yields
  `LICENSE_DEVICE_MISMATCH`.
- **`version_constraint`** — `{"min_version", "max_version",
  "maintenance_until", "covered_max_version"}`. While `maintenance_until` is
  active all in-range versions are covered; afterward only
  `<= covered_max_version` remain covered (else `LICENSE_VERSION_UNSUPPORTED`).
- **`metadata`** — Free-form `string → string` map for issuer bookkeeping (e.g.
  `order_id`, `region`); not interpreted by the verifier.

> `license_id` and `serial_number` are normally generated with `crypto/rand` at
> issue time; the scenario fixtures set `license_id` explicitly only to make
> revocation assertions deterministic.

## CLI usage

```bash
# Generate a key pair into a gitignored dir (private key stays local, mode 0600).
# ./_keys is gitignored; never commit a private key.
go run ./cmd/license-tool keygen -key-id k1 -out-dir ./_keys

# Print the public key from a private key
go run ./cmd/license-tool public-key -key ./_keys/k1-private.key

# Issue a license from JSON config
go run ./cmd/license-tool issue -config examples/issue-config.json \
  -key ./_keys/k1-private.key -out customer.lic

# Verify + policy-validate (client-side)
go run ./cmd/license-tool verify -license customer.lic -pubkey ./_keys/k1-public.key \
  -product acme-app -version 1.4.0

# Inspect (signature only, no policy checks) — diagnostics only
go run ./cmd/license-tool inspect -license customer.lic -pubkey ./_keys/k1-public.key

# Device fingerprint / request code
go run ./cmd/license-tool fingerprint -namespace acme-app -json
go run ./cmd/license-tool fingerprint -namespace acme-app -request-code

# Build a signed revocation list (v2: -sequence is required, plus -ttl or
# -expires-at). The sequence is a monotonically increasing publication counter
# the client tracks as a high-water mark to reject replayed older lists.
go run ./cmd/license-tool revoke-list -key ./_keys/k1-private.key -key-id k1 \
  -ids lic_abc,lic_def -sequence 1 -ttl 8760h -out revoked.json

# Print the license-tool version
go run ./cmd/license-tool version
```

## Install & Docker

`license-tool` is the **issuer-side** binary and holds private-key logic, so it
is meant for authorized issuers only.

- **Release binary:** download from the
  [releases page](https://github.com/soulteary/grantseal/releases).
- **Homebrew (macOS / Linux):**

```bash
brew tap soulteary/tap
brew install soulteary/tap/grantseal
```

- **Docker:** `docker pull soulteary/grantseal:latest`

> **Private-key safety.** The image never bundles `keys/` or any `*.key` file.
> Mount your private key at runtime with `-v` (read-only) — never bake it into
> an image — and keep it on a trusted issuer machine.

```bash
# Issuer: generate a key pair into a host directory, then keep it off the image.
# ./_keys is gitignored; never commit or bake in a private key.
docker run --rm -v "$PWD/_keys:/work/_keys" soulteary/grantseal:latest \
  keygen -key-id k1 -out-dir /work/_keys

# Issue a license with a read-only mounted private key
docker run --rm \
  -v "$PWD/_keys:/work/_keys:ro" \
  -v "$PWD:/work" \
  soulteary/grantseal:latest \
  issue -config /work/examples/issue-config.json \
  -key /work/_keys/k1-private.key -out /work/customer.lic

# Client-side verification only needs the public key (-product is required to
# scope validation to a specific product_id)
docker run --rm -v "$PWD:/work" soulteary/grantseal:latest \
  verify -license /work/customer.lic -pubkey /work/_keys/k1-public.key -product acme-app
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
    // license.CodeOf(err) == license.CodeFeatureUnavailable ("LICENSE_FEATURE_UNAVAILABLE")
    // (CodeFeatureDenied is a Go alias resolving to the same wire code)
}
if err := res.CheckLimit("max_seats", seatsInUse); err != nil {
    // license.CodeOf(err) == license.CodeLimitExceeded ("LICENSE_LIMIT_EXCEEDED")
    // Note: an undeclared limit key is treated as UNLIMITED (returns nil).
}
// Fail-closed alternative: RequireLimit rejects an undeclared key with
// CodeLimitRequired and a negative current with CodeInvalidLimits.
if err := res.RequireLimit("max_seats", seatsInUse); err != nil {
    // license.CodeOf(err) == CodeLimitExceeded / CodeLimitRequired / CodeInvalidLimits
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

- `RequireFeature(name) error` — returns `CodeFeatureUnavailable`
  (wire code `LICENSE_FEATURE_UNAVAILABLE`) when a feature is not granted.
  `CodeFeatureDenied` is a Go-identifier alias that resolves to the *same*
  wire code (see the note below).
- `CheckLimit(key, current) error` — returns `CodeLimitExceeded`
  (`LICENSE_LIMIT_EXCEEDED`) when exceeded. A key that the license does not
  declare is treated as **unlimited**.
- `RequireLimit(key, current) error` — fail-closed counterpart of `CheckLimit`:
  an undeclared key returns `CodeLimitRequired` (`LICENSE_LIMIT_REQUIRED`), a
  negative `current` returns `CodeInvalidLimits`, and over-limit returns
  `CodeLimitExceeded`. `CheckLimitStrict(key, current)` is the same but without
  the empty-key / negative-`current` guards.
- `GetLimit`, `GetEdition`, `GetExpiration`, `GetRemainingDays` (returns `-1`
  for perpetual), `RemainingTime`, `KeyID`, `DeviceMatched`.

`Manager` caches the most recent successful result; use
`Manager.CachedResult()` to query it without re-verifying and
`Manager.InvalidateCache()` to clear it. `Manager.GetDeviceRequestCode(ns)`
delegates to `pkg/fingerprint` for an activation/request code.

> **`CachedResult` is not an authorization decision.** It exists only for
> history display, diagnostics, and non-security UI. The cache is cleared at the
> start of every `Validate`/`LoadAndValidate` and is fail-closed when the
> trusted clock errors (it returns `(ValidationResult{}, false)` rather than
> falling back to the wall clock). Any current authorization decision MUST
> re-run `Validate`/`LoadAndValidate`; never gate access on a cached result.

> **Feature-gate error code.** The stable wire code emitted by `RequireFeature`
> is `LICENSE_FEATURE_UNAVAILABLE`. The Go source exposes two identifiers,
> `CodeFeatureUnavailable` and its alias `CodeFeatureDenied`, which both resolve
> to that *same* wire string — the alias exists only so existing callers keep
> compiling. A new Go name does not mean a new wire code, and there is not a
> `LICENSE_FEATURE_DENIED` wire string (that spelling is not emitted).


See [`../../examples/client/main.go`](../../examples/client/main.go).

## Error codes

Every failure path returns a stable, machine-readable `LICENSE_*` code (see
[`../../pkg/license/errors.go`](../../pkg/license/errors.go)). These strings are
part of the public contract and are safe to switch on for UX. Use
`license.CodeOf(err)` to extract one. The full set is **31 distinct wire codes**
(`LICENSE_OK` plus 30 failure codes). Note that `LICENSE_FEATURE_UNAVAILABLE` is
surfaced in Go under two identifiers (`CodeFeatureUnavailable` and its alias
`CodeFeatureDenied`) but is a single wire code:

- **`LICENSE_OK`** — Validation succeeded. *Trigger:* a valid, in-window license.
  *UX:* proceed; optionally surface remaining days / edition.
- **`LICENSE_FILE_NOT_FOUND`** — The license file path does not exist. *Trigger:*
  missing or wrong path on first run. *UX:* prompt the user to import/select a
  license file.
- **`LICENSE_FILE_TOO_LARGE`** — File exceeds the 64 KiB cap. *Trigger:* corrupt
  or hostile input. *UX:* reject as invalid; ask for a fresh license.
- **`LICENSE_MALFORMED`** — Envelope/JSON cannot be parsed or is structurally
  invalid. *Trigger:* truncated/edited file, wrong file type. *UX:* "invalid
  license file", offer re-import.
- **`LICENSE_UNSUPPORTED_ALGORITHM`** — Envelope algorithm is not `Ed25519`.
  *Trigger:* wrong/forged algorithm field. *UX:* reject as invalid.
- **`LICENSE_UNSUPPORTED_SCHEMA`** — `schema_version` is not `1`. *Trigger:* a
  license issued by a newer/older incompatible tool. *UX:* prompt to upgrade the
  app or obtain a compatible license.
- **`LICENSE_KEY_UNKNOWN`** — The envelope `key_id` is not in the client's key
  ring. *Trigger:* license signed by a key the app does not embed. *UX:* treat
  as invalid; may indicate a wrong build/channel.
- **`LICENSE_KEY_DISABLED`** — The signing key exists but is disabled in the
  ring. *Trigger:* operator retired the key. *UX:* ask the user to obtain a
  re-issued license.
- **`LICENSE_KEY_REVOKED`** — The signing key is outside its validity window /
  revoked in the ring. *Trigger:* key rotation/compromise. *UX:* request a
  re-issued license.
- **`LICENSE_SIGNATURE_INVALID`** — Signature does not verify over the canonical
  payload. *Trigger:* tampered payload or wrong public key. *UX:* reject as
  invalid/forged.
- **`LICENSE_KEY_ID_MISMATCH`** — Payload `key_id` disagrees with the envelope /
  verifying key. *Trigger:* spliced/edited license. *UX:* reject as invalid.
- **`LICENSE_INVALID_ENUM`** — `edition` or `license_type` is not in the
  whitelist. *Trigger:* hand-edited or corrupt config. *UX:* reject as invalid.
- **`LICENSE_INVALID_LIMITS`** — A `limits` value is out of range (e.g.
  negative). *Trigger:* malformed issue config. *UX:* reject as invalid.
- **`LICENSE_REVOKED`** — The license ID appears in a signed revocation list.
  *Trigger:* issuer revoked this specific license. *UX:* "license revoked",
  direct the user to support/renewal.
- **`LICENSE_NOT_YET_VALID`** — Current time is before `not_before`. *Trigger:*
  future activation date or a rolled-back clock. *UX:* show the activation date;
  suggest checking the system clock.
- **`LICENSE_EXPIRED`** — Past `expires_at` (and grace period, if any).
  *Trigger:* trial/subscription lapsed. *UX:* prompt to renew; show expiry date.
- **`LICENSE_CLOCK_ROLLBACK`** — Detected system time earlier than the trusted
  high-water mark. *Trigger:* clock tampering to dodge expiry. *UX:* warn about
  the clock; block time-bound features.
- **`LICENSE_DEVICE_MISMATCH`** — The running device fingerprint is not bound.
  *Trigger:* license moved to another machine. *UX:* show a device request code
  and ask the user to re-bind.
- **`LICENSE_PRODUCT_MISMATCH`** — Payload `product_id` differs from the caller's
  product. *Trigger:* license for a different product. *UX:* reject as invalid.
- **`LICENSE_PRODUCT_REQUIRED`** — Validation was not scoped to a product (empty
  `ProductID`) and the `Manager` was not configured with
  `WithUnscopedProductValidation`. *Trigger:* forgetting to pass a product.
  *UX:* fail-closed; a license issued for another product could otherwise be
  authorized.
- **`LICENSE_NON_CANONICAL_PAYLOAD`** — A signed payload's carried bytes are not
  the canonical encoding of the payload. *Trigger:* re-encoded/tampered bytes.
  *UX:* reject as invalid even if the signature would verify.
- **`LICENSE_VERSION_UNSUPPORTED`** — The running version is out of the covered
  range, or no/unparseable version was supplied while a constraint exists.
  *Trigger:* upgrade beyond the maintenance/covered window. *UX:* prompt to
  purchase an upgrade or run a covered version.
- **`LICENSE_FEATURE_UNAVAILABLE`** — A required feature is not granted (returned
  by `RequireFeature`, whether the feature is absent, insufficient, or the result
  is not valid). *Trigger:* gating a feature not in the license. *UX:*
  upsell/upgrade prompt for that feature.
- **`LICENSE_LIMIT_EXCEEDED`** — A usage counter exceeds its declared limit
  (returned by `CheckLimit`). *Trigger:* e.g. seats over `max_seats`. *UX:* show
  the limit and prompt to upgrade.
- **`LICENSE_STATE_INTEGRITY_FAILURE`** — The anti-rollback state file is corrupt
  and the policy is fail-closed. *Trigger:* tampered/corrupt state for a
  `trial`/`subscription` license. *UX:* reject; may require re-activation.
- **`LICENSE_LIMIT_REQUIRED`** — A strict limit check (`RequireLimit` /
  `CheckLimitStrict`) queried a limit key the license does not declare. *Trigger:*
  a typo'd or forgotten limit key. *UX:* fail-closed so an undeclared limit is
  not silently unlimited.
- **`LICENSE_REVOCATION_STALE`** — A validly-signed revocation list has a lower
  sequence than the local high-water state (an old list is being replayed).
  *Trigger:* replay of an older revocation list. *UX:* keep the newer known
  state; reject the stale list.
- **`LICENSE_REVOCATION_FROM_FUTURE`** — A revocation list's `issued_at` is
  further in the future than the tolerated clock skew. *Trigger:* wrong clock or
  forged future list. *UX:* reject the list.
- **`LICENSE_REVOCATION_EXPIRED`** — A revocation list's `expires_at` is in the
  past (beyond tolerated skew): the distribution is too old to trust. *Trigger:*
  a stale published list. *UX:* fetch a fresh list.
- **`LICENSE_REVOCATION_ROLLBACK`** — A revocation list reuses a previously seen
  sequence but carries a different payload digest. *Trigger:* content
  substitution at an already-accepted sequence. *UX:* reject; the local state is
  unchanged.
- **`LICENSE_REVOCATION_STATE_INTEGRITY_FAILURE`** — The local revocation
  high-water state store is corrupt or fails its HMAC check. *Trigger:*
  tampered/corrupt revocation state. *UX:* fail-closed; the state is not
  overwritten.

> **Backward-compat alias:** `CodeFeatureDenied` is a Go-identifier alias for
> `CodeFeatureUnavailable`; both resolve to the single stable wire code
> `LICENSE_FEATURE_UNAVAILABLE`. The alias is retained only so existing callers
> that reference the `CodeFeatureDenied` identifier keep compiling — it is **not**
> a distinct error code, and there is no `LICENSE_FEATURE_DENIED` wire string.

## Online activation (future / Roadmap)

- Inject a network-backed `TrustedTimeProvider` for authoritative time.
- Fetch signed revocation lists / public-key updates over a signed OTA channel.
- Add a device re-binding endpoint so users can move licenses between machines.

See [`architecture.md`](./architecture.md) for the trust boundaries and the
verification order, and [`../../SECURITY.md`](../../SECURITY.md) for the full
threat model.
