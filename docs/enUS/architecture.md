# Architecture

[English](./architecture.md) | [中文文档](../zhCN/architecture.md) — back to the [project README](../../README.md)

Related docs: [README](./README.md) · [quality & coverage](./quality.md) · [performance](./performance.md) · [security](../../SECURITY.md)

This document describes the trust boundaries, on-the-wire envelope format, the
exact verification order, revocation and offline freshness, and the device
fingerprint scheme. It reflects the code in `pkg/license` and `pkg/fingerprint`.

## Trust boundaries

grantseal splits cleanly into an **issuer side** (holds the private key) and a
**client side** (holds only public keys). Go's `internal/` mechanism makes the
issuer package unimportable by clients, so private-key logic cannot link into a
client binary.

```
                 Issuer machine (trusted)              |        Client / customer (untrusted)
                                                        |
  cmd/license-tool  ──uses──▶  internal/issuer          |   application ──imports──▶ pkg/license
      keygen                     private key (0600)     |                              KeyRing (public keys only)
      issue        ──signs──▶    Ed25519 sign           |                              Verifier / Validator
      revoke-list                canonical payload      |                              Manager (file I/O, cache)
                                     │                   |                                  │
                                     ▼                   |                                  ▼
                              customer.lic  ───────ships over any channel──────▶  verify + policy-validate
                              revoked.json                                        (fail-closed, stable errors)
                                                        |
  Trust boundary: the private key never crosses this line. Only signed artifacts
  (licenses, revocation lists) and public keys do.
```

Key properties:

- **Private-key isolation.** Clients import only `pkg/license`; `internal/issuer`
  is unimportable outside the module's issuer tree. CI scans the final release
  archives for key material and enforces an archive allowlist.
- **Untrusted input.** The client treats the license file, the revocation list,
  the local rollback state file, and the system clock as untrusted. No untrusted
  data may mutate trusted state before its signature is proven authentic (see
  [Verification order](#verification-order)).
- **Fingerprint privacy.** Raw hardware identifiers never leave
  `pkg/fingerprint`; only the hash and category names are exposed.

## Envelope format

A license on disk is a JSON `Envelope`:

```json
{
  "algorithm": "Ed25519",
  "key_id": "k1",
  "payload": "<Base64URL(canonical payload bytes)>",
  "signature": "<Base64URL(Ed25519 signature over the payload bytes)>"
}
```

- `payload` is the **canonical** (deterministic, sorted-key) JSON of the
  `Payload`, Base64URL-encoded **verbatim**. The client verifies the signature
  against the exact bytes carried in `payload` — it does not re-serialize the
  payload — so there is no room for a canonicalization mismatch between issuer
  and client.
- `signature` is the Base64URL-encoded Ed25519 signature over those payload
  bytes.
- Both `payload` and `signature` are parsed as **URL-safe Base64 only**;
  standard-alphabet Base64 (with `+`/`/`) is rejected.
- `ParseEnvelope` enforces the 64 KiB size cap, uses `DisallowUnknownFields`,
  rejects trailing data, and requires all four fields to be non-empty.

A revocation list uses the analogous `RevocationEnvelope` wrapping a signed
`RevocationList{schema_version, issued_at, key_id, revoked_license_ids}`.

### Golden vectors carry no private key

The test suite pins **golden envelope vectors** — fixed `(public key, canonical
payload, signature)` triples — and asserts that verification succeeds and that
the canonical bytes are byte-for-byte stable. These vectors embed **only public
keys**: a private key is never required to *verify*, so it never appears in a
fixture. This both documents the wire format and guards against accidental
changes to canonicalization. See [quality](./quality.md) for the vector list.

Concretely, `TestCanonicalBytesGoldenVectors` in
[`pkg/license/canonical_golden_test.go`](../../pkg/license/canonical_golden_test.go)
pins the exact canonical byte sequence for several payloads, so any change to key
sorting, HTML escaping, number fidelity, or null handling fails the test.

## Verification order

`Manager.LoadAndValidate` (and the underlying `Verifier` + validator) run in a
fixed, security-motivated order:

1. Read the license file (reject if `> 64 KiB`).
2. Parse the envelope (`DisallowUnknownFields`, reject trailing data).
3. Check the algorithm is `Ed25519`.
4. Resolve `key_id` in the `KeyRing` (must be enabled, not revoked, within its
   validity window).
5. Verify the Ed25519 signature over the canonical payload bytes.
6. Check the payload's `key_id` matches the envelope `key_id` and the schema
   version is `1`.
7. **Anti-rollback state is loaded, checked, and saved only *here* — after the
   signature is proven authentic.** This ordering is deliberate: if untrusted
   input could load/mutate the trusted-time high-water mark *before* the
   signature is verified, a forged file could poison the rollback state (e.g.
   push the high-water mark forward to force spurious `LICENSE_CLOCK_ROLLBACK`,
   or reset it). Verifying first means only authentic licenses ever touch
   trusted time state.
8. Enum whitelist + `license_type` time semantics.
9. Revocation check.
10. Time checks (`not_before` / expiry / grace).
11. Device binding.
12. Product / version constraint.
13. Return a **read-only** `ValidationResult`.

If the anti-rollback state file is corrupt, the policy is fail-closed by
`license_type`: `trial`/`subscription` are rejected
(`LICENSE_STATE_INTEGRITY_FAILURE`), while a time-independent `lifetime` license
is tolerated and the state is reset. Every failure path returns a stable
`LICENSE_*` code; malformed input returns an error on every supported entry
point instead of panicking (continuously fuzz/race verified in CI).

## Revocation & offline freshness

- A revocation list is authenticated exactly like a license: canonical bytes,
  Ed25519 signature, verified client-side against the same `KeyRing`. Its
  `key_id` inside the signed body must match the envelope `key_id`, the schema
  must be `2` (`RevocationSchemaVersion`), and the entry count is capped at
  `MaxRevokedIDs`.
- The v2 list carries `list_id`, a monotonically increasing `sequence`,
  `issued_at`, and `expires_at` inside the signed body. Three distinct
  properties are enforced independently:
  1. **Signature authenticity** — the list is really from the issuer (Ed25519
     over canonical bytes).
  2. **Distribution freshness** — `issued_at` must not be in the future
     (`LICENSE_REVOCATION_FROM_FUTURE`) and the list must not be past
     `expires_at` / older than any configured `MaxAge`
     (`LICENSE_REVOCATION_EXPIRED`). This is governed by
     `RevocationPolicy.RequireFresh`, which defaults to **true**;
     `RevocationPolicy.WithoutFreshness()` is the explicit, deliberate opt-out
     for replaying an archived list.
  3. **Local anti-replay** — the client persists the highest accepted `sequence`
     per `list_id` as a high-water mark. A list whose sequence is lower than the
     last accepted one is rejected (`LICENSE_REVOCATION_STALE`); reusing a
     sequence with different content is rejected as a rollback
     (`LICENSE_REVOCATION_ROLLBACK`). If the local state file is tampered with,
     the check fails closed (`LICENSE_REVOCATION_STATE_INTEGRITY_FAILURE`).
- **Legacy v1 lists are rejected by default.** A v1 list (no
  sequence/expiry, no replay resistance) is only accepted when the caller
  explicitly opts in via `RevocationPolicy.AllowLegacyV1Revocation()` (or the
  `-v1` flag when *building* a list). This keeps the default fail-closed.
- **Offline freshness limit.** A client still enforces only the revocation list
  it currently holds; without a newer signed list it cannot learn about newer
  revocations. The freshness window bounds how stale a held list may be, but
  distribution of newer lists is out of band.

### Roadmap fields / mechanisms (not yet implemented)

The following are **not** implemented today and are called out so nobody depends
on them:

- **Online revocation / OTA distribution** of signed revocation lists and
  public-key updates. *Roadmap.*
- **Network-backed `TrustedTimeProvider`** for authoritative time instead of the
  local clock. *Roadmap.*
- **Device re-binding endpoint** for moving a license between machines. *Roadmap.*

## Device fingerprint

`pkg/fingerprint` builds a stable, privacy-respecting device fingerprint:

1. **Collect** platform hardware identifiers (Linux/macOS/Windows + a fallback).
   Each is a `Component{Category, value}` where `value` is unexported so raw
   identifiers cannot leak via reflection/JSON/logging.
2. **Normalize** each value: trim, lowercase, collapse internal whitespace.
3. **Canonicalize**: drop empties, sort deterministically by `(category, value)`,
   prefix with the product namespace and a NUL separator, and join
   `category=value` lines with `\n`.
4. **Hash**: SHA-256 by default, or HMAC-SHA256 when a key is supplied
   (`ComputeHMAC`). The plain and v1 keyed outputs are prefixed `sha256:`; the
   v2 keyed output (`ComputeHMACV2`) is prefixed `hmac-sha256:` so the scheme is
   self-describing and the two cannot be confused.

Properties and caveats:

- **Order-independent, namespace-scoped.** The canonical form sorts components
  and includes the product namespace, so two products on the same device get
  different fingerprints and component order does not matter.
- **The hash is an identity signal, not a secret.** It provides device
  *identity*, not authentication.
- **`RequestCode`** derives a short, uppercase, dash-grouped code from the
  fingerprint for activation/support flows; it is deterministic per
  namespace+device.
- **Drift** is expected in VMs/containers or after hardware changes/reinstalls
  and can cause `LICENSE_DEVICE_MISMATCH`; provide a re-binding / support path.
- **Fail-closed.** If no usable hardware information is available the package
  returns `ErrInsufficientInfo`; it never fabricates a random identifier.
