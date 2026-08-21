# Security Policy

Related: [Code of Conduct](CODE_OF_CONDUCT.md) | [Contributing Guide](CONTRIBUTING.md) | [Architecture](docs/enUS/architecture.md) · [架构](docs/zhCN/architecture.md) | [Docs: English](docs/enUS/README.md) · [中文文档](docs/zhCN/README.md)

## Goals

grantseal is an **offline** licensing system. Its goal is to **raise the cost of
forgery and offline tampering**, not to make software uncrackable. It provides:

- **Origin authentication and integrity** for licenses and revocation lists via
  Ed25519 signatures over a deterministic canonical payload.
- A **fail-closed** client verifier that returns stable `LICENSE_*` codes on
  every supported entry point instead of panicking on malformed input
  (continuously exercised by the race detector and fuzz targets in CI).
- Physical separation of private-key logic (`internal/issuer`) from client code
  (`pkg/license`), enforced by Go's `internal/` mechanism.

It explicitly does **not** provide confidentiality of the license contents
(payloads are readable), protection against a modified client binary, or
protection against a privileged (root/admin) local adversary.

## Trust boundaries

| Boundary | Trusted side | Untrusted side | Enforced by |
| -------- | ------------ | -------------- | ----------- |
| Private key material | Issuer machine (`internal/issuer` + CLI) | Everything shipped to customers | Go `internal/` (clients cannot import `internal/issuer`); CI scans the final release archives for key material and enforces an archive allowlist |
| Signature verification | Embedded public key(s) in the client `KeyRing` | The license file, revocation list, and their transport | `pkg/license` Ed25519 verification over canonical bytes |
| Anti-rollback state | HMAC key derived from a built-in secret + device fingerprint | The on-disk state file | HMAC-SHA256 tag checked with `subtle.ConstantTimeCompare` |
| Time source | Caller-supplied clock / `TrustedTimeProvider` | The local system clock | Rollback high-water-mark heuristic (naive rollback only) |
| Device identity | Hashed fingerprint categories | Raw hardware identifiers | `pkg/fingerprint` never exports or logs raw values |

The verifier processes **untrusted input**. No untrusted data is allowed to
mutate trusted state before its signature has been proven authentic — in
particular the anti-rollback state is loaded, checked, and saved **only after**
the signature verifies (see [architecture](docs/enUS/architecture.md#verification-order)).

## Threat model

| Threat | Protection | Residual risk / limits |
| ------ | ---------- | ---------------------- |
| **Forgery** — mint a license that verifies | Ed25519 signature; without the private key an attacker cannot produce a valid signature over the embedded public key | Depends on the private key staying secret and the public key reaching the client through a trusted channel |
| **Tampering** — edit edition/expiry/limits/device list | Signature covers the **complete canonical payload**; any change yields `LICENSE_SIGNATURE_INVALID` | None for the signed bytes; unsigned transport metadata is not authenticated |
| **Algorithm / schema downgrade** | Only `Ed25519` and `schema_version = 1` are accepted; unknown algorithms/enums are rejected, never silently downgraded | New algorithms require an explicit, signed schema bump |
| **Key substitution / splicing** | The payload `key_id` must equal the envelope `key_id`; unknown/disabled/out-of-window keys are rejected | Relies on correct key-ring configuration by the client |
| **Naive clock rollback** — move the clock back to dodge expiry | Integrity-protected local state records a trusted-time high-water mark; large backward jumps report `LICENSE_CLOCK_ROLLBACK` | Detects, does not prevent; a root/admin adversary can delete state or manipulate time beyond the heuristic |
| **Resource exhaustion** | Independent size caps (`MaxLicenseFileSize`, `MaxRevocationFileSize`, `MaxRollbackStateSize`), a revoked-ID cap (`MaxRevokedIDs`), payload entry/length caps, and `DisallowUnknownFields` with trailing-data rejection | Bounds work; does not bound attacker retries |
| **Version-coverage bypass** | Version-constraint checks are **fail-closed**: a constrained license with no/unparseable running version is rejected as `LICENSE_VERSION_UNSUPPORTED` | Callers must pass `ProductVersion` whenever a constraint may be present |
| **Revocation** — keep using a revoked license offline | Licenses and revocation lists are both signed and verified client-side | **Offline freshness limit:** a client only knows about revocations in the list it currently holds; there is no online freshness guarantee (see below) |
| **Binary patching / reverse engineering** | — | **Out of scope.** A determined attacker can patch the client to skip verification; combine with obfuscation / server-side checks for high-value assets |

## Cryptography red lines (enforced in code)

- **Ed25519 only.** PKCS#1v1.5, MD5, SHA-1, ECB, and any home-grown scheme are
  forbidden.
- **Signatures provide origin authentication and integrity, not
  confidentiality.** The canonical payload is Base64URL-encoded, not encrypted;
  anyone can read a license's contents. Do not put secrets in a payload.
- Sensitive comparisons use `crypto/subtle.ConstantTimeCompare`.
- **Key material is parsed as URL-safe Base64 only.** `AddPublicKeyBase64` and
  `DecodePrivateKey` reject standard-alphabet Base64 (with `+`/`/`) so there is a
  single unambiguous encoding for keys.
- `limits` are range-validated; negative/overflowing values are rejected.
- License files use **atomic writes** (temp file + `rename`) and default to
  **not overwriting** existing files.
- Validation results are **read-only**; the verifier is **fail-closed** and
  returns a stable `LICENSE_*` error on every supported entry point instead of
  panicking on malformed input — a property continuously exercised by the CI
  race detector and fuzz targets rather than asserted as an absolute guarantee.
- Logs are redacted: no private keys, no raw hardware identifiers, no full
  sensitive license bodies.

## Private-key isolation (verifiable architecture)

The isolation is a property you can verify, not a promise:

- Clients import **only** `pkg/license` plus their embedded **public** keys.
  Signing lives entirely under `internal/issuer`, which Go's `internal/`
  mechanism makes **unimportable** by any package outside this module's issuer
  tree — so private-key logic cannot link into a client binary.
- `keygen` writes the private key with mode `0600` and refuses to print it or
  overwrite an existing key without `-force`.
- Golden test vectors embed only public keys, canonical payloads, and
  signatures — never a private key (see
  [architecture](docs/enUS/architecture.md#envelope-format)).
- CI scans the **final release archives** for private-key material (PEM
  private-key headers, `*-private.key` names) and enforces an **archive
  allowlist** (`scripts/check-archive-allowlist.sh`) so only the intended files
  ship and a key cannot be included by accident.

## Key lifecycle

- **Generate** keys with `license-tool keygen` on a trusted issuer machine.
- **Store** private keys in a secrets manager / HSM in production. Never commit
  them; never bake them into a container image.
- **Rotate** by issuing new licenses under a new `key_id` while keeping old
  public keys in the client `KeyRing`, so previously issued licenses keep
  validating.
- **Disable / revoke a key** in the ring to reject licenses signed by it
  (`LICENSE_KEY_DISABLED` / `LICENSE_KEY_REVOKED`).

## Offline revocation freshness

Individual licenses are revoked with a **signed** revocation list
(`license-tool revoke-list`), verified client-side against the same key ring. In
an offline deployment the client only enforces the revocation list it currently
holds; it cannot learn about newer revocations without a fresh, signed list. To
tighten freshness, distribute updated revocation lists over a signed OTA channel
and/or add online revocation checks for high-value assets. The `issued_at` field
on a revocation list lets you reason about how stale a client's copy may be, but
it is **not** an automatic freshness enforcement mechanism today (Roadmap).

## Fingerprint privacy & drift

- `pkg/fingerprint` derives a fingerprint from stable hardware identifiers by
  **normalizing** them (trim/lowercase/whitespace-collapse), sorting them
  deterministically, scoping by a product namespace, and hashing with SHA-256
  (or HMAC-SHA256 when a key is supplied).
- The hash is a **non-cryptographic identity signal**, not a secret: it provides
  device *identity*, not authentication. Raw hardware values are never exported,
  returned, or logged — only the hash and the category names leave the package.
- **Drift** is expected in VMs, containers, or after hardware changes /
  reinstalls; the fingerprint may change and cause `LICENSE_DEVICE_MISMATCH`.
  Provide a re-binding / support path (show the request code from
  `GetDeviceRequestCode`).

## Clock & rollback limits

- The anti-rollback state remembers the highest trusted time observed and
  detects large backward jumps (`LICENSE_CLOCK_ROLLBACK`). It **detects**, it
  does not **prevent**: a privileged user can delete the state file or otherwise
  manipulate the environment.
- If the state file is corrupt, policy is fail-closed by `license_type`:
  `trial`/`subscription` are rejected (`LICENSE_STATE_INTEGRITY_FAILURE`), while
  a time-independent `lifetime` license is tolerated and the state is reset.
- The HMAC key should be derived from a built-in secret **and** a device
  fingerprint (`DeriveRollbackKeyStrict`) so state cannot be transplanted
  between machines.

## `inspect` is diagnostics, not authorization

`license-tool inspect` verifies the signature and prints the payload for
**diagnostics only**. It performs **no** policy checks (time, device, product,
version, revocation). A successful `inspect` does **not** mean a license would
pass validation — always gate on `verify` / `LoadAndValidate`, never on
`inspect`.

## Deployment checklist

- [ ] Private keys live only on trusted issuer machines / a secrets manager or
      HSM; never in git, images, logs, or client builds.
- [ ] Clients embed only the required **public** keys; old public keys are kept
      in the ring across rotations.
- [ ] Public keys reach clients over a trusted channel (shipped with the signed
      binary, or a signed OTA update).
- [ ] Callers pass `ProductID` and `ProductVersion` whenever a product/version
      constraint may be present (version checks are fail-closed).
- [ ] The anti-rollback HMAC key is derived from a built-in secret **and** a
      device fingerprint (`DeriveRollbackKeyStrict`).
- [ ] The client branches on `license.CodeOf(err)` and offers recovery paths
      (renew, re-bind, re-import); it does not ignore verification errors.
- [ ] For high-value assets, pair offline verification with obfuscation and/or
      server-side checks and a signed OTA channel for revocation freshness.
- [ ] Gate on `verify` / `LoadAndValidate`, never on `inspect`.

## Reporting a vulnerability

Please report security issues privately to the maintainers of
`github.com/soulteary/grantseal` rather than opening a public issue.
