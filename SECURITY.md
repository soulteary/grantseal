# Security Policy

## Threat model & honest boundaries

grantseal is an **offline** licensing system. Its goal is to **raise the cost of
forgery and tampering**, not to make software uncrackable. Please read the
limitations below before relying on it.

### What grantseal protects against

- **Forgery.** Licenses are signed with **Ed25519**. Without the issuer's
  private key an attacker cannot mint a license that verifies against the
  embedded public key.
- **Tampering.** The signature covers the **complete canonical payload**
  (deterministic sorted-key JSON). Changing any field (edition, expiry, device
  list, limits, …) invalidates the signature.
- **Downgrade / algorithm confusion.** Only `Ed25519` is accepted. Unknown
  algorithms, schema versions, and enum values are **rejected**, never silently
  downgraded.
- **Key substitution.** The `key_id` inside the signed payload must match the
  envelope `key_id`; unknown/disabled/revoked keys are rejected.
- **Naive clock rollback.** An integrity-protected (HMAC-SHA256) local state
  file records the last trusted time; large backward jumps are detected.
- **Resource exhaustion.** License files are capped at 64 KiB and parsed with
  `DisallowUnknownFields`; trailing data is rejected. Revocation lists and the
  local anti-rollback state file have their own independent size caps
  (`MaxRevocationFileSize`, `MaxRollbackStateSize`) and a revocation-entry cap
  (`MaxRevokedIDs`); payload entry counts and metadata key/value lengths are
  bounded too.
- **Version-coverage bypass.** Version-constraint checks are **fail-closed**: a
  license that declares any version constraint is rejected
  (`LICENSE_VERSION_UNSUPPORTED`) when the caller supplies no running version,
  or a running version that cannot be strictly parsed. Callers must pass the
  running `ProductVersion` whenever a constraint may be present.

### What grantseal CANNOT protect against (by design)

- **Binary patching / reverse engineering.** A determined attacker can patch the
  client binary to skip verification. This is inherent to all offline licensing.
  Combine with obfuscation / server-side checks for high-value assets.
- **System clock manipulation** by root/admin beyond the rollback heuristic.
- **Fingerprint drift** in VMs, containers, or after hardware changes/reinstalls.
  Provide an online re-binding / support path.
- **Public-key distribution.** Public keys must reach clients through a trusted
  channel (shipped with the signed binary, or signed OTA updates).

## Cryptography red lines (enforced in code)

- **Ed25519 only.** PKCS#1v1.5, MD5, SHA-1, ECB, and any home-grown scheme are
  forbidden.
- Sensitive comparisons use `crypto/subtle.ConstantTimeCompare`.
- **Key material is parsed as URL-safe Base64 only.** `AddPublicKeyBase64` and
  `DecodePrivateKey` reject standard-alphabet Base64 (with `+`/`/`) so there is a
  single unambiguous encoding for keys.
- **Private keys never** appear in client code, shipped binaries, git, logs, or
  test fixtures. Signing lives entirely under `internal/issuer` (unimportable by
  clients) and the CLI.
- `limits` are range-validated; negative/overflowing values are rejected.
- License files use **atomic writes** (temp file + `rename`) and default to
  **not overwriting** existing files.
- Validation results are **read-only**; the verifier is **fail-closed** and
  **never panics** on malformed input.
- Logs are redacted: no private keys, no raw hardware identifiers, no full
  sensitive license bodies.

## Key management

- Generate keys with `license-tool keygen`. The private key is written `0600`
  and the tool refuses to print it or overwrite it without `-force`.
- Store private keys in a secrets manager / HSM in production. Never commit them.
- Rotate by issuing new licenses under a new `key_id` while keeping old public
  keys in the client `KeyRing` so previously issued licenses keep validating.
- Revoke individual licenses with a **signed** revocation list
  (`license-tool revoke-list`), verified client-side against the same key ring.

## Reporting a vulnerability

Please report security issues privately to the maintainers of
`github.com/soulteary/grantseal` rather than opening a public issue.
