# Security (English)

The authoritative security policy, trust boundaries, threat table, and
deployment checklist live in the root [`SECURITY.md`](../../SECURITY.md). The
architecture and verification order are in [`architecture.md`](./architecture.md).
Summary:

- **Ed25519 signatures only**; PKCS#1v1.5/MD5/SHA-1/ECB/home-grown crypto are forbidden.
- Signatures provide **origin authentication and integrity, not confidentiality** — payloads are readable, so never put secrets in them.
- Private-key logic is confined to `internal/issuer` + the CLI and is **unimportable** by clients; CI scans the final release archives for key material and enforces an archive allowlist.
- Naive clock rollback is **detected** via an integrity-protected high-water mark, not prevented against a root/admin adversary. The state HMAC is **tamper-evident against ordinary file modification, not secure secret storage**: the built-in secret is recoverable from the client binary, so it is not cryptographically impossible to forge for an out-of-scope local high-privilege attacker.
- Fingerprints are normalized, namespaced, then SHA-256/HMAC hashed; the hash is a non-cryptographic **identity** signal and raw hardware values are **not returned by the API**; drift is expected — provide a re-binding path.
- `inspect` verifies the signature for **diagnostics only** and performs no policy checks; gate on `verify` / `LoadAndValidate`.
- Offline revocation separates four concepts, enforced in order: **signature authenticity** (always enforced), **static structural invariants** (schema/`list_id`/`sequence`>0/`issued_at`/`expires_at` ordering — always enforced, not relaxed by `WithoutFreshness`, mapped to `LICENSE_MALFORMED`), **distribution freshness** (the time-relative window; the only layer `WithoutFreshness` relaxes; a client only enforces the list it currently holds), and **local anti-replay** (high-water sequence per `list_id`, still enforced under `WithoutFreshness`).
- The revocation state store is a **single-process writer**: `FileRevocationStateStore` coordinates in-process instances via a per-path lock but takes no OS file lock, so it is not safe against concurrent writers in separate processes. Deploy one of three shapes — (1) a **single writer process** using the file store (optionally `NewFileRevocationStateStoreExclusive`, which fails closed on an in-process duplicate writer and is released by `Close`), (2) a **custom atomic backend** (SQLite/Redis/RDBMS with cross-process serializable compare-and-set) for multi-process/multi-instance writers, or (3) **read-only replicas plus a single writer**. The in-process guardrail cannot detect a second OS process; see the root [`SECURITY.md`](../../SECURITY.md#revocation-state-store-concurrency--deployment).
- `Manager.CachedResult()` is for history/diagnostics/non-security UI **only** (fail-closed when the trusted clock errors); never use it as an authorization decision — re-run `Validate`/`LoadAndValidate` for any current authorization.
- Read-only results, fail-closed verifier; every supported entry point returns a stable error instead of panicking (continuously fuzz/race verified in CI).
- Offline licensing raises forgery/tamper cost; it is **not** uncrackable — pair with server-side checks for high-value assets.
