# Security (English)

The authoritative security policy, trust boundaries, threat table, and
deployment checklist live in the root [`SECURITY.md`](../../SECURITY.md). The
architecture and verification order are in [`architecture.md`](./architecture.md).
Summary:

- **Ed25519 signatures only**; PKCS#1v1.5/MD5/SHA-1/ECB/home-grown crypto are forbidden.
- Signatures provide **origin authentication and integrity, not confidentiality** — payloads are readable, so never put secrets in them.
- Private-key logic is confined to `internal/issuer` + the CLI and is **unimportable** by clients; CI scans the final release archives for key material and enforces an archive allowlist.
- Naive clock rollback is **detected** via an integrity-protected high-water mark, not prevented against a root/admin adversary.
- Fingerprints are normalized, namespaced, then SHA-256/HMAC hashed; the hash is a non-cryptographic **identity** signal and raw hardware values are **not returned by the API**; drift is expected — provide a re-binding path.
- `inspect` verifies the signature for **diagnostics only** and performs no policy checks; gate on `verify` / `LoadAndValidate`.
- Offline revocation separates three concepts: **signature authenticity** (always enforced), **distribution freshness** (a client only enforces the list it currently holds), and **local anti-rollback** (best-effort, detects not prevents).
- Read-only results, fail-closed verifier; every supported entry point returns a stable error instead of panicking (continuously fuzz/race verified in CI).
- Offline licensing raises forgery/tamper cost; it is **not** uncrackable — pair with server-side checks for high-value assets.
