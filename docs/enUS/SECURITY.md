# Security (English)

The authoritative security policy and threat model live in the root
[`SECURITY.md`](../../SECURITY.md). Summary:

- **Ed25519 signatures only**; PKCS#1v1.5/MD5/SHA-1/ECB/home-grown crypto are forbidden.
- Signatures cover the complete canonical payload; `subtle.ConstantTimeCompare` for sensitive data.
- Private keys never appear in client code, binaries, git, logs, or test fixtures.
- Range-validated limits, rejected unknown enums, 64 KiB file cap, atomic writes.
- Read-only results, fail-closed verifier, never panics.
- Offline licensing raises forgery/tamper cost; it is **not** uncrackable — pair with server checks for high-value assets.
