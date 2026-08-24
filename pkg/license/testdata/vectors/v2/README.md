# grantseal v2 cross-implementation test vectors

These are **language-agnostic conformance vectors** for the grantseal v2 license
wire protocol. They are not here for Go's own benefit — the Go implementation is
tested many other ways. They exist so that a **Rust / Python / Java / Node** (or
any other) implementation of the protocol can prove, byte-for-byte and
decision-for-decision, that it is compatible with grantseal.

The normative protocol spec these vectors pin is
[`docs/enUS/protocol-v2.md`](../../../../../docs/enUS/protocol-v2.md)
([中文](../../../../../docs/zhCN/protocol-v2.md)). Where a vector and the prose
disagree, the vector (and the Go golden tests) win.

> **The v2 wire format is frozen after v1.0.** If regenerating these vectors
> changes any committed bytes, that is a breaking wire change and must be
> reviewed as such — never rubber-stamped.

## Files

- `vectors.json` — the manifest: shared metadata plus every vector inlined, so a
  runner can consume a single file if it prefers.
- `valid-*.json` / `invalid-*.json` — one self-contained vector each.

| File | Expected | Code | What it pins |
|------|----------|------|--------------|
| `valid-basic.json` | valid | — | Minimal lifetime license, sorted keys, `omitempty` fields absent. |
| `valid-lifetime.json` | valid | — | Features + limits + metadata: nested sorted maps, `2^40` integer fidelity, un-escaped HTML/Unicode. |
| `valid-subscription.json` | valid | — | Subscription with an explicit `expires_at` in the future relative to `now`. |
| `valid-device-bound.json` | valid | — | Single-device binding via a versioned fingerprint `device_id`. |
| `invalid-signature.json` | invalid | `LICENSE_SIGNATURE_INVALID` | One signature bit flipped; length still 64. |
| `invalid-keyid.json` | invalid | `LICENSE_KEY_ID_MISMATCH` | Envelope `key_id` swapped to a different trusted key; signature still verifies but no longer matches the payload's embedded `key_id`. |
| `invalid-noncanonical.json` | invalid | `LICENSE_NON_CANONICAL_PAYLOAD` | Payload keys reordered and re-signed; signature verifies but bytes are not canonical. |
| `invalid-duplicate-key.json` | invalid | `LICENSE_MALFORMED` | Payload JSON has a duplicate object key (JSON-smuggling defense). |

## Vector schema

Every `*.json` vector (and each entry in `vectors.json`'s `vectors` array) has:

| Field | Meaning |
|-------|---------|
| `name` / `description` | Human labels. |
| `schema_version` | Always `2`. |
| `signing_domain` | The domain-separation prefix, `grantseal/license/v2\u0000` (note the trailing NUL). |
| `key_id` | The `key_id` carried in the envelope for this vector. |
| `public_key` | Base64URL(32-byte Ed25519 public key) the signature verifies against. |
| `canonical` | The exact canonical JSON payload string the signature actually covers. For `invalid-noncanonical` / `invalid-duplicate-key` this is the mutated (non-canonical / duplicate-key) bytes that were signed. |
| `signing_input_hex` | `hex(signing_domain_bytes ‖ canonical_bytes)` — the exact bytes passed to Ed25519 verify. |
| `signature` | Base64URL(64-byte Ed25519 signature) as carried in the envelope. |
| `envelope` | The complete on-the-wire license envelope object (`algorithm` / `key_id` / `payload` / `signature`). This is the primary input to feed your parser. |
| `validation.product_id` | The product scope to validate against (grantseal fails closed without it). |
| `validation.device_fingerprint` | Current device identity to supply; set for device-bound vectors, empty otherwise. |
| `validation.now` | RFC3339 UTC instant to treat as "now" so time checks are reproducible. |
| `validation.clock_skew_seconds` | Tolerated clock skew, in seconds. |
| `expected` | `"valid"` or `"invalid"`. |
| `expected_code` | For invalid vectors, the stable error code your implementation must map to (see [`pkg/license/errors.go`](../../../errors.go)). |
| `layer` | Where the outcome is decided: `verify` (signature/key), `parse` (envelope/JSON structure), or `validate` (policy). Informational. |

The `vectors.json` manifest additionally carries:

- `seed_hex` — the fixed 32-byte Ed25519 **seed** all vectors are signed with.
  Seed an Ed25519 key from these exact bytes and you reproduce `public_key` and
  every signature. **Throwaway test key — never sign real licenses with it.**
- `trusted_key_ids` — every `key_id` a verifier must register (all bound to the
  same `public_key`). Required so `invalid-keyid` fails as a
  payload↔envelope binding mismatch, not an unknown-key lookup.

## How to consume the vectors (any language)

There are two conformance roles; do whichever your implementation supports.

### 1. Verifier / validator (minimum bar)

For each `*.json` vector:

1. Register `public_key` under each id in `trusted_key_ids` in your key ring.
2. Parse `envelope` with your strict JSON parser (reject duplicate keys and
   unknown fields — see protocol §9).
3. Verify the Ed25519 signature over `signing_domain_bytes ‖ decoded_payload`.
4. Re-canonicalize the decoded payload and require it to equal the carried
   payload bytes (reject non-canonical).
5. Enforce that the payload's embedded `key_id` equals the envelope `key_id`.
6. Run policy validation using `validation.*` (product scope, `now`, skew,
   device fingerprint).
7. Assert your outcome matches `expected`, and on failure that your stable code
   equals `expected_code`.

A pure verifier can ignore `seed_hex` entirely.

### 2. Issuer (byte-exact producer)

To prove you can *produce* identical bytes:

1. Seed an Ed25519 key from `seed_hex`.
2. Canonicalize the payload with the grantseal algorithm (protocol §2): marshal,
   sort every object's keys byte-wise, no insignificant whitespace, **HTML
   escaping disabled**, preserve integer fidelity. This is **not** RFC 8785 JCS.
3. Sign `signing_domain_bytes ‖ canonical_bytes`.
4. Assert your `canonical` string, `signing_input_hex`, and `signature` match
   the vector for the `valid-*` cases exactly.

## Regenerating (grantseal maintainers only)

The vectors are generated from the Go implementation and committed. Regenerate
after an intentional, reviewed protocol change:

```bash
go test ./pkg/license -run TestGenerateCrossImplVectors -update
```

`vectors_test.go` consumes these files on every ordinary `go test` run and fails
if the Go implementation drifts from the recorded bytes or decisions. A foreign
implementation runs the analogous loop against the same files.
