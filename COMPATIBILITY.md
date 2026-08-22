# Compatibility Policy · 兼容性政策

This project versions **four independent surfaces**. Each has its own rules for
what counts as a breaking change. The Git tag (SemVer 2.0) is the umbrella
version for the module; a bump of any surface below is reflected there.

本项目对**四个独立面**分别做版本管理，每个面有各自的“破坏性变更”判定规则。Git tag
（SemVer 2.0）是模块的总版本号；下述任一面的破坏性变更都会体现在总版本号上。

---

## Version policy (pre-1.0 vs post-1.0) · 版本政策

- **This project is released as `v1.0.0`** — the point at which its four
  surfaces are declared stable. From `1.0.0` onward the SemVer rules below are
  binding: any breaking change to a surface requires a **MAJOR** version bump
  and a migration note here and in `CHANGELOG.md`.
- The one-time schema clean break to `schema_version = 2` (and the
  `grantseal/license/v2\x00` signing domain, revocation v2, etc.) happened
  **during pre-1.0 development** (`0.1.0` → `0.9.0`), where such breaking
  protocol changes were permitted without a MAJOR bump. That clean break is
  **development history**, not a promise that future schema versions may be
  removed freely; the forward-looking policy in each section below governs
  everything from `1.0.0` on.

- 本项目以 `v1.0.0` 发布，即宣布下述四个面进入稳定期。自 `1.0.0` 起，下述 SemVer
  规则具有约束力：任一面的破坏性变更都需要 **MAJOR** 版本号提升，并在本文件与
  `CHANGELOG.md` 中给出迁移说明。
- 一次性的 schema 断代（`schema_version = 2`、`grantseal/license/v2\x00` 签名域、
  撤销 v2 等）发生在 **1.0 之前的开发期**（`0.1.0` → `0.9.0`），彼时允许此类破坏性
  协议变更而无需 MAJOR 提升。该断代属于开发历史，并非"未来 schema 版本可随意移除"
  的承诺；自 `1.0.0` 起以下各节的前瞻性政策为准。

---

## 1. Wire / on-disk schema · 数据格式

- Field: `schema_version` inside the signed payload; also the revocation-list
  schema and the anti-rollback state format.
- **Current:** license payload `schema_version = 2` (signed under the
  domain-separation prefix `grantseal/license/v2\x00`); revocation list **v2**
  with domain-separation prefix `grantseal/revocation/v2\x00`.
- Rules (forward-looking, in force from `1.0.0`) · 规则（自 `1.0.0` 起生效）:
  - **Adding** a new schema version is done additively: the verifier accepts a
    bounded, explicit allowlist of versions and **rejects** everything else
    (fail-closed, never silently downgraded). An additive addition that keeps
    the existing accepted versions working is a **minor** change.
  - **Removing** acceptance of a currently-accepted schema version — or
    otherwise making a previously-valid artifact fail — is a **breaking change
    (MAJOR bump)** and must ship a migration note here and in `CHANGELOG.md`.
    (The historical `schema_version = 1` → `2` clean break predates `1.0.0`;
    see the *Version policy* section above.)
  - Legacy v1 revocation lists are rejected **by default** and only accepted
    when the caller opts in with `AllowLegacyV1Revocation()`.
  - Legacy **v0.1.0 license payloads** (`schema_version = 1`) are **no longer
    accepted**. Note the *actual* rejection code: v0.1.0 signed the canonical
    payload **directly, with no signing-domain prefix**, whereas the current
    verifier checks the Ed25519 signature over the domain-separated input
    (`grantseal/license/v2\x00` + canonical) *before* it parses the schema.
    A real v0.1.0 license therefore fails at signature verification and is
    rejected with **`LICENSE_SIGNATURE_INVALID`**, not
    `LICENSE_UNSUPPORTED_SCHEMA`. (`LICENSE_UNSUPPORTED_SCHEMA` is what a
    payload carrying `schema_version != 2` gets *if* its signature verifies
    under the v2 domain — i.e. a v2-domain-signed payload with a mismatched
    schema field, not a genuine v0.1.0 artifact.) Either way the outcome is
    fail-closed; licenses must be re-issued as v2. See `CHANGELOG.md` for the
    migration note.

### 1.1 Device-binding fingerprint scheme (Scheme A) · 设备指纹格式

- Surface: the string values stored in a signed license's
  `device_binding.device_ids` (and the `DeviceFingerprint` a caller supplies at
  validation time).
- **Contract:** every `device_id` is one of two explicit, strictly-parseable
  forms:
  - a **versioned fingerprint** `fp:v<N>:<algo>:<digest>`, where `<N>` is a
    known scheme version (currently `v1` or `v2`), `<algo>` is `sha256` or
    `hmac-sha256`, and `<digest>` is a 64-char lowercase-hex SHA-256/HMAC-SHA256
    digest; or
  - an **explicit opaque identifier** `opaque:<namespace>:<value>` for
    business-custom IDs that are not hashed fingerprints.
- Values are produced by `pkg/fingerprint` (`Compute*`/`ComputeVersion`/
  `ComputeHMACVersion`) and parsed/validated by `fingerprint.Parse`. The license
  layer enforces this format at static-validation time: a payload whose
  `device_ids` contain a legacy bare value (e.g. `sha256:<hex>` without a
  version, `dev-1`, or any arbitrary string) is rejected fail-closed with
  `LICENSE_MALFORMED`.
- Rules · 规则:
  - Parsing is **fail-closed**: unknown versions (`ErrUnknownVersion`), unknown
    algorithms (`ErrUnknownAlgorithm`), empty/malformed digests, non-hex, or
    wrong-length digests are all rejected. Nothing outside the two forms above
    is accepted.
  - The `fp:v<N>:` prefix records **which** scheme produced a value; it is an
    identification/migration aid and does **not** by itself keep an old binding
    matchable as the default scheme evolves. Matching is exact-string equality,
    so re-matching an already-issued binding requires recomputing that specific
    version via `ComputeVersion`/`ComputeHMACVersion`.
  - Introducing a new fingerprint scheme version is additive (a new value in the
    known-version allowlist). Removing acceptance of an existing version, or
    changing what `fingerprint.Parse` accepts, is a **breaking change**.


## 2. Stable error codes · 稳定错误码

- Surface: the `LICENSE_*` strings returned by `license.CodeOf(err)`.
- Rules · 规则:
  - Error code **strings are a public contract.** They are never renamed,
    removed, or repurposed. New failure modes get **new** codes appended.
  - Callers should branch on `license.Code` constants / the `LICENSE_*` string,
    never on the human-readable message text (which may change any time).
  - Renaming or repurposing an existing code is a **breaking change**.
  - Adding a Go-identifier **alias** for an existing wire code is *not* a new
    code and *not* a breaking change: e.g. `CodeFeatureDenied` is a Go alias that
    resolves to the same wire string as `CodeFeatureUnavailable`
    (`LICENSE_FEATURE_UNAVAILABLE`). There are **31** distinct wire codes
    (`LICENSE_OK` plus 30 failure codes).

## 3. CLI · 命令行

- Surface: `license-tool` subcommands, flags, exit codes, and stdout format.
- Rules · 规则:
  - Existing subcommands and flags are additive-only within a major version.
  - Exit codes are stable: `0` success (including `--help`/`-h`/`help` and a
    per-command `-h`/`-help`); `2` usage errors (unknown command, flag-parse
    failures, missing required flags, and malformed user input such as
    duration/RFC3339/enum/bool/number); `1` runtime/domain errors (file I/O, key
    loading, signing/verification failure, or a rejected license). Classification
    is by error type (`flag.ErrHelp` / `*usageError`), not by matching message
    strings.
  - Removing or repurposing a subcommand/flag, or changing an exit-code meaning,
    is a **breaking change**.
  - New flags default to preserving prior behavior.

## 4. Go API · Go 接口

- Surface: exported identifiers under `pkg/...` (notably `pkg/license` and
  `pkg/fingerprint`). `internal/...` is **not** part of the public API and may
  change at any time.
- Rules · 规则:
  - Follows standard Go module SemVer: no exported symbol in `pkg/*` is removed
    or changed incompatibly within a major version.
  - Deprecations are marked with a `// Deprecated:` doc comment and kept working
    for at least one minor release before any major-version removal.
  - Every new exported API ships with a Go doc comment.

---

## Deprecation flow · 弃用流程

1. Mark with `// Deprecated:` and point at the replacement.
2. Record it under `CHANGELOG.md` → *Deprecated*.
3. Keep it working across minor releases; remove only in the next **major**
   release, with a migration note.

## Reporting incompatibilities · 反馈不兼容

If an upgrade breaks you and it is not documented as a breaking change here or in
`CHANGELOG.md`, please open an issue — it is treated as a bug.

升级后若出现未在本文件或 `CHANGELOG.md` 中标注为破坏性变更的不兼容，请提交 issue，
我们按缺陷处理。
