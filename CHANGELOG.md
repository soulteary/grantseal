# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

本项目的所有重要变更都记录在本文件中，格式参考
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循
[语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [0.9.0] - 2026-08-22

### Security & protocol hardening (quality hardening initiative)

This release is a one-time, clean protocol upgrade. Read the **Migration** notes
below before upgrading.

- **License payload schema v2.** The license payload `schema_version` is
  raised from `1` to **`2`**, paired with the new `grantseal/license/v2\x00`
  signing domain. **v0.1.0 licenses can no longer be verified.** The prior
  release (`schema_version = 1`) signed the canonical payload **directly, with
  no signing-domain prefix**; the new verifier checks the signature over the
  domain-separated input (`grantseal/license/v2\x00` + canonical) *before* it
  inspects `schema_version`, so a genuine v0.1.0 license fails at signature
  verification and is reported as **`LICENSE_SIGNATURE_INVALID`** (not
  `LICENSE_UNSUPPORTED_SCHEMA`). `LICENSE_UNSUPPORTED_SCHEMA` is reserved for a
  payload whose signature *does* verify under the v2 domain but whose
  `schema_version` is not `2`. Both paths are fail-closed. **All existing
  licenses must be re-issued** as v2.
- **Signing domain separation.** License signatures are now computed over a
  domain-separated payload (`grantseal/license/v2\x00` prefix) and revocation
  lists over `grantseal/revocation/v2\x00`. Previously (v0.1.0) signatures
  covered the canonical payload bytes directly, with no domain prefix; adding
  the prefix binds a signature to its intended context and prevents
  cross-protocol signature reuse (which is why pre-upgrade artifacts no longer
  verify — see **Migration**).
- **Revocation protocol v2 (replay-resistant).** Revocation lists carry
  `list_id`, `sequence`, `issued_at`, and `expires_at`, verified against an
  integrity-protected (HMAC) high-water-mark state so a client cannot be rolled
  back to an older list. Legacy v1 lists are **rejected by default** and only
  accepted via the explicit `AllowLegacyV1Revocation()` option.
- **Strict JSON parsing.** Payload and list decoding reject trailing garbage,
  duplicate keys, and non-canonical encodings (`CodeNonCanonicalPayload`).
- **Fail-closed limits.** `RequireLimit` treats an undeclared limit key as a
  denial (`CodeLimitRequired`) rather than an implicit allow; `CheckLimitStrict`
  is the fail-closed counterpart of `CheckLimit`.
- **SemVer 2.0 version comparison.** Version-constraint checks implement full
  SemVer 2.0 precedence (including prerelease ordering) and **reject** malformed
  versions instead of coercing/stripping them.
- **KeyRing issuance-window semantics.** Signatures are verified first, then the
  signed `Payload.IssuedAt` is checked against the key's `NotBefore`/`NotAfter`
  window; `Revoked` remains an immediate kill switch. Lookup is split into
  `LookupPublicKey(id)` + `CheckKeyPolicy(entry, issuedAt)`.
- **Durable file writes.** `keygen` and license writes use `O_EXCL` (no-clobber)
  and atomic temp-file + `fsync` + `rename` (with parent-dir fsync) so a crash
  cannot leave a partially written or half-overwritten key/license.
- **Fingerprint v2 is the default for new integrations.** Version-agnostic
  entry points `ComputeDefault` / `ComputeHMACDefault` / `RequestCodeDefault`
  (and `Manager.GetDeviceRequestCode`, the `license-tool fingerprint` command,
  and the client example) now resolve to the more stable v2 per-platform
  primary identifier. The legacy `Compute` / `RequestCode` remain pinned to v1
  for compatibility; the CLI keeps `-v2` as a no-op and adds `-v1` to opt back
  into the drift-prone all-components scheme.
- **Signing enforces static validity.** `Signer.SignPayload` now runs
  `ValidatePayloadStatic` before canonicalizing/signing (matching the
  `BuildPayload` contract), so a structurally invalid payload can no longer be
  signed through that path. `Issue(nil, req)` and `(*Signer)(nil).KeyID()` are
  nil-safe instead of panicking.
- **Device-binding cardinality is enforced.** `DeviceModeNone` must carry no
  device IDs, `DeviceModeSingle` requires exactly one, and `DeviceModeMulti`
  requires at least one; violations are rejected by static validation.
- **Bounded CLI file reads.** `verify`, `inspect`, `issue`, `revoke-list`, and
  public-key loading read through a shared `Stat` + `io.LimitReader` helper so an
  oversized input is rejected before it is buffered, rather than being read in
  full and only then size-checked by the parser.
- **Anti-rollback state store hardening.** `RollbackStore` now shares the same
  per-path mutex as `FileRevocationStateStore` (serializing writers to the same
  file within a process), and its `atomicWriteFile` handles the parent-directory
  fsync consistently with the rest of the codebase — returning the error on
  POSIX (so "durable" is truthful) and skipping it on Windows. The
  single-process-writer limitation is now documented.

### Added

- New stable error codes (appended, never repurposed): `CodeProductRequired`,
  `CodeNonCanonicalPayload`, `CodeRevocationStale`, `CodeRevocationFromFuture`,
  `CodeRevocationExpired`, `CodeRevocationRollback`,
  `CodeRevocationStateIntegrityFailure`, `CodeLimitRequired`.
- Fingerprint **v2**: per-platform primary identifier (Linux `machine-id`,
  macOS `platform_uuid`, Windows `MachineGuid`) with placeholder filtering; v1
  strict-all-components behavior is unchanged. `RequestCode` is tagged with the
  version (`V1-`/`V2-`), keyed fingerprints use an `hmac-sha256:` algorithm tag,
  and every persisted fingerprint value now carries a versioned scheme prefix
  `fp:v<N>:` (e.g. `fp:v1:sha256:<hex>`, `fp:v2:hmac-sha256:<hex>`) so a value
  written into a license's `device_ids` records which fingerprint scheme
  produced it and cannot be silently invalidated when the default scheme
  evolves. `license-tool fingerprint` gains a `-v2` flag.
- Repository governance: `.github/dependabot.yml` (weekly grouped Actions + Go
  toolchain updates), issue templates + `PULL_REQUEST_TEMPLATE.md`, and a
  `COMPATIBILITY.md` policy for the schema / error-code / CLI / Go API surfaces.
- Supply-chain hardening in CI: all third-party Actions pinned to full commit
  SHAs, per-job minimal `permissions`, `govulncheck` (pinned to `v1.7.0`), a
  4-target fuzz matrix (plus a nightly longer campaign), a `goreleaser
  --snapshot` packaging check (GoReleaser pinned to `v2.17.1`), a release-time
  re-run of the full quality gate, and a release-archive allowlist
  (`scripts/check-archive-allowlist.sh`). Full SBOM generation, `cosign`
  keyless signing, and provenance attestation are **not yet implemented** and
  remain tracked for the maintainer (they need repository OIDC configuration and
  a real release run).
- Single source of truth for quality metrics: `scripts/generate-quality-docs.sh`
  regenerates the coverage blocks of `docs/*/quality.md` from
  `.github/go-test-report.json`. The JSON now also carries an `environment`
  block (commit, generation time, Go version, OS/arch), stamped in CI by
  `scripts/inject-report-environment.sh`, so the "environment of record" shown
  in `quality.md` is generated from that JSON instead of being hand-maintained.
- The Go Report Card Markdown report (`.github/goreportcard-report.md`) is now
  regenerated alongside the badge by the `goreportcard` workflow (via the
  action's `report` output) and committed through the same restricted
  write-back allowlist, so the report the README links to can no longer drift
  from the current code (previously it was a hand-maintained snapshot that still
  listed already-refactored complexity warnings).

### Changed

- Security documentation now matches enforced behavior: the absolute
  "never panics" phrasing is replaced with "returns errors on every supported
  entry point, continuously fuzz/race verified"; fingerprint docs state that raw
  values are **not returned by the API** (rather than claiming the hash is
  irreversible); revocation docs distinguish **signature authenticity** vs
  **distribution freshness** vs **local anti-rollback**; and the CI artifact
  scan is described as scanning the **final release archives** plus enforcing an
  allowlist.
- Coverage figures are no longer hardcoded to `77.5%`/commit `e5c6e93` in the
  README/quality docs; they are published from `.github/go-test-report.json`
  (the value quoted here, ~84.02% total with an 80% gate, was the measurement at
  the time of this changelog entry; the current measured total and gate are
  generated into `docs/*/quality.md` from that JSON and may be higher).
- CI coverage now uses the GTR (Go Test Report) Action
  (`soulteary/go-test-report-action`) instead of hand-rolled scripts. The
  `coverage` job runs tests once with the race detector over
  `./cmd/... ./internal/... ./pkg/...` (the tests-free `examples/` demo is left
  out of the package set) and enforces a total gate of 80% plus a per-package
  gate of 70%; the default-branch `coverage-report` job writes back
  `.github/coverage.svg`, `.github/go-test-report.md`, and
  `.github/go-test-report.json`. The removed helper scripts
  `scripts/check-coverage.sh` and `scripts/gen-coverage-badge.sh` are superseded
  by this Action.
- CI 覆盖率改用 GTR (Go Test Report) Action
  (`soulteary/go-test-report-action`) 取代手写脚本:`coverage` 作业带竞态检测在
  `./cmd/... ./internal/... ./pkg/...` 上跑一次测试(不含无测试的 `examples/`
  演示),执行总覆盖率 80% 与单包 70% 门禁;默认分支的 `coverage-report` 作业写回
  `.github/coverage.svg`、`.github/go-test-report.md` 与
  `.github/go-test-report.json`。已删除的辅助脚本 `scripts/check-coverage.sh`
  与 `scripts/gen-coverage-badge.sh` 由该 Action 取代。
- Sensitive-file scan (`scripts/check-sensitive-files.sh`) now performs a
  git-tracked audit by default: it enumerates only tracked files
  (`git ls-files -z`) and fails if any private-key filename or PEM private-key
  header was committed (including keys force-added past `.gitignore`), while
  git-ignored local example keys never trip the gate. The `keys/` blanket
  exemption was removed; the `dist/`/explicit-path artifact scan (used by the
  CI full-tree `.` audit) is preserved for backward compatibility.
- 敏感文件扫描(`scripts/check-sensitive-files.sh`)默认改为基于 git 跟踪的审计:
  仅枚举已跟踪文件(`git ls-files -z`),命中私钥文件名或 PEM 私钥头即失败(含
  用 `-f` 绕过 `.gitignore` 强制添加的密钥),而本地 gitignored 的示例密钥不会
  误报;移除了对 `keys/` 的无条件豁免,并保留 `dist/`/显式路径的产物扫描
  (兼容 CI 的全树 `.` 审计)。
- Example and documentation keys are now generated at runtime into gitignored
  directories: `examples/run-scenarios.sh` writes to `examples/out/keys`, and
  the READMEs (`README.md`, `docs/enUS/README.md`, `docs/zhCN/README.md`) show
  `keygen ... -out-dir ./_keys` before referencing `./_keys/k1-*.key`. This
  removes the impression that the repo ships fixed `keys/k1-*.key` private keys.
- 示例与文档密钥改为运行时生成到 gitignored 目录:`examples/run-scenarios.sh`
  写入 `examples/out/keys`,三份 README(`README.md`、`docs/enUS/README.md`、
  `docs/zhCN/README.md`)先 `keygen ... -out-dir ./_keys` 再引用
  `./_keys/k1-*.key`,消除"仓库自带固定 `keys/k1-*.key` 私钥"的错误印象。
- Documentation rewritten to be evidence-based: removed unsubstantiated quality
  labels ("commercial-grade" / "商业级") in favor of verifiable positioning, and
  reorganized `README.md`, `docs/enUS/README.md`, and `docs/zhCN/README.md`.
- Rewrote `SECURITY.md` around an explicit threat table, trust boundaries, and a
  deployment checklist; synced the `docs/*/SECURITY.md` summaries.

### Added

- Architecture, quality, and performance docs under `docs/enUS/` and
  `docs/zhCN/` (`architecture.md`, `quality.md`, `performance.md`), backfilled
  with measured coverage and benchmark numbers from a recorded commit/environment.
- Benchmarks: `pkg/license/benchmark_test.go` and
  `pkg/fingerprint/benchmark_test.go` (parse, verify, in-memory validate,
  validate-with-revocation at 0/100/10000 entries, canonical bytes, cached
  result, key-ring lookup, fingerprint canonicalization).
- Expanded tests: `cmd/license-tool` CLI (was 0% coverage), `internal/issuer`,
  canonical golden vectors, envelope/keyring/rollback/revocation/version/facade
  edge cases; total statement coverage raised from ~53.6% to 77.5%.
- Fuzz targets for canonical bytes / payload decode, revocation-list parsing,
  and rollback-state parsing (in addition to `FuzzParseEnvelope`).
- CI jobs: coverage gate (`>= 77%`, floor of measured total) with profile
  artifact, an auto-generated coverage SVG badge (committed only on default
  branch/tag pushes), doc-language check (blocks unverifiable quality labels),
  sensitive-file scan (no private keys), Markdown link check, and a benchmark
  smoke run.
- Helper scripts under `scripts/`: `check-coverage.sh`, `check-doc-language.sh`
  (+ `doc-language-allowlist.txt`), `check-sensitive-files.sh`,
  `gen-coverage-badge.sh`.

The documentation/testing/CI groundwork above changed no public API, license
file format, error code, or CLI behavior. The **protocol hardening** items at
the top of this release do — see **Migration** below.

### Migration

The signing domain separation and revocation v2 are a **one-time, clean
protocol upgrade** — they are not wire-compatible with pre-upgrade artifacts:

- **Re-issue licenses and re-sign revocation lists** with the upgraded
  `license-tool`. Signatures produced before the domain-separation change will
  not verify against the new verifier, and vice versa.
- **Revocation lists must be v2.** Re-generate them (they gain `list_id`,
  `sequence`, `issued_at`, `expires_at`). If you must temporarily keep serving a
  legacy v1 list, opt in explicitly with `AllowLegacyV1Revocation()`; this is a
  stopgap, not a supported long-term mode.
- **Verification now requires a ProductID by default.** The library returns
  `LICENSE_PRODUCT_REQUIRED` (`CodeProductRequired`) when `ValidationContext`
  carries no `ProductID`, unless you explicitly opt out with
  `WithUnscopedProductValidation`; the CLI `verify` command now requires
  `-product`. Scope every verification to the product it authorizes.
- **Audit limit checks.** If you relied on `CheckLimit` returning "allowed" for
  an *undeclared* limit key, switch security-relevant checks to `RequireLimit` /
  `CheckLimitStrict`, which are fail-closed (`LICENSE_LIMIT_REQUIRED`).
- **Version constraints must be valid SemVer 2.0.** Previously tolerated
  malformed versions (e.g. two-part `1.2`, leading zeros) are now rejected;
  normalize your `version_constraint` values.
- **Fingerprint value format changed.** Persisted fingerprint strings now carry
  a versioned scheme prefix `fp:v<N>:` in front of the algorithm tag: the plain
  digest is `fp:v1:sha256:<hex>` / `fp:v2:sha256:<hex>` and the keyed digest is
  `fp:v1:hmac-sha256:<hex>` / `fp:v2:hmac-sha256:<hex>` (previously the value was
  just `sha256:<hex>` with no version, and keyed v2 was `hmac-sha256:<hex>`).
  Re-issue any device-bound licenses so their `device_ids` use the new
  self-describing form, and update any stored comparisons; the plain-text
  request codes (`V1-`/`V2-...`) are unchanged.

## [0.1.0] - 2026-08-21

Initial public release of `grantseal`, an **offline software licensing** system
written in Go 1.26 using **only the standard library**.

首个公开版本。使用 Go 1.26 **纯标准库**实现的**离线软件授权系统**。

### Added

- Ed25519-signed license issuing, verification, and management.
- License wire format `Envelope{algorithm, key_id, payload, signature}` with a
  canonical (deterministic sorted-key) JSON payload. The on-disk license schema
  is fixed at **`schema_version = 1`**; unknown versions are rejected. The
  Ed25519 signature covers the canonical payload bytes **directly**, without a
  signing-domain prefix. (Both are changed by the 0.9.0 protocol upgrade
  above — schema `2` and a `grantseal/license/v2\x00` signing domain.)
- `pkg/license`: client-side, fail-closed verification (public keys only, never
  contains private keys) with a read-only `ValidationResult` facade
  (`RequireFeature`, `CheckLimit`, `GetEdition`, `GetExpiration`,
  `GetRemainingDays`, `RemainingTime`, `KeyID`, `DeviceMatched`).
- `pkg/fingerprint`: cross-platform device fingerprint (Linux/macOS/Windows +
  fallback).
- `internal/issuer`: issuer-side private-key logic (keygen, signing, issuing,
  revocation lists), isolated via Go `internal/`.
- `cmd/license-tool` CLI with 8 subcommands: `keygen`, `public-key`, `issue`,
  `verify`, `inspect`, `fingerprint`, `revoke-list`, `version`.
- Policy features: device binding (`none`/`single`/`multi`), feature/limit
  gating, expiry with grace periods, clock-rollback detection, and signed
  revocation lists.
- 31 stable `LICENSE_*` wire codes (`LICENSE_OK` plus 30 failure codes). The
  feature-gate failure surfaces as `LICENSE_FEATURE_UNAVAILABLE`; in Go it is
  reachable via both `CodeFeatureUnavailable` and its alias identifier
  `CodeFeatureDenied`, which resolve to the same wire code (there is not a
  separate `LICENSE_FEATURE_DENIED` wire string — that spelling is not emitted).
- `examples/`: client integration sample and multi-scenario batch-issue configs
  with an assertion script.

### Schema

- `schema_version = 1` — the license schema version shipped in this release.
  The signature covers the canonical payload bytes directly (no signing-domain
  prefix). Any future breaking change to the payload layout bumps this value and
  is recorded here (see the 0.9.0 entry, which raises it to `2` and adds
  signing-domain separation).

[Unreleased]: https://github.com/soulteary/grantseal/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/soulteary/grantseal/compare/v0.1.0...v0.9.0
[0.1.0]: https://github.com/soulteary/grantseal/releases/tag/v0.1.0
