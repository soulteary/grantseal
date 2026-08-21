# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

本项目的所有重要变更都记录在本文件中，格式参考
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循
[语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Changed

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

No public API, license file format, error code, or CLI behavior changed.

## [0.1.0]

Initial public release of `grantseal`, an **offline software licensing** system
written in Go 1.26 using **only the standard library**.

首个公开版本。使用 Go 1.26 **纯标准库**实现的**离线软件授权系统**。

### Added

- Ed25519-signed license issuing, verification, and management.
- License wire format `Envelope{algorithm, key_id, payload, signature}` with a
  canonical (deterministic sorted-key) JSON payload. The on-disk license schema
  is fixed at **`schema_version = 1`**; unknown versions are rejected.
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
- 23 stable `LICENSE_*` error codes (including the backward-compatible alias
  `LICENSE_FEATURE_UNAVAILABLE`).
- `examples/`: client integration sample and multi-scenario batch-issue configs
  with an assertion script.

### Schema

- `schema_version = 1` — the current and only accepted license schema version.
  Any future breaking change to the payload layout will bump this value and be
  recorded here.

[Unreleased]: https://github.com/soulteary/grantseal/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/soulteary/grantseal/releases/tag/v0.1.0
