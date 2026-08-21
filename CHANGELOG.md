# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

本项目的所有重要变更都记录在本文件中，格式参考
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循
[语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [0.1.0]

Initial public release of `grantseal`, a commercial-grade **offline software
licensing** system written in Go 1.26 using **only the standard library**.

首个公开版本。使用 Go 1.26 **纯标准库**实现的商业级**离线软件授权系统**。

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
