# Compatibility Policy · 兼容性政策

This project versions **four independent surfaces**. Each has its own rules for
what counts as a breaking change. The Git tag (SemVer 2.0) is the umbrella
version for the module; a bump of any surface below is reflected there.

本项目对**四个独立面**分别做版本管理，每个面有各自的“破坏性变更”判定规则。Git tag
（SemVer 2.0）是模块的总版本号；下述任一面的破坏性变更都会体现在总版本号上。

---

## 1. Wire / on-disk schema · 数据格式

- Field: `schema_version` inside the signed payload; also the revocation-list
  schema and the anti-rollback state format.
- **Current:** license payload `schema_version = 1`; revocation list **v2** with
  domain-separation prefix `grantseal/revocation/v2\x00`.
- Rules · 规则:
  - A **new** schema version is introduced additively; the verifier accepts a
    bounded, explicit allowlist of versions and **rejects** everything else
    (fail-closed, never silently downgraded).
  - Legacy v1 revocation lists are rejected **by default** and only accepted
    when the caller opts in with `AllowLegacyV1Revocation()`.
  - Removing acceptance of an old schema version is a **breaking change**
    (major bump) and must ship a migration note here and in `CHANGELOG.md`.

## 2. Stable error codes · 稳定错误码

- Surface: the `LICENSE_*` strings returned by `license.CodeOf(err)`.
- Rules · 规则:
  - Error code **strings are a public contract.** They are never renamed,
    removed, or repurposed. New failure modes get **new** codes appended.
  - Callers should branch on `license.Code` constants / the `LICENSE_*` string,
    never on the human-readable message text (which may change any time).
  - Renaming or repurposing an existing code is a **breaking change**.

## 3. CLI · 命令行

- Surface: `license-tool` subcommands, flags, exit codes, and stdout format.
- Rules · 规则:
  - Existing subcommands and flags are additive-only within a major version.
  - Exit codes are stable: `0` success, `1` runtime/verification failure, `2`
    usage error.
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
