# grantseal

[![CI](https://github.com/soulteary/grantseal/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/soulteary/grantseal/actions/workflows/ci.yml) [![Release](https://github.com/soulteary/grantseal/actions/workflows/release.yml/badge.svg)](https://github.com/soulteary/grantseal/actions/workflows/release.yml) [![Go Report Card](./.github/goreportcard.svg)](./.github/goreportcard-report.md) [![Coverage](./.github/coverage.svg)](./.github/go-test-report.md) [![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE) [![Go Version](https://img.shields.io/badge/go-1.26-00ADD8.svg)](https://go.dev/)

[English](#english) | [简体中文](#简体中文) — full docs: [English](./docs/enUS/README.md) | [中文文档](./docs/zhCN/README.md) — [Changelog](./CHANGELOG.md)

---

## English

`grantseal` is an **offline software licensing** library and CLI written in
Go 1.26 using **only the standard library** (`crypto/ed25519`, `crypto/rand`,
`crypto/sha256`, `crypto/hmac`, `crypto/subtle`, `encoding/json`). No third-party
dependencies. It issues Ed25519-signed licenses on the issuer side and verifies
them client-side with a **fail-closed**, never-panicking verifier.

Its goal is to **raise the cost of forgery and offline tampering**, not to make
software uncrackable. See [`SECURITY.md`](./SECURITY.md) for the honest threat
model and limits.

### Is grantseal for you?

**A good fit when you:**

- Ship software that must run **offline** or air-gapped and still gate features,
  seats/limits, editions, expiry, or device binding.
- Want licenses that are **cryptographically signed** (Ed25519) so a customer
  cannot mint or edit their own.
- Prefer a **zero-dependency** Go library you can embed and audit, with stable,
  machine-readable error codes for your UX.

**Not a fit when you:**

- Need to guarantee software cannot be cracked. A determined attacker can patch
  the client binary to skip verification — inherent to all offline licensing.
- Want a hosted license server, per-request online activation, or metering. This
  library is offline-first; online activation is on the [Roadmap](#roadmap).
- Rely on the system clock being trustworthy against a root/admin adversary.
  Rollback detection catches naive backward jumps, not a privileged attacker.

### Evidence, not slogans

| Claim | How you can verify it |
| ----- | --------------------- |
| Zero third-party dependencies | `go.mod` has no `require` block for external modules; build with `go build ./...`. |
| Ed25519-only, no algorithm downgrade | `pkg/license/verifier.go` rejects any non-`Ed25519` algorithm; see error `LICENSE_UNSUPPORTED_ALGORITHM`. |
| Private keys never link into a client | Clients import `pkg/license`; signing lives under `internal/issuer` (unimportable). CI scans the final release archives for key material and enforces an archive allowlist. |
| Signature covers the whole payload | Deterministic canonical JSON is signed verbatim; any edit yields `LICENSE_SIGNATURE_INVALID`. See [`architecture`](./docs/enUS/architecture.md). |
| Fail-closed error reporting | The verifier returns a stable `LICENSE_*` code on every supported entry point instead of panicking on malformed input (continuously fuzz/race verified in CI). |
| Golden envelope vectors carry no private key | Test vectors embed only public keys, canonical payloads, and signatures. See [`architecture`](./docs/enUS/architecture.md#envelope-format). |

### Components

| Package / Command      | Role                                                                 |
| ---------------------- | -------------------------------------------------------------------- |
| `pkg/license`          | **Client-side** verification only. Public keys, signature checking, validation orchestration, fail-closed. **Never contains private keys.** |
| `pkg/fingerprint`      | Cross-platform device fingerprint (Linux/macOS/Windows + fallback).  |
| `internal/issuer`      | **Issuer-side** private-key logic (keygen, signing, issuing, revocation lists). Isolated via Go `internal/`. |
| `cmd/license-tool`     | Issuer CLI: `keygen`, `public-key`, `issue`, `verify`, `inspect`, `fingerprint`, `revoke-list`, `version`. |
| `examples/`            | Client integration & batch-issue config examples. See [`examples/README.md`](./examples/README.md). |

### Quick start

```bash
# Issuer: generate a key pair into a gitignored dir (private key stays local).
# ./_keys is gitignored; never commit a private key.
go run ./cmd/license-tool keygen -key-id k1 -out-dir ./_keys

# Issue a license
go run ./cmd/license-tool issue -config examples/issue-config.json \
  -key ./_keys/k1-private.key -out customer.lic

# Client: verify + policy-validate
go run ./cmd/license-tool verify -license customer.lic -pubkey ./_keys/k1-public.key \
  -product acme-app -version 1.4.0
```

### Minimal client integration

The client embeds only public keys and never touches the private key. Always
branch on the stable error code and provide a recovery path — do not ignore the
error.

```go
ring := license.NewKeyRing()
_ = ring.AddPublicKeyBase64("k1", embeddedPublicKeyB64)

mgr := license.NewManager(ring)
res, err := mgr.LoadAndValidate("customer.lic", license.ValidationContext{
    ProductID:      "acme-app",
    ProductVersion: "1.4.0",
})
if err != nil {
    switch license.CodeOf(err) {
    case license.CodeExpired:
        // prompt the user to renew; show the expiry date
    case license.CodeDeviceMismatch:
        // show a device request code and ask the user to re-bind
    case license.CodeClockRollback:
        // warn about the system clock; block time-bound features
    default:
        // treat as invalid; offer to re-import a license file
    }
    return
}

if err := res.RequireFeature("api"); err != nil {
    // license.CodeOf(err) == license.CodeFeatureDenied
}
// Fail-closed seat enforcement: an undeclared "max_seats" limit yields
// CodeLimitRequired (not silently unlimited). Use CheckLimit instead if you
// want the lenient "undeclared == unlimited" behavior.
if err := res.RequireLimit("max_seats", seatsInUse); err != nil {
    // license.CodeOf(err) == license.CodeLimitExceeded / CodeLimitRequired /
    // CodeInvalidLimits
}
```

### Issuer vs. client boundary

- **Issuer side** (`internal/issuer` + `cmd/license-tool`): holds the private
  key, runs `keygen`/`issue`/`revoke-list`. Runs only on trusted issuer
  machines. The private key is written mode `0600` and never overwritten without
  `-force`.
- **Client side** (`pkg/license`): embeds public keys only, verifies and gates.
  Cannot import `internal/issuer` (enforced by Go's `internal/` mechanism), so
  private-key logic never links into a client binary.

### What business questions it answers

| Business need | Mechanism | On failure |
| ------------- | --------- | ---------- |
| "Is this license genuine and unmodified?" | Ed25519 signature over the canonical payload | `LICENSE_SIGNATURE_INVALID` / `LICENSE_MALFORMED` |
| "Has this customer's subscription expired?" | `license_type` time semantics + `expires_at` + grace period | `LICENSE_EXPIRED` / status `grace` |
| "Is this edition/feature allowed?" | Edition defaults unioned with `features`; `RequireFeature` | `LICENSE_FEATURE_DENIED` |
| "Are they within seat/usage limits?" | Range-validated `limits`; `CheckLimit` | `LICENSE_LIMIT_EXCEEDED` |
| "Is this running on a licensed device?" | Device binding (`none`/`single`/`multi`) + fingerprint | `LICENSE_DEVICE_MISMATCH` |
| "Is this build within the covered version range?" | `version_constraint` with maintenance/covered ceiling (fail-closed) | `LICENSE_VERSION_UNSUPPORTED` |
| "Has this specific license been revoked?" | Signed offline revocation list | `LICENSE_REVOKED` |
| "Did someone roll the clock back to dodge expiry?" | Integrity-protected local rollback state (naive rollback only) | `LICENSE_CLOCK_ROLLBACK` |

### Security model (summary)

- **Ed25519 signatures only.** PKCS#1v1.5, MD5, SHA-1, ECB and home-grown crypto are forbidden.
- Signature covers the **complete canonical payload** (deterministic sorted-key JSON): it provides **origin authentication and integrity, not confidentiality** — payloads are readable.
- Constant-time comparison (`subtle.ConstantTimeCompare`) for sensitive comparisons.
- Private key **never** appears in client code, binaries, git, logs, or test fixtures; signing is confined to `internal/issuer` + the CLI.
- `limits` range validation, unknown enums rejected, license-file size cap, atomic writes.
- **`license_type` time semantics enforced**: `trial`/`subscription` require `expires_at`; `lifetime` must not carry one and never expires.
- Validation results are **read-only**; the verifier is **fail-closed** and returns a stable error on every supported entry point instead of panicking (continuously fuzz/race verified in CI).

**Limits (by design):** binary patching / reverse engineering, privileged clock
manipulation beyond the rollback heuristic, fingerprint drift, and offline
revocation freshness (a client only knows about revocations in the list it has).
See [`SECURITY.md`](./SECURITY.md) and [`docs/enUS/architecture.md`](./docs/enUS/architecture.md).

### Testing, coverage & performance

CI runs unit tests on Linux, macOS, and Windows, race detection on Linux, and a
short fuzz target for envelope parsing. Coverage and benchmark results are
generated from the referenced commit; see Quality and Performance for full detail.

- **Coverage:** `go test ./... -covermode=atomic` currently reports **80.8%**
  total statement coverage; the CI gate enforces `>= 80%`. These figures are
  published from a single machine-readable source of truth
  ([`.github/go-test-report.json`](./.github/go-test-report.json)) and the
  Coverage badge above is generated by CI from the same run. Per-package numbers
  are in [`docs/enUS/quality.md`](./docs/enUS/quality.md).
- **Performance:** on Apple M5 / darwin/arm64 / `go1.26.6`, in-memory validation
  of the typical fixture measures ~`33904 ns/op`, `6072 B/op`, `41 allocs/op`;
  in-memory signature verify ~`34552 ns/op`; envelope parse ~`2738 ns/op`
  (median of `-count=5`). These numbers describe the recorded environment rather
  than a cross-device guarantee. Full methodology and per-path results (with
  environment and commit SHA) live in
  [`docs/enUS/performance.md`](./docs/enUS/performance.md).

Verification has distinct cost/side-effect profiles depending on the path:

1. **In-memory signature verify only** — `Verifier.Verify` over an in-memory
   envelope. No disk I/O, no policy checks.
2. **Full policy validation** — signature verify plus enum/time/device/version
   policy checks against in-memory input.
3. **File load + rollback state persistence** — `Manager.LoadAndValidate` reads
   the license file and may read/write the anti-rollback state file (disk I/O).
4. **Device fingerprint collection** — `pkg/fingerprint` reads platform hardware
   identifiers; cost and availability depend on the host OS.

### Install

`license-tool` is the **issuer-side** CLI (it holds private-key logic and is only
for authorized issuers). Pick whichever install method fits your workflow.

**Download a release binary** — grab the archive for your OS/arch from the
[releases page](https://github.com/soulteary/grantseal/releases), extract, and
run `license-tool`.

**Homebrew (macOS / Linux):**

```bash
brew tap soulteary/tap
brew install soulteary/tap/grantseal
```

After installation the `license-tool` command is available globally.

**Docker:**

```bash
docker pull soulteary/grantseal:latest
```

For full Docker usage (issuer keygen/issue and client verify, with private-key
safety notes) see [`docs/enUS/README.md`](./docs/enUS/README.md#install--docker).

### Documentation

- Full English guide: [`docs/enUS/README.md`](./docs/enUS/README.md)
- Architecture & envelope format: [`docs/enUS/architecture.md`](./docs/enUS/architecture.md)
- Quality & coverage: [`docs/enUS/quality.md`](./docs/enUS/quality.md)
- Performance & benchmarks: [`docs/enUS/performance.md`](./docs/enUS/performance.md)
- Security policy: [`SECURITY.md`](./SECURITY.md)
- Compatibility policy: [`COMPATIBILITY.md`](./COMPATIBILITY.md)
- Examples: [`examples/README.md`](./examples/README.md)

### Roadmap

- Inject a network-backed `TrustedTimeProvider` for authoritative time.
- Fetch signed revocation lists / public-key updates over a signed OTA channel.
- A device re-binding endpoint so users can move licenses between machines.

---

## 简体中文

`grantseal` 是使用 Go 1.26 **纯标准库**（`crypto/ed25519`、`crypto/rand`、
`crypto/sha256`、`crypto/hmac`、`crypto/subtle`、`encoding/json`）实现的**离线软件
授权**库与 CLI，不引入任何第三方依赖。它在签发端生成 Ed25519 签名的授权文件，在
客户端以 **fail-closed**、对受支持入口返回错误而非 panic 的验证器进行校验。

它的目标是**提高伪造与离线篡改的成本**，而非让软件不可破解。诚实的威胁模型与边界
见 [`SECURITY.md`](./SECURITY.md)。

### 是否适合你？

**适合的场景：**

- 软件需要**离线/隔离网络**运行，同时仍要对功能、席位/额度、版本（edition）、
  到期、设备绑定做门禁。
- 希望授权文件经 **Ed25519 密码学签名**，客户无法自行伪造或修改。
- 偏好**零依赖**、可嵌入且可审计的 Go 库，并提供稳定、机器可读的错误码用于 UX。

**不适合的场景：**

- 需要保证软件不被破解。有决心的攻击者可以修改客户端二进制以跳过校验——这是所有
  离线授权固有的局限。
- 需要托管的授权服务器、逐次在线激活或计量。本库以离线为先；在线激活见
  [路线图](#路线图)。
- 依赖系统时钟对抗 root/admin 级攻击者。回拨检测只能捕获朴素的时间回拨，无法防住
  特权攻击者。

### 证据而非口号

| 主张 | 你如何验证 |
| ---- | ---------- |
| 零第三方依赖 | `go.mod` 无外部模块 `require`；用 `go build ./...` 构建即可确认。 |
| 仅 Ed25519、不降级算法 | `pkg/license/verifier.go` 拒绝任何非 `Ed25519` 算法；对应错误码 `LICENSE_UNSUPPORTED_ALGORITHM`。 |
| 私钥绝不链接进客户端 | 客户端只 import `pkg/license`；签名逻辑在 `internal/issuer`（不可被 import）。CI 扫描最终发布归档中的密钥材料并强制归档白名单。 |
| 签名覆盖整个 payload | 确定性规范化 JSON 被逐字签名；任何改动都会得到 `LICENSE_SIGNATURE_INVALID`。见[架构文档](./docs/zhCN/architecture.md)。 |
| fail-closed 错误上报 | 每个受支持入口对非法输入返回稳定的 `LICENSE_*` 错误码而非 panic（CI 持续以 fuzz/race 验证）。 |
| golden 信封向量不含私钥 | 测试向量仅嵌入公钥、规范化 payload 与签名。见[架构文档](./docs/zhCN/architecture.md#信封格式)。 |

### 组件

| 包 / 命令 | 职责 |
| --------- | ---- |
| `pkg/license` | **客户端**验证（公钥、签名校验、校验编排、fail-closed），**绝不含私钥**。 |
| `pkg/fingerprint` | 跨平台设备指纹（Linux/macOS/Windows + 回退）。 |
| `internal/issuer` | **签发端**私钥逻辑（keygen、签名、签发、撤销列表），通过 Go `internal/` 隔离。 |
| `cmd/license-tool` | 签发端 CLI：`keygen`、`public-key`、`issue`、`verify`、`inspect`、`fingerprint`、`revoke-list`、`version`。 |
| `examples/` | 客户端集成与批量签发配置示例，见 [`examples/README.md`](./examples/README.md)。 |

### 快速开始

```bash
# 签发端:把密钥对生成到 gitignored 目录(私钥留在本地机器)。
# ./_keys 已 gitignore;私钥绝不可提交。
go run ./cmd/license-tool keygen -key-id k1 -out-dir ./_keys

# 签发授权
go run ./cmd/license-tool issue -config examples/issue-config.json \
  -key ./_keys/k1-private.key -out customer.lic

# 客户端:验证 + 策略校验
go run ./cmd/license-tool verify -license customer.lic -pubkey ./_keys/k1-public.key \
  -product acme-app -version 1.4.0
```

### 最小客户端集成

客户端只内置公钥，绝不接触私钥。务必根据稳定错误码分支处理并提供恢复路径——不要
忽略错误。

```go
ring := license.NewKeyRing()
_ = ring.AddPublicKeyBase64("k1", embeddedPublicKeyB64)

mgr := license.NewManager(ring)
res, err := mgr.LoadAndValidate("customer.lic", license.ValidationContext{
    ProductID:      "acme-app",
    ProductVersion: "1.4.0",
})
if err != nil {
    switch license.CodeOf(err) {
    case license.CodeExpired:
        // 引导用户续期，并展示到期日
    case license.CodeDeviceMismatch:
        // 展示设备申请码，请用户重新绑定
    case license.CodeClockRollback:
        // 提示系统时钟异常，禁用与时间相关的功能
    default:
        // 判为无效；引导重新导入许可文件
    }
    return
}

if err := res.RequireFeature("api"); err != nil {
    // license.CodeOf(err) == license.CodeFeatureDenied
}
// 席位配额 fail-closed：未声明 "max_seats" 会返回 CodeLimitRequired（而非静默无限制）。
// 若需要“未声明即无限制”的宽松语义，请改用 CheckLimit。
if err := res.RequireLimit("max_seats", seatsInUse); err != nil {
    // license.CodeOf(err) == license.CodeLimitExceeded / CodeLimitRequired /
    // CodeInvalidLimits
}
```

完整库指南见 [`docs/zhCN/README.md`](./docs/zhCN/README.md)，示例见
[`examples/client/main.go`](./examples/client/main.go)。

### 签发端与客户端边界

- **签发端**（`internal/issuer` + `cmd/license-tool`）：持有私钥，运行
  `keygen`/`issue`/`revoke-list`，仅在受信任的签发机器上运行。私钥以 `0600` 权限
  写入，且不加 `-force` 不会覆盖。
- **客户端**（`pkg/license`）：只内置公钥，负责验证与门禁。借助 Go 的 `internal/`
  机制，客户端无法 import `internal/issuer`，私钥逻辑绝不链接进客户端二进制。

### 它能回答哪些业务问题

| 业务需求 | 机制 | 失败时 |
| -------- | ---- | ------ |
| “这份授权是否真实、未被修改？” | 对规范化 payload 的 Ed25519 签名 | `LICENSE_SIGNATURE_INVALID` / `LICENSE_MALFORMED` |
| “该客户的订阅是否已到期？” | `license_type` 时间语义 + `expires_at` + 宽限期 | `LICENSE_EXPIRED` / 状态 `grace` |
| “这个版本/功能是否被允许？” | edition 默认功能与 `features` 取并集；`RequireFeature` | `LICENSE_FEATURE_DENIED` |
| “是否在席位/用量额度内？” | 带范围校验的 `limits`；`CheckLimit` | `LICENSE_LIMIT_EXCEEDED` |
| “是否运行在被授权的设备上？” | 设备绑定（`none`/`single`/`multi`）+ 指纹 | `LICENSE_DEVICE_MISMATCH` |
| “这个构建是否在覆盖的版本范围内？” | 带维护/覆盖上限的 `version_constraint`（fail-closed） | `LICENSE_VERSION_UNSUPPORTED` |
| “这份具体授权是否已被撤销？” | 签名的离线撤销列表 | `LICENSE_REVOKED` |
| “有人把时钟回拨以规避到期吗？” | 完整性保护的本地回拨状态（仅朴素回拨） | `LICENSE_CLOCK_ROLLBACK` |

### 安全模型（摘要）

- **仅使用 Ed25519 签名**。禁止 PKCS#1v1.5、MD5、SHA-1、ECB 及自制算法。
- 签名覆盖**完整规范化 payload**（键排序的确定性 JSON）：提供**来源认证与完整性，
  而非保密性**——payload 可被读取。
- 敏感比较使用常量时间比较（`subtle.ConstantTimeCompare`）。
- 私钥**绝不**出现在客户端代码、二进制、git、日志或测试固定数据中；签名仅存在于
  `internal/issuer` 与 CLI。
- `limits` 范围校验、拒绝未知枚举、许可文件大小上限、原子写入。
- **强制 `license_type` 时间语义**：`trial`/`subscription` 必须带 `expires_at`；
  `lifetime` 不得带且永不过期。
- 验证结果**只读**；验证器 **fail-closed**，对受支持入口返回稳定错误而非 panic（CI 持续以 fuzz/race 验证）。

**固有边界：** 二进制修补 / 逆向工程、超出回拨启发式的特权时钟篡改、指纹漂移，以及
离线撤销新鲜度（客户端只知道它手中列表里的撤销）。详见 [`SECURITY.md`](./SECURITY.md)
与 [`docs/zhCN/architecture.md`](./docs/zhCN/architecture.md)。

### 测试、覆盖率与性能

CI 在 Linux、macOS 和 Windows 上运行测试，在 Linux 上执行竞态检测，并对授权信封解析
执行短时 fuzz。覆盖率与性能数据详见《质量说明》与《性能基准》。

- **覆盖率：** `go test ./... -covermode=atomic` 当前总语句覆盖率为 **80.8%**，CI
  门禁强制 `>= 80%`。这些数字来自唯一机器可读事实来源
  （[`.github/go-test-report.json`](./.github/go-test-report.json)），顶部 Coverage
  徽章由 CI 基于同一次运行生成。分包数字见
  [`docs/zhCN/quality.md`](./docs/zhCN/quality.md)。
- **性能：** 在 Apple M5 / darwin/arm64 / `go1.26.6` 环境中，典型授权样本的纯内存完整
  校验约为 `33904 ns/op`、`6072 B/op`、`41 allocs/op`；纯内存验签约 `34552 ns/op`；
  信封解析约 `2738 ns/op`（`-count=5` 中位数）。该结果用于说明测试环境中的实现成本，
  不承诺所有设备获得相同数值。完整方法与各路径结果（含环境与 commit SHA）见
  [`docs/zhCN/performance.md`](./docs/zhCN/performance.md)。

验证在不同路径上有各异的开销与副作用：

1. **纯内存验签** —— 对内存中的信封调用 `Verifier.Verify`，无磁盘 I/O、无策略校验。
2. **完整策略校验** —— 验签之外再对内存输入做枚举/时间/设备/版本策略校验。
3. **文件读取 + 回拨状态落盘** —— `Manager.LoadAndValidate` 读取许可文件，并可能
   读写防回拨状态文件（涉及磁盘 I/O）。
4. **设备指纹采集** —— `pkg/fingerprint` 读取平台硬件标识；开销与可用性取决于宿主
   操作系统。

### 安装

`license-tool` 是**签发端** CLI（含私钥逻辑，仅供授权签发方使用）。可按需选择安装方式。

**下载发布二进制** —— 从[发布页](https://github.com/soulteary/grantseal/releases)下载对应
OS/架构的压缩包，解压后运行 `license-tool`。

**Homebrew（macOS / Linux）：**

```bash
brew tap soulteary/tap
brew install soulteary/tap/grantseal
```

安装后即可全局使用 `license-tool` 命令。

**Docker：**

```bash
docker pull soulteary/grantseal:latest
```

完整 Docker 用法（签发端 keygen/issue 与客户端 verify，含私钥安全提示）见
[`docs/zhCN/README.md`](./docs/zhCN/README.md#安装与-docker)。

### 文档导航

- 完整中文指南：[`docs/zhCN/README.md`](./docs/zhCN/README.md)
- 架构与信封格式：[`docs/zhCN/architecture.md`](./docs/zhCN/architecture.md)
- 质量与覆盖率：[`docs/zhCN/quality.md`](./docs/zhCN/quality.md)
- 性能与 benchmark：[`docs/zhCN/performance.md`](./docs/zhCN/performance.md)
- 安全策略：[`SECURITY.md`](./SECURITY.md)
- 兼容性政策：[`COMPATIBILITY.md`](./COMPATIBILITY.md)
- 示例：[`examples/README.md`](./examples/README.md)

### 路线图

- 注入基于网络的 `TrustedTimeProvider` 获取权威时间。
- 通过签名 OTA 通道下发撤销列表 / 公钥更新。
- 增加设备解绑/重绑接口，便于用户迁移设备。
