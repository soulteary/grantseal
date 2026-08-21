# grantseal

[![CI](https://github.com/soulteary/grantseal/actions/workflows/ci.yml/badge.svg)](https://github.com/soulteary/grantseal/actions/workflows/ci.yml) [![Release](https://github.com/soulteary/grantseal/actions/workflows/release.yml/badge.svg)](https://github.com/soulteary/grantseal/actions/workflows/release.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/soulteary/grantseal)](https://goreportcard.com/report/github.com/soulteary/grantseal) [![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE) [![Go Version](https://img.shields.io/badge/go-1.26-00ADD8.svg)](https://go.dev/)

[English](#english) | [简体中文](#简体中文) — full docs: [English](./docs/enUS/README.md) | [中文文档](./docs/zhCN/README.md)

---

## English

`grantseal` is a commercial-grade **offline software licensing** system written in
Go 1.26 using **only the standard library** (`crypto/ed25519`, `crypto/rand`,
`crypto/sha256`, `crypto/hmac`, `crypto/subtle`, `encoding/json`). No third-party
dependencies.

### Components

| Package / Command      | Role                                                                 |
| ---------------------- | -------------------------------------------------------------------- |
| `pkg/license`          | **Client-side** verification only. Public keys, signature checking, validation orchestration, fail-closed. **Never contains private keys.** |
| `pkg/fingerprint`      | Cross-platform device fingerprint (Linux/macOS/Windows + fallback).  |
| `internal/issuer`      | **Issuer-side** private-key logic (keygen, signing, issuing, revocation lists). Isolated via Go `internal/`. |
| `cmd/license-tool`     | Issuer CLI: `keygen`, `public-key`, `issue`, `verify`, `inspect`, `fingerprint`, `revoke-list`, `version`. |
| `examples/`            | Client integration & batch-issue config examples.                    |

### Security model (summary)

- **Ed25519 signatures only.** PKCS#1v1.5, MD5, SHA-1, ECB and home-grown crypto are forbidden.
- Signature covers the **complete canonical payload** (deterministic sorted-key JSON).
- Constant-time comparison (`subtle.ConstantTimeCompare`) for sensitive data.
- Private key **never** appears in client code, binaries, git, logs, or test fixtures.
- `limits` range validation, unknown enums rejected, license-file size cap, atomic writes.
- **`license_type` time semantics enforced**: `trial`/`subscription` require `expires_at`; `lifetime` must not carry one and never expires (see [`docs/enUS/README.md`](./docs/enUS/README.md)).
- Read-only result facade: `RequireFeature` (→ `LICENSE_FEATURE_DENIED`), `CheckLimit` (→ `LICENSE_LIMIT_EXCEEDED`), `GetEdition`/`GetExpiration`/`GetRemainingDays`/`RemainingTime`/`KeyID`/`DeviceMatched`.
- Validation results are **read-only**; the verifier is **fail-closed** and **never panics**.

See [`SECURITY.md`](./SECURITY.md) and [`docs/enUS/README.md`](./docs/enUS/README.md).

### Quick start

```bash
# Issuer: generate a key pair (private key stays on the issuer machine)
go run ./cmd/license-tool keygen -key-id k1 -out-dir ./keys

# Issue a license
go run ./cmd/license-tool issue -config examples/issue-config.json \
  -key ./keys/k1-private.key -out customer.lic

# Client: verify
go run ./cmd/license-tool verify -license customer.lic -pubkey ./keys/k1-public.key
```

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

### Docker usage

> **Private-key safety.** The image **never** bundles `keys/` or any `*.key`
> file. Always mount your private key at runtime with `-v` (read-only) instead
> of baking it into an image, and keep the key on a trusted issuer machine only.

```bash
# Issuer: generate a key pair into a host directory, then keep it off the image
docker run --rm -v "$PWD/keys:/work/keys" soulteary/grantseal:latest \
  keygen -key-id k1 -out-dir /work/keys

# Issue a license — private key is mounted read-only, never copied into the image
docker run --rm \
  -v "$PWD/keys:/work/keys:ro" \
  -v "$PWD:/work" \
  soulteary/grantseal:latest \
  issue -config /work/examples/issue-config.json \
  -key /work/keys/k1-private.key -out /work/customer.lic

# Client-side verification needs only the public key
docker run --rm -v "$PWD:/work" soulteary/grantseal:latest \
  verify -license /work/customer.lic -pubkey /work/keys/k1-public.key
```

---

## 简体中文

`grantseal` 是使用 Go 1.26 **纯标准库**实现的商业级**离线软件授权系统**，
不引入任何第三方依赖。

- `pkg/license`：客户端验证（公钥、签名校验、校验编排、fail-closed），**绝不含私钥**。
- `pkg/fingerprint`：跨平台设备指纹。
- `internal/issuer`：签发端私钥逻辑（Go `internal/` 物理隔离）。
- `cmd/license-tool`：签发端 CLI。

详见 [`docs/zhCN/README.md`](./docs/zhCN/README.md) 与 [`SECURITY.md`](./SECURITY.md)。

### 快速开始

```bash
# 签发端：生成密钥对（私钥留在签发端机器上）
go run ./cmd/license-tool keygen -key-id k1 -out-dir ./keys

# 签发授权
go run ./cmd/license-tool issue -config examples/issue-config.json \
  -key ./keys/k1-private.key -out customer.lic

# 客户端：验证
go run ./cmd/license-tool verify -license customer.lic -pubkey ./keys/k1-public.key
```

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

### Docker 用法

> **私钥安全**：镜像**绝不**打包 `keys/` 或任何 `*.key` 文件。请在运行时用 `-v`（只读）
> 挂载私钥，而不是把私钥打进镜像；私钥只保存在受信任的签发端机器上。

```bash
# 签发端：把密钥对生成到宿主机目录，切勿打进镜像
docker run --rm -v "$PWD/keys:/work/keys" soulteary/grantseal:latest \
  keygen -key-id k1 -out-dir /work/keys

# 签发授权：私钥以只读方式挂载，绝不复制进镜像
docker run --rm \
  -v "$PWD/keys:/work/keys:ro" \
  -v "$PWD:/work" \
  soulteary/grantseal:latest \
  issue -config /work/examples/issue-config.json \
  -key /work/keys/k1-private.key -out /work/customer.lic

# 客户端验证只需公钥
docker run --rm -v "$PWD:/work" soulteary/grantseal:latest \
  verify -license /work/customer.lic -pubkey /work/keys/k1-public.key
```
