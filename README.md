# grantseal

[English](#english) | [简体中文](#简体中文)

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
| `cmd/license-tool`     | Issuer CLI: `keygen`, `public-key`, `issue`, `verify`, `inspect`, `fingerprint`, `revoke-list`. |
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

---

## 简体中文

`grantseal` 是使用 Go 1.26 **纯标准库**实现的商业级**离线软件授权系统**，
不引入任何第三方依赖。

- `pkg/license`：客户端验证（公钥、签名校验、校验编排、fail-closed），**绝不含私钥**。
- `pkg/fingerprint`：跨平台设备指纹。
- `internal/issuer`：签发端私钥逻辑（Go `internal/` 物理隔离）。
- `cmd/license-tool`：签发端 CLI。

详见 [`docs/zhCN/README.md`](./docs/zhCN/README.md) 与 [`SECURITY.md`](./SECURITY.md)。
