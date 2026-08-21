# grantseal — 离线软件授权系统（简体中文）

grantseal 是使用 Go 1.26 **纯标准库**实现的商业级离线软件授权系统。它负责签发、
验证与管理基于 **Ed25519** 签名的授权文件，支持设备绑定、功能/额度门禁、带宽限期
的到期策略、时钟回拨检测以及签名撤销列表。

## 架构

```
pkg/license/       客户端验证（仅公钥，fail-closed）
pkg/fingerprint/   跨平台设备指纹
internal/issuer/   签发端签名逻辑（私钥；客户端无法 import）
cmd/license-tool/  签发端 CLI
examples/          客户端集成 + 批量签发配置
```

借助 Go 的 `internal/` 机制，import 了 `pkg/license` 的客户端**无法** import
`internal/issuer`，因此私钥相关逻辑绝不会链接进客户端二进制。

## 数据模型（`pkg/license.Payload`）

- `schema_version`：仅接受 `1`，未知版本直接拒绝。
- `license_id` / `serial_number`：签发时用 `crypto/rand` 生成。
- `product_id`：调用方传入时必须匹配。
- `edition`：`trial`/`basic`/`professional`/`enterprise`（白名单）。
- `license_type`：`trial`/`subscription`/`lifetime`（白名单）。`trial` 与 `subscription` **必须**带 `expires_at`；`lifetime` **不得**带 `expires_at` 且永不过期。
- `issued_at` / `not_before` / `expires_at`：RFC3339 UTC。`issued_at` 不得晚于 `expires_at`，`not_before` 不得早于 `issued_at`；`lifetime` 无 `expires_at` 即永久。
- `grace_period_days`：0–3650，到期后的宽限期。
- `features`：与 edition 默认功能取并集。
- `limits`：非负、带范围校验的整型。
- `device_binding`：`none`/`single`/`multi` + 设备指纹列表。
- `version_constraint`：`min/max_version` + `maintenance_until` + `covered_max_version`。`maintenance_until` 未过期时，范围内所有版本均被覆盖；过期后，仅 `<= covered_max_version` 的版本仍被覆盖，更高版本判为 `LICENSE_VERSION_UNSUPPORTED`。未携带 `covered_max_version` 的旧许可回退到旧行为（严格高于 `min_version`（维护基线）的版本不被覆盖；若 `min_version` 也为空则跳过该门）。**fail-closed：** 若许可声明了任意版本约束，但调用方未传入运行版本（或传入无法解析的版本），验证直接拒绝并返回 `LICENSE_VERSION_UNSUPPORTED`。因此只要许可可能携带版本约束，调用方就必须传入 `ProductVersion`。
- `metadata`：自由字符串映射。
- `key_id`：必须与签名密钥、信封一致。

签名覆盖 payload 的确定性**规范化**（键排序）JSON。传输格式为
`Envelope{algorithm,key_id,payload,signature}`，其中 `payload` 与 `signature`
为 Base64URL。公钥/私钥文件仅按 **URL-safe Base64** 解析（`AddPublicKeyBase64` /
`DecodePrivateKey`）；含 `+`/`/` 的标准字母表 Base64 会被拒绝，以消除歧义解析。

## 验证流程

读取文件（≤ 64 KiB）→ 解析信封 → 校验算法为 `Ed25519` → 在公钥环中解析
`key_id`（启用/未撤销/在有效期内）→ 用规范化 payload 验签 → 校验 payload 的
`key_id` 与 schema →**验签成功后**再执行防回拨（加载/校验/保存状态，伪造输入不会
污染受信时间高水位线）→ 枚举白名单 + `license_type` 时间语义 → 撤销检查 →
时间校验（not_before / 到期 / 宽限）→ 设备绑定 → 产品/版本 → 返回**只读**
`ValidationResult`。

回拨状态文件损坏时，按 `license_type` fail-closed：`trial`/`subscription` 直接
拒绝（`LICENSE_STATE_INTEGRITY_FAILURE`），`lifetime`（与时间无关）则容忍并重置。
任一步失败均 **fail-closed**，返回稳定的 `LICENSE_*` 错误码；非法输入返回 error，
**绝不 panic**。

## CLI 用法

```bash
go run ./cmd/license-tool keygen -key-id k1 -out-dir ./keys
go run ./cmd/license-tool issue -config examples/issue-config.json \
  -key ./keys/k1-private.key -out customer.lic
go run ./cmd/license-tool verify -license customer.lic -pubkey ./keys/k1-public.key \
  -product acme-app -version 1.4.0
go run ./cmd/license-tool fingerprint -namespace acme-app -json
go run ./cmd/license-tool revoke-list -key ./keys/k1-private.key -key-id k1 \
  -ids lic_abc,lic_def -out revoked.json
```

## 客户端集成（库）

```go
ring := license.NewKeyRing()
_ = ring.AddPublicKeyBase64("k1", embeddedPublicKeyB64)

mgr := license.NewManager(ring)
res, err := mgr.LoadAndValidate("customer.lic", license.ValidationContext{
    ProductID:      "acme-app",
    ProductVersion: "1.4.0",
})
if err != nil {
    // license.CodeOf(err) 返回稳定的 LICENSE_* 码，可用于 UX 提示
    return
}

// 只读结果门面，用于功能/额度门禁：
if err := res.RequireFeature("api"); err != nil {
    // license.CodeOf(err) == license.CodeFeatureDenied（"LICENSE_FEATURE_DENIED"）
}
if err := res.CheckLimit("max_seats", seatsInUse); err != nil {
    // license.CodeOf(err) == license.CodeLimitExceeded（"LICENSE_LIMIT_EXCEEDED"）
    // 注意：license 未声明的 key 视为“无限制”，返回 nil。
}
_ = res.GetEdition()        // Edition
_ = res.GetExpiration()     // *time.Time（lifetime 为 nil）
_ = res.GetRemainingDays()  // lifetime 返回 -1（license.PerpetualRemainingDays）
_ = res.RemainingTime()     // time.Duration
_ = res.KeyID()             // 验签通过的签名 key_id
_ = res.DeviceMatched()     // 设备绑定是否满足
```

### 结果门面与错误码

`ValidationResult` 为只读，推荐使用门面方法而非直接读取字段：

- `RequireFeature(name) error`：功能未授予返回 `CodeFeatureDenied`（`LICENSE_FEATURE_DENIED`）。
- `CheckLimit(key, current) error`：超限返回 `CodeLimitExceeded`（`LICENSE_LIMIT_EXCEEDED`）；未声明的 key 视为**无限制**。
- `GetLimit`、`GetEdition`、`GetExpiration`、`GetRemainingDays`（永久返回 `-1`）、`RemainingTime`、`KeyID`、`DeviceMatched`。

`Manager` 会缓存最近一次成功的结果：用 `Manager.CachedResult()` 免验签查询，用 `Manager.InvalidateCache()` 清除；`Manager.GetDeviceRequestCode(ns)` 委托 `pkg/fingerprint` 生成申请码。

> 说明：`CodeFeatureDenied` 取代旧的 `LICENSE_FEATURE_UNAVAILABLE`，旧常量 `CodeFeatureUnavailable` 作为向后兼容别名保留。

## 在线激活（后续扩展）

- 注入基于网络的 `TrustedTimeProvider` 获取权威时间。
- 通过签名 OTA 通道下发撤销列表 / 公钥更新。
- 增加设备解绑/重绑接口，便于用户迁移设备。

安全边界与威胁模型详见 [`../../SECURITY.md`](../../SECURITY.md)。
