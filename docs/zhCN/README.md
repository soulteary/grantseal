# grantseal — 离线软件授权系统（简体中文）

[English](../enUS/README.md) | [中文文档](./README.md) —— 返回[项目 README](../../README.md)

相关文档：[架构](./architecture.md) · [质量与覆盖率](./quality.md) · [性能](./performance.md) · [安全](../../SECURITY.md)

grantseal 是使用 Go 1.26 **纯标准库**实现的离线软件授权库与 CLI。它负责签发、
验证与管理基于 **Ed25519** 签名的授权文件，支持设备绑定、功能/额度门禁、带宽限期
的到期策略、时钟回拨检测以及签名撤销列表。它的目标是提高伪造与离线篡改的成本——
而非让软件不可破解；诚实的边界见 [`../../SECURITY.md`](../../SECURITY.md)。

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

可运行示例与多场景签发/验证配置见
[`../../examples/README.md`](../../examples/README.md)。

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

## 签发配置

`issue` 命令读取 JSON 配置并签名生成许可。完整示例见
[`../../examples/issue-config.json`](../../examples/issue-config.json)，各场景变体见
[`../../examples/scenarios/`](../../examples/scenarios/)。字段说明：

- **`key_id`** *(必填)* —— 签名密钥 ID，须与传给 `issue` 的私钥一致，并记录在信封
  中。示例：`"k1"`。
- **`product_id`** *(建议)* —— 该许可对应的产品；客户端不匹配时返回
  `LICENSE_PRODUCT_MISMATCH`。示例：`"acme-app"`。
- **`customer_id`** —— 稳定的客户标识。示例：`"cust_00042"`。
- **`customer_name`** —— 可读的客户名称。示例：`"ACME Corporation"`。
- **`edition`** *(必填)* —— `trial`/`basic`/`professional`/`enterprise` 之一
  （白名单），决定默认功能集。
- **`license_type`** *(必填)* —— `trial`/`subscription`/`lifetime` 之一（白名单）。
  **时间约束：** `trial` 与 `subscription` **必须**带 `expires_at`；`lifetime`
  **不得**带 `expires_at` 且永不过期。
- **`not_before`** *(可选)* —— RFC3339 UTC 激活时间；早于该时间返回
  `LICENSE_NOT_YET_VALID`，且不得早于 `issued_at`。
- **`expires_at`** —— RFC3339 UTC 硬到期时间。`trial`/`subscription` **必填**，
  `lifetime` **须省略**；不得早于 `issued_at`（否则签发端静态校验判为
  `LICENSE_MALFORMED`）。
- **`grace_period_days`** —— 整数 `0`–`3650`，在 `expires_at` 之后延长可用期
  （状态 `grace`），超出后才判 `LICENSE_EXPIRED`。
- **`features`** —— 授予的功能标志字符串数组，与 edition 默认功能取并集。示例：
  `["export_pdf", "webhooks"]`。
- **`limits`** —— 非负整型额度映射，带范围校验。示例：
  `{"max_seats": 50, "max_projects": 200}`。未声明的 key 被 `CheckLimit` 视为
  **无限制**。
- **`device_binding`** —— `{"mode": "none"|"single"|"multi", "device_ids": [...]}`。
  `single`/`multi` 绑定到列出的指纹；设备不匹配返回 `LICENSE_DEVICE_MISMATCH`。
- **`version_constraint`** —— `{"min_version", "max_version", "maintenance_until",
  "covered_max_version"}`。`maintenance_until` 未过期时范围内所有版本均被覆盖；
  过期后仅 `<= covered_max_version` 仍被覆盖（否则 `LICENSE_VERSION_UNSUPPORTED`）。
- **`metadata`** —— 自由的 `string → string` 映射，供签发方记账（如 `order_id`、
  `region`），验证器不做解释。

> `license_id` 与 `serial_number` 通常在签发时用 `crypto/rand` 生成；场景固定数据
> 显式写死 `license_id` 只是为了让撤销断言可复现。

## CLI 用法

```bash
# 生成密钥对到 gitignored 目录(私钥留在本地,权限 0600)。
# ./_keys 已 gitignore;私钥绝不可提交。
go run ./cmd/license-tool keygen -key-id k1 -out-dir ./_keys

# 从私钥打印公钥
go run ./cmd/license-tool public-key -key ./_keys/k1-private.key

# 从 JSON 配置签发授权
go run ./cmd/license-tool issue -config examples/issue-config.json \
  -key ./_keys/k1-private.key -out customer.lic

# 验证 + 策略校验(客户端)
go run ./cmd/license-tool verify -license customer.lic -pubkey ./_keys/k1-public.key \
  -product acme-app -version 1.4.0

# 仅验签、打印 payload(不做策略校验)—— 仅用于诊断
go run ./cmd/license-tool inspect -license customer.lic -pubkey ./_keys/k1-public.key

# 设备指纹 / 申请码
go run ./cmd/license-tool fingerprint -namespace acme-app -json
go run ./cmd/license-tool fingerprint -namespace acme-app -request-code

# 构建签名撤销列表
go run ./cmd/license-tool revoke-list -key ./_keys/k1-private.key -key-id k1 \
  -ids lic_abc,lic_def -out revoked.json

# 打印 license-tool 版本
go run ./cmd/license-tool version
```

## 安装与 Docker

`license-tool` 是**签发端**二进制，含私钥逻辑，仅供授权签发方使用。

- **发布二进制**：从[发布页](https://github.com/soulteary/grantseal/releases)下载。
- **Homebrew（macOS / Linux）：**

```bash
brew tap soulteary/tap
brew install soulteary/tap/grantseal
```

- **Docker：**`docker pull soulteary/grantseal:latest`

> **私钥安全**：镜像绝不打包 `keys/` 或任何 `*.key` 文件。请在运行时用 `-v`（只读）
> 挂载私钥，绝不打进镜像，且私钥只保存在受信任的签发端机器上。

```bash
# 签发端:把密钥对生成到宿主机目录,切勿打进镜像。
# ./_keys 已 gitignore;私钥绝不可提交或打进镜像。
docker run --rm -v "$PWD/_keys:/work/_keys" soulteary/grantseal:latest \
  keygen -key-id k1 -out-dir /work/_keys

# 以只读方式挂载私钥来签发授权
docker run --rm \
  -v "$PWD/_keys:/work/_keys:ro" \
  -v "$PWD:/work" \
  soulteary/grantseal:latest \
  issue -config /work/examples/issue-config.json \
  -key /work/_keys/k1-private.key -out /work/customer.lic

# 客户端验证只需公钥
docker run --rm -v "$PWD:/work" soulteary/grantseal:latest \
  verify -license /work/customer.lic -pubkey /work/_keys/k1-public.key
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

## 错误码

每条失败路径都会返回稳定、机器可读的 `LICENSE_*` 错误码（见
[`../../pkg/license/errors.go`](../../pkg/license/errors.go)）。这些字符串是公开
契约的一部分，可安全用于 UX 分支判断；用 `license.CodeOf(err)` 提取。完整清单
（共 23 个）：

- **`LICENSE_OK`** —— 校验通过。*触发：* 有效且在有效期内的许可。*UX：* 放行，可
  额外展示剩余天数 / 版本。
- **`LICENSE_FILE_NOT_FOUND`** —— 许可文件路径不存在。*触发：* 首次运行缺少或路径
  错误。*UX：* 引导用户导入/选择许可文件。
- **`LICENSE_FILE_TOO_LARGE`** —— 文件超过 64 KiB 上限。*触发：* 损坏或恶意输入。
  *UX：* 判为无效，要求重新导入。
- **`LICENSE_MALFORMED`** —— 信封/JSON 无法解析或结构非法。*触发：* 文件被截断/
  篡改或类型错误。*UX：* 提示"许可文件无效"，引导重新导入。
- **`LICENSE_UNSUPPORTED_ALGORITHM`** —— 信封算法不是 `Ed25519`。*触发：* 算法字段
  错误或被伪造。*UX：* 判为无效。
- **`LICENSE_UNSUPPORTED_SCHEMA`** —— `schema_version` 不为 `1`。*触发：* 由不兼容
  的新/旧工具签发。*UX：* 提示升级应用或换取兼容许可。
- **`LICENSE_KEY_UNKNOWN`** —— 信封 `key_id` 不在客户端公钥环内。*触发：* 由应用未
  内置的密钥签发。*UX：* 判为无效，可能是构建/渠道不匹配。
- **`LICENSE_KEY_DISABLED`** —— 签名密钥存在但在环内被禁用。*触发：* 运维停用该
  密钥。*UX：* 请用户换取重新签发的许可。
- **`LICENSE_KEY_REVOKED`** —— 签名密钥超出有效期 / 在环内被撤销。*触发：* 密钥轮换
  或泄露。*UX：* 请求重新签发。
- **`LICENSE_SIGNATURE_INVALID`** —— 对规范化 payload 验签失败。*触发：* payload 被
  篡改或公钥不对。*UX：* 判为无效/伪造。
- **`LICENSE_KEY_ID_MISMATCH`** —— payload 的 `key_id` 与信封/验签密钥不一致。
  *触发：* 被拼接/篡改的许可。*UX：* 判为无效。
- **`LICENSE_INVALID_ENUM`** —— `edition` 或 `license_type` 不在白名单内。*触发：*
  手改或损坏的配置。*UX：* 判为无效。
- **`LICENSE_INVALID_LIMITS`** —— 某个 `limits` 值越界（如为负）。*触发：* 签发配置
  非法。*UX：* 判为无效。
- **`LICENSE_REVOKED`** —— 许可 ID 出现在签名撤销列表中。*触发：* 签发方撤销了该
  许可。*UX：* 提示"许可已被撤销"，引导联系支持/续期。
- **`LICENSE_NOT_YET_VALID`** —— 当前时间早于 `not_before`。*触发：* 激活时间在
  未来，或时钟被回拨。*UX：* 展示激活时间，提示检查系统时钟。
- **`LICENSE_EXPIRED`** —— 已过 `expires_at`（含宽限期，如有）。*触发：* 试用/订阅
  到期。*UX：* 引导续期并展示到期日。
- **`LICENSE_CLOCK_ROLLBACK`** —— 检测到系统时间早于受信高水位线。*触发：* 篡改
  时钟以规避到期。*UX：* 提示时钟异常，禁用与时间相关的功能。
- **`LICENSE_DEVICE_MISMATCH`** —— 当前设备指纹未被绑定。*触发：* 许可被迁移到另一
  台机器。*UX：* 展示设备申请码，请用户重新绑定。
- **`LICENSE_PRODUCT_MISMATCH`** —— payload 的 `product_id` 与调用方产品不符。
  *触发：* 用于其他产品的许可。*UX：* 判为无效。
- **`LICENSE_VERSION_UNSUPPORTED`** —— 运行版本超出覆盖范围，或存在版本约束却未
  传入/无法解析运行版本。*触发：* 升级超出维护/覆盖窗口。*UX：* 提示购买升级或
  运行受覆盖的版本。
- **`LICENSE_FEATURE_DENIED`** —— 所需功能未授予（由 `RequireFeature` 返回）。
  *触发：* 门禁了许可未包含的功能。*UX：* 针对该功能进行升级/增购提示。
- **`LICENSE_LIMIT_EXCEEDED`** —— 用量计数超过声明的额度（由 `CheckLimit` 返回）。
  *触发：* 如席位数超过 `max_seats`。*UX：* 展示额度并引导升级。
- **`LICENSE_STATE_INTEGRITY_FAILURE`** —— 防回拨状态文件损坏且策略 fail-closed。
  *触发：* `trial`/`subscription` 许可的状态被篡改/损坏。*UX：* 判为无效，可能需要
  重新激活。

> **向后兼容别名：** `LICENSE_FEATURE_UNAVAILABLE` 是 `LICENSE_FEATURE_DENIED` 的
> 旧写法，仅为避免比较旧字符串的调用方失效而保留；新代码应发出
> `LICENSE_FEATURE_DENIED`。

## 在线激活（后续扩展 / 路线图）

- 注入基于网络的 `TrustedTimeProvider` 获取权威时间。
- 通过签名 OTA 通道下发撤销列表 / 公钥更新。
- 增加设备解绑/重绑接口，便于用户迁移设备。

信任边界与验证顺序见 [`architecture.md`](./architecture.md)；完整威胁模型见
[`../../SECURITY.md`](../../SECURITY.md)。
