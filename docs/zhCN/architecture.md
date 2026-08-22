# 架构

[English](../enUS/architecture.md) | [中文文档](./architecture.md) —— 返回[项目 README](../../README.md)

相关文档：[README](./README.md) · [质量与覆盖率](./quality.md) · [性能](./performance.md) · [安全](../../SECURITY.md)

本文档描述信任边界、传输信封格式、精确的验证顺序、撤销与离线新鲜度，以及设备指纹
方案，内容与 `pkg/license` 和 `pkg/fingerprint` 的代码一致。

## 信任边界

grantseal 清晰地划分为**签发端**（持有私钥）与**客户端**（只持有公钥）。借助 Go 的
`internal/` 机制，签发端包无法被客户端 import，因此私钥逻辑绝不会链接进客户端二进制。

```
                 签发端机器（受信）                      |        客户端 / 客户（不受信）
                                                        |
  cmd/license-tool  ──调用──▶  internal/issuer          |   应用 ──import──▶ pkg/license
      keygen                     私钥（0600）           |                     KeyRing（仅公钥）
      issue        ──签名──▶     Ed25519 签名           |                     Verifier / Validator
      revoke-list                规范化 payload         |                     Manager（文件 I/O、缓存）
                                     │                   |                         │
                                     ▼                   |                         ▼
                              customer.lic  ──────经任意通道分发──────▶  验签 + 策略校验
                              revoked.json                                （fail-closed，稳定错误码）
                                                        |
  信任边界：私钥绝不跨越此线。跨越的只有签名产物（授权、撤销列表）与公钥。
```

关键属性：

- **私钥隔离。** 客户端只 import `pkg/license`；`internal/issuer` 在模块签发端树之外
  不可被 import。CI 扫描最终发布归档确认无密钥材料，并强制归档白名单。
- **不受信输入。** 客户端将许可文件、撤销列表、本地回拨状态文件与系统时钟均视为不受
  信。任何不受信数据在其签名被证明为真之前，都不得改动受信状态（见[验证顺序](#验证顺序)）。
- **指纹隐私。** 原始硬件标识绝不离开 `pkg/fingerprint`，只暴露散列与类别名。

## 信封格式

磁盘上的许可是一段 JSON `Envelope`：

```json
{
  "algorithm": "Ed25519",
  "key_id": "k1",
  "payload": "<Base64URL(规范化 payload 字节)>",
  "signature": "<Base64URL(对 payload 字节的 Ed25519 签名)>"
}
```

- `payload` 是 `Payload` 的**规范化**（确定性、键排序）JSON，被**逐字**做 Base64URL
  编码。客户端针对 `payload` 中携带的确切字节验签——不会重新序列化 payload——因此签发端
  与客户端之间不存在规范化不一致的空隙。
- `signature` 是对上述 payload 字节的 Ed25519 签名的 Base64URL 编码。
- `payload` 与 `signature` 都仅按 **URL-safe Base64** 解析；含 `+`/`/` 的标准字母表
  Base64 会被拒绝。
- `ParseEnvelope` 强制 64 KiB 大小上限、使用 `DisallowUnknownFields`、拒绝尾随数据，
  并要求四个字段均非空。

撤销列表使用相应的 `RevocationEnvelope`，包裹一个签名的
`RevocationList{schema_version, issued_at, key_id, revoked_license_ids}`。

### golden 向量不含私钥

测试套件固定了 **golden 信封向量**——固定的 `(公钥, 规范化 payload, 签名)` 三元组——
并断言验签成功、规范化字节逐字节稳定。这些向量**只嵌入公钥**：验签本身从不需要私钥，
因此私钥永远不会出现在固定数据中。它既记录了传输格式，又能防止规范化被意外改动。
向量清单见[质量文档](./quality.md)。

具体而言，[`pkg/license/canonical_golden_test.go`](../../pkg/license/canonical_golden_test.go)
中的 `TestCanonicalBytesGoldenVectors` 固定了多个 payload 的精确规范化字节序列，因此对
键排序、HTML 转义、数值精度或空值处理的任何改动都会导致该测试失败。

## 验证顺序

`Manager.LoadAndValidate`（及底层的 `Verifier` + 校验器）以固定、出于安全考量的顺序
执行：

1. 读取许可文件（`> 64 KiB` 直接拒绝）。
2. 解析信封（`DisallowUnknownFields`、拒绝尾随数据）。
3. 校验算法为 `Ed25519`。
4. 在 `KeyRing` 中解析 `key_id`（须启用、未撤销、在有效期窗口内）。
5. 对规范化 payload 字节验证 Ed25519 签名。
6. 校验 payload 的 `key_id` 与信封 `key_id` 一致、schema 版本为 `1`。
7. **防回拨状态只在此处（即签名被证明为真之后）加载、校验并保存。** 这一顺序是刻意
   设计的：如果不受信输入能在验签之前加载/改动受信时间高水位线，伪造文件就可能污染回拨
   状态（例如把高水位线推前以逼出误报的 `LICENSE_CLOCK_ROLLBACK`，或将其重置）。先验签
   意味着只有真实许可才会触碰受信时间状态。
8. 枚举白名单 + `license_type` 时间语义。
9. 撤销检查。
10. 时间校验（`not_before` / 到期 / 宽限）。
11. 设备绑定。
12. 产品 / 版本约束。
13. 返回**只读** `ValidationResult`。

回拨状态文件损坏时，按 `license_type` fail-closed：`trial`/`subscription` 直接拒绝
（`LICENSE_STATE_INTEGRITY_FAILURE`），且损坏状态**绝不会被静默重置**。与时间无关的
`lifetime` 许可**根本不参与防回拨**——不会为其读取、写入或重置状态文件——因此损坏状态
永远不会拒绝 lifetime 许可（此为刻意设计）。任一失败路径都返回稳定的 `LICENSE_*`
错误码；非法输入对受支持入口返回 error 而非 panic（CI 持续以 fuzz/race 验证）。

## 撤销与离线新鲜度

- 撤销列表的认证方式与许可完全一致：规范化字节、Ed25519 签名，客户端针对同一
  `KeyRing` 验证。其签名体内的 `key_id` 必须与信封 `key_id` 一致，schema 必须为 `2`
  （`RevocationSchemaVersion`），条目数受 `MaxRevokedIDs` 限制。
- v2 列表在签名体内携带 `list_id`、单调递增的 `sequence`、`issued_at` 与 `expires_at`。
  四个相互独立的属性按顺序分别强制：
  1. **签名真实性** —— 列表确实来自签发方（对撤销签名域 + 规范化字节做 Ed25519 签名）。
  2. **静态结构约束** —— 由 `validateRevocationV2Static` 在认证之后、任何时间相关检查
     之前**无条件**强制，且不受 `WithoutFreshness` 放宽：`schema_version == 2`、`list_id`
     非空、`sequence > 0`、`issued_at` 非零、`expires_at` 非 nil、`expires_at` 严格晚于
     `issued_at`。任一违反返回 `LICENSE_MALFORMED`。因此即便离线回放归档列表，
     `issued_at`/`expires_at` 的*存在与先后次序*也是硬性要求。
  3. **分发新鲜度**（时间相关）—— `issued_at` 不得超出偏移地处于未来
     （`LICENSE_REVOCATION_FROM_FUTURE`），且列表不得超过 `expires_at` 或早于任意配置的
     `MaxAge`（`LICENSE_REVOCATION_EXPIRED`）。这是**唯一**由
     `RevocationPolicy.RequireFresh`（默认 **true**）控制的层；
     `RevocationPolicy.WithoutFreshness()` 是用于回放归档列表的显式、审慎的关闭途径，
     且*只*放宽这一层。
  4. **本地防重放** —— 客户端按 `list_id` 持久化已接受的最高 `sequence` 作为高水位，
     且即便在 `WithoutFreshness` 下也会执行。sequence 低于上次已接受值的列表会被拒绝
     （`LICENSE_REVOCATION_STALE`）；以相同 sequence 复用但内容不同者按回滚拒绝
     （`LICENSE_REVOCATION_ROLLBACK`）。若本地状态文件被篡改，检查 fail-closed
     （`LICENSE_REVOCATION_STATE_INTEGRITY_FAILURE`）。
- **撤销状态为单进程写者。** `RevocationStateStore` 的并发保证仅在**单进程内**成立。
  `FileRevocationStateStore` 通过包级按路径锁协调同一进程内共享同一路径的多个实例，但
  **不获取操作系统级文件锁**，因此**不**能保护分处不同进程、写同一状态文件的并发写者。
  请为撤销状态文件部署单一写者进程。
- **默认拒绝 v1 旧列表。** v1 列表（无 sequence/expiry、无防重放）仅在调用方通过
  `RevocationPolicy.AllowLegacyV1Revocation()` 显式选择加入时才被接受（*构建*列表时对应
  `-v1` 标志）。以此保持默认 fail-closed。
- **离线新鲜度限制。** 客户端仍然只强制执行它当前持有的列表；没有更新的签名列表就无法
  得知更新的撤销。新鲜度窗口限定持有列表可以陈旧到什么程度，但更新列表的分发在带外进行。

### 路线图字段 / 机制（尚未实现）

以下内容目前**未**实现，特此标注以免有人依赖：

- 签名撤销列表与公钥更新的**在线撤销 / OTA 分发**。*Roadmap。*
- 用于获取权威时间、替代本地时钟的**基于网络的 `TrustedTimeProvider`**。*Roadmap。*
- 用于在机器间迁移许可的**设备重绑接口**。*Roadmap。*

## 设备指纹

`pkg/fingerprint` 构建稳定、尊重隐私的设备指纹：

1. **采集**平台硬件标识（Linux/macOS/Windows + 回退）。每个是一个
   `Component{Category, value}`，其中 `value` 未导出，因此原始标识不会通过反射/JSON/
   日志泄露。
2. **归一化**每个值：trim、转小写、折叠内部空白。
3. **规范化**：丢弃空值，按 `(category, value)` 确定性排序，前缀加产品命名空间与一个
   NUL 分隔符，再用 `\n` 连接 `category=value` 行。
4. **散列**：默认 SHA-256；提供密钥时用 HMAC-SHA256（`ComputeHMAC`）。digest 带
   `sha256:` / `hmac-sha256:` 算法标签，整个值再加上带版本的方案前缀 `fp:v<N>:`
   （如 `fp:v1:sha256:<hex>`、`fp:v2:hmac-sha256:<hex>`），因此写入许可证
   `device_ids` 的值自带其由哪一版指纹方案生成的信息。这样版本无关的默认入口
   （`ComputeDefault`）可以继续演进而不会悄悄使已签发的设备绑定失配，同时 plain 与
   keyed、v1 与 v2 输出互不混淆。

属性与注意：

- **与顺序无关、按命名空间隔离。** 规范化形式会对组件排序并包含产品命名空间，因此同
   一设备上的两个产品得到不同指纹，且组件顺序无关紧要。
- **该散列是身份信号，而非机密。** 它提供设备*身份*，而非认证。
- **`RequestCode`** 从指纹派生出简短、大写、按短横线分组的申请码，用于激活/支持流程；
   对同一命名空间+设备是确定性的。
- **漂移**在 VM/容器或硬件更换/重装后是预期内的，可能导致 `LICENSE_DEVICE_MISMATCH`；
   请提供重绑 / 支持路径。
- **fail-closed。** 若无可用硬件信息，包会返回 `ErrInsufficientInfo`，绝不伪造随机
   标识。
