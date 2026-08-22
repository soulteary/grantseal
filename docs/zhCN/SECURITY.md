# 安全说明（简体中文）

完整安全策略、信任边界、威胁表与部署检查清单见根目录
[`SECURITY.md`](../../SECURITY.md)；架构与验证顺序见
[`architecture.md`](./architecture.md)。要点：

- **仅使用 Ed25519 签名**；禁止 PKCS#1v1.5/MD5/SHA-1/ECB/自制算法。
- 签名提供**来源认证与完整性，而非保密性**——payload 可被读取，切勿在其中放置机密。
- 私钥逻辑仅存在于 `internal/issuer` 与 CLI，客户端**无法 import**；CI 扫描最终发布归档中的密钥材料并强制归档白名单。
- 朴素时钟回拨通过完整性保护的时间高水位线被**检测**，但无法防住 root/admin 级攻击者。
- 指纹经归一化、加命名空间后再做 SHA-256/HMAC 散列；该散列是**非加密的身份**信号，原始硬件值**不会由 API 返回**；漂移是预期内的——请提供重绑路径。
- `inspect` 仅验签用于**诊断**，不做任何策略校验；请以 `verify` / `LoadAndValidate` 为准。
- 离线撤销按顺序区分四个概念：**签名真实性**（始终强制）、**静态结构约束**（schema/`list_id`/`sequence`>0/`issued_at`/`expires_at` 先后次序——始终强制，不受 `WithoutFreshness` 放宽，归为 `LICENSE_MALFORMED`）、**分发新鲜度**（时间相关窗口，`WithoutFreshness` 唯一放宽的一层；客户端只强制它当前持有的列表）、**本地防重放**（按 `list_id` 的高水位 sequence，`WithoutFreshness` 下仍执行）。
- 撤销状态存储为**单进程写者**：`FileRevocationStateStore` 以按路径锁协调同一进程内的实例，但不获取操作系统级文件锁，因此无法保护分处不同进程写同一状态文件的并发写者——请为该状态文件部署单一写者进程。
- `Manager.CachedResult()` **仅**用于历史/诊断/非安全 UI（受信时钟出错时 fail-closed），绝不能作为授权判定；任何当前授权都必须重新运行 `Validate`/`LoadAndValidate`。
- 验证结果只读、验证器 fail-closed；每个受支持入口返回稳定错误而非 panic（CI 持续以 fuzz/race 验证）。
- 离线授权用于**提高伪造/篡改成本**，并非绝对防破解；高价值场景请结合服务端校验。
