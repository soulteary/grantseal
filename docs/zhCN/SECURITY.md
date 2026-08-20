# 安全说明（简体中文）

完整安全策略与威胁模型见根目录 [`SECURITY.md`](../../SECURITY.md)。要点：

- **仅使用 Ed25519 签名**；禁止 PKCS#1v1.5/MD5/SHA-1/ECB/自制算法。
- 签名覆盖完整规范化 payload；敏感数据用 `subtle.ConstantTimeCompare` 比较。
- 私钥绝不出现在客户端代码、二进制、git、日志或测试固定数据中。
- limits 范围校验、拒绝未知枚举、64 KiB 文件上限、原子写入。
- 验证结果只读、验证器 fail-closed、绝不 panic。
- 离线授权用于**提高伪造/篡改成本**，并非绝对防破解；高价值场景请结合服务端校验。
