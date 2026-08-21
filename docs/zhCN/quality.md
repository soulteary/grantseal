# 质量与覆盖率

[English](../enUS/quality.md) | [中文文档](./quality.md) —— 返回[项目 README](../../README.md)

相关文档：[README](./README.md) · [架构](./architecture.md) · [性能](./performance.md) · [安全](../../SECURITY.md)

> **说明。** 下方覆盖率数字由覆盖率工作流基于某个具体提交回填。任何
> `<!-- FILL: ... -->` 标记或 `TBD` 都是待替换为实测值的占位符——请勿把占位符当作真实
> 数字。

## 记录环境

- Commit SHA：`e5c6e93`
- 日期（UTC）：2026-08-21
- Go 版本：`go1.26.6`
- OS / 架构：`darwin/arm64`
- 命令：`go test ./... -covermode=atomic -coverprofile=coverage.out && go tool cover -func=coverage.out`

## 总覆盖率

- **总计：** `77.5%` 语句覆盖率
- 覆盖率门禁（CI）：`77%`（实测总覆盖率向下取整；确保同一提交不会失败于自身门禁）

根 README 的 Coverage 徽章由 CI 基于同一次运行生成。

## 分包覆盖率

| 包 | 覆盖率 |
| -- | ------ |
| `pkg/license` | `82.9%` |
| `pkg/fingerprint` | `90.7%` |
| `internal/issuer` | `85.4%` |
| `cmd/license-tool` | `70.7%` |
| `examples/client` | `0.0%`（示例代码，无测试） |

## 测试矩阵

测试套件覆盖以下领域。（具体测试名与新增用例在回填时补充。）

- **规范化** —— 针对 Unicode、HTML 字符、空值、嵌套对象、数值边界的 golden 向量；逐
  字节稳定性。
- **信封解析** —— 重复 key、尾随数据、未知字段、混用 Base64 字母表、大小上限。
- **KeyRing** —— 并发、有效期窗口边界、revoke/disable、nil/错误长度 key。
- **回拨状态** —— 缺失/损坏/截断/超大状态、原子写与权限失败、`lifetime` 与
  `trial`/`subscription` 的策略差异。
- **撤销** —— 过期/未来 `issued_at`、重复 ID、超额列表、错误签名、未知 key。
- **指纹** —— 顺序无关、空组件、namespace/HMAC 隔离、申请码稳定性。
- **版本** —— 预发布/非法字符串、缺 `ProductVersion` 的 fail-closed。
- **结果门面** —— 切片/map 的防御性复制。
- **CLI（`cmd/license-tool`）** —— 各子命令参数错误、退出码、stdout/stderr 分离、
  `-force` 拒绝覆盖、不输出敏感信息。

本次改动新增的测试文件：
`pkg/license/canonical_golden_test.go`、`pkg/license/coverage_test.go`、
`pkg/license/fuzz_targets_test.go`、`pkg/license/benchmark_test.go`、
`pkg/fingerprint/canonical_internal_test.go`、`pkg/fingerprint/benchmark_test.go`、
`internal/issuer/issuer_more_test.go`、`cmd/license-tool/cli_test.go`。

## Fuzz 策略

- 现有 fuzz target：`FuzzParseEnvelope`（`pkg/license`）。
- 新增 fuzz target（`pkg/license/fuzz_targets_test.go`）：canonical 字节 / payload
  解码、撤销列表解析、回拨状态解析。
- 语料与临时 fuzz 文件**不**提交到仓库。

CI 会短暂运行 fuzz target 以确保其可编译、可执行；长时 fuzz 在带外运行。记录运行所用
的 fuzz 时长：`30s`
（`go test ./pkg/license -run=^$ -fuzz=FuzzParseEnvelope -fuzztime=30s`，通过，0 崩溃）。
