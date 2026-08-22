# 质量与覆盖率

[English](../enUS/quality.md) | [中文文档](./quality.md) —— 返回[项目 README](../../README.md)

相关文档：[README](./README.md) · [架构](./architecture.md) · [性能](./performance.md) · [安全](../../SECURITY.md)

> **说明。** 下方生成区块中的记录环境与覆盖率数字均来自唯一机器可读事实来源
> [`.github/go-test-report.json`](../../.github/go-test-report.json)，经
> `scripts/generate-quality-docs.sh` 生成。区块以外的说明性文字由人工维护。

记录环境（提交、生成时间、Go 版本、OS/架构）与覆盖率数字都取自该 JSON 的
`environment` 与 `coverage` 字段，由覆盖率工作流重新生成并提交，因此不会与实测运行
漂移；下方生成区块请勿手工编辑（CI 会运行生成器并在出现 diff 时失败）。测试命令：
`go test ./cmd/... ./internal/... ./pkg/... -covermode=atomic -coverprofile=coverage.out`。

<!-- BEGIN:GENERATED-COVERAGE -->
<!-- 由 scripts/generate-quality-docs.sh 从 .github/go-test-report.json 生成，请勿手工编辑。 -->

## 记录环境

- 提交：`6a0b032de06a7c52eab259c487e79c734b6ed060`
- 生成时间（UTC）：`2026-08-22T08:20:59Z`
- Go 版本：`go1.26.6`
- 操作系统 / 架构：`linux/amd64`

这些值取自 `.github/go-test-report.json` 的 `environment` 字段（唯一的机器可读来源），因此不会与实际运行漂移。

## 总覆盖率

- **总计：** `93.80%` 语句覆盖率（1845/1967）
- 覆盖率门禁（CI）：`93%`（实测总覆盖率向下取整；确保同一提交不会失败于自身门禁）

根 README 的 Coverage 徽章由 CI 基于同一次运行生成。

## 分包覆盖率

| 包 | 覆盖率 |
| -- | ------ |
| `pkg/license` | `95.0%` |
| `pkg/fingerprint` | `94.3%` |
| `internal/issuer` | `91.7%` |
| `cmd/license-tool` | `91.8%` |
| `examples/client` | `0.0%`（示例代码，无测试） |

<!-- END:GENERATED-COVERAGE -->

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

- Fuzz target（`pkg/license`）：`FuzzParseEnvelope`、`FuzzCanonicalBytes`、
  `FuzzLoadRevocationList`、`FuzzRollbackStateLoad`。
- 语料与临时 fuzz 文件**不**提交到仓库。

每次 push/PR 会对全部四个 target 各短时 smoke（`.github/workflows/ci.yml` 中的矩阵
job，每个 `-fuzztime=30s`）以确保其可编译、可执行。定时工作流
（`.github/workflows/fuzz-nightly.yml`）会运行更长的 campaign（每 target
`-fuzztime=10m`），并把发现的 crash 语料作为构建产物归档，便于复现。
