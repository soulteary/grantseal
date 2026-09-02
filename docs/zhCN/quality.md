# 质量与覆盖率

[English](../enUS/quality.md) | [中文文档](./quality.md) —— 返回[项目 README](../../README.md)

相关文档：[README](./README.md) · [架构](./architecture.md) · [性能](./performance.md) · [安全](../../SECURITY.md)

> **说明。** 下方生成区块中的记录环境与覆盖率数字均来自唯一机器可读事实来源
> [`.github/go-test-report.json`](../../.github/go-test-report.json)，经
> `ci-recipes grantseal generate-quality-docs` 生成。区块以外的说明性文字由人工维护。

记录环境（提交、生成时间、Go 版本、OS/架构）与覆盖率数字都取自该 JSON 的
`environment` 与 `coverage` 字段，由覆盖率工作流重新生成并提交，因此不会与实测运行
漂移；下方生成区块请勿手工编辑（CI 会运行生成器并在出现 diff 时失败）。测试命令：
`go test ./cmd/... ./internal/... ./pkg/... -covermode=atomic -coverprofile=coverage.out`。

<!-- BEGIN:GENERATED-COVERAGE -->
<!-- 由 ci-recipes grantseal generate-quality-docs 从 .github/go-test-report.json 生成，请勿手工编辑。 -->

## 记录环境

- 提交：`9c6d8f5de7acd97d97585bbb7b3ce50c2659f0df`
- 生成时间（UTC）：`2026-09-02T21:09:29Z`
- Go 版本：`go1.26.7`
- 操作系统 / 架构：`linux/amd64`

这些值取自 `.github/go-test-report.json` 的 `environment` 字段（唯一的机器可读来源），因此不会与实际运行漂移。

## 总覆盖率

- **总计：** `95.18%` 语句覆盖率（2035/2138）
- 覆盖率门禁（CI）：`93%`（实测总覆盖率向下取整；确保同一提交不会失败于自身门禁）

根 README 的 Coverage 徽章由 CI 基于同一次运行生成。

## 分包覆盖率

| 包 | 覆盖率 |
| -- | ------ |
| `pkg/license` | `96.3%` |
| `pkg/fingerprint` | `96.7%` |
| `internal/issuer` | `93.2%` |
| `cmd/license-tool` | `93.2%` |
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

## 测试文件命名重构（P2 / 可维护性）

以下测试文件是在快速补覆盖率阶段产生的"杂物型"命名（`coverage_*`、
`arms2_*`、`*_more_*`），名字无法告诉维护者其中到底测什么。这**不是质量缺陷**，
而是可维护性事项：**不要为此单独发大改 commit**，以后碰到对应源码时顺手按下表迁移即可。

约定：按**被测源文件**一一对应命名；内部包（`package license`，可测未导出符号）
测试保留 `_internal_test.go` 后缀，外部包（`package license_test`）测试不加后缀。
拆分时若目标文件名已存在（如 `version_internal_test.go`、`revocation_v2_regression_test.go`），
合并进去即可，无需新建。

| 现文件 | 包 | 目标文件（按主题拆分） | 覆盖的主题 |
| ------ | -- | ---------------------- | ---------- |
| `pkg/license/coverage_test.go` | `license_test`（外部） | `envelope_parse_test.go` | 信封解析边界：空、未知字段、尾随数据、重复 key、缺字段、坏 Base64 签名 |
| ↑ | | `keyring_lookup_test.go` | KeyRing：坏 key 长度、空 key_id、未知 key、revoke/disable 优先级、有效期窗口、`KeyIDs()` 排序 |
| ↑ | | `rollback_state_test.go` | 回拨状态：空路径/key、缺失、截断、未知字段、超大、round-trip、错误 key、派生 key、`lifetime` 容错 |
| ↑ | | `revocation_load_test.go` | 撤销列表加载：错误 key_id、坏签名、去重、`StaticRevocation` nil 安全 |
| ↑ | | `result_facade_test.go` | 结果门面：`Features()`/`Limits()`/`ExpiresAt()` 防御性拷贝 |
| ↑ | | `version_validate_test.go` | 经公开 `Manager.Validate` 的版本 fail-closed（缺版本、预发布、不可解析） |
| `pkg/license/arms2_internal_test.go` | `license`（内部） | `version_internal_test.go`（已存在，合并） | `parseVersion`/`parseNumericID` 分支（`TestParseVersionAndNumericArms`） |
| ↑ | | `strictjson_internal_test.go` | `decodeStrictJSON`/`rejectDuplicateKeys` 直连分支（`TestStrictJSONDirectArms`） |
| ↑ | | `device_check_internal_test.go` | `checkDevice` 的空指纹/无效模式分支（`TestCheckDeviceArms`） |
| ↑ | | `revocation_validation_internal_test.go` | v2 静态不变量、freshness、`classifyRevocationTransition`、`signedRevocation` nil 安全（`TestValidateRevocationV2StaticArms`/`TestCheckRevocationFreshnessArms`/`TestSignedRevocationIsRevokedNil`/`TestClassifyRevocationTransitionNilNext`） |
| ↑ | | `manager_loadvalidate_internal_test.go` | `LoadAndValidate` 的 size-cap/not-found/委派分支（`TestLoadAndValidateArms`） |
| `pkg/license/coverage_more_internal_test.go` | `license`（内部） | `errors_internal_test.go` | `Error()`/`Unwrap()`/`Is()`/`CodeOf` 分支（`TestError*`/`TestCodeOfNonLicenseError`） |
| ↑ | | `model_validate_internal_test.go` | enum `Valid()` 默认分支、`validateStatic` 各分支：身份/枚举/limits/时间语义/设备绑定（`TestEnumValidDefaultArms`/`TestValidate{Static,Identity,Enums,LimitsRange,TimeSemantics}Arms`） |
| ↑ | | `manager_clock_internal_test.go` | `WithClockSkew`、`clockSkewDefault` env、时钟不可用 fail-closed、`Inspect` 降级/解析、`CachedResult`（`TestWithClockSkewIgnoresNonPositive`/`TestClockSkewDefaultEnv`/`TestValidateFailsClosedOnClockError`/`TestInspect*`/`TestCachedResultClockFailClosedAndStale`） |
| ↑ | | `verifier_internal_test.go` | nil verifier/ring/envelope、坏算法、坏签名长度（`TestVerifyNilAndConfigErrors`/`TestVerifyBadSignatureLength`） |
| ↑ | | `keyring_policy_internal_test.go` | `CheckKeyPolicy` 的 revoked/disabled/window 分支（`TestCheckKeyPolicyArms`） |
| ↑ | | `strictjson_internal_test.go`（同上，合并） | `DecodeStrictJSON` 的数组/嵌套对象/非法 key/重复 key 分支（`TestStrictJSONArmsDirect`） |
| `cmd/license-tool/cli_more_test.go` | `main`（内部，非 `main_test`） | `cli_verify_test.go` / `cli_issue_test.go` / `cli_revoke_test.go` / `cli_inspect_test.go` / `cli_keys_test.go` | 按子命令拆分：verify / issue / revoke-list / inspect / keygen+publickey+fingerprint 与 write helper |
| `internal/issuer/issuer_more_test.go` | `issuer_test` | `keys_test.go` / `sign_test.go` / `issue_test.go` / `revocation_test.go` | 按能力拆分：密钥生成/编解码/写文件、签名、签发、构建撤销列表 |

> 落地建议：每次因功能改动而修改上述某个源码时，把该源码对应的测试从杂物文件里
> 剪切到新命名文件，逐步清空 `coverage_*` / `arms2_*` / `*_more_*`，最终删除空壳文件。
> 迁移是纯文件移动（不改测试逻辑），完成后同步更新上方"本次改动新增的测试文件"清单。
>
> 注意共享 helper：`coverage_more_internal_test.go` 顶部的 `errClock` / `internalSigner` /
> `testInternalSigner` / `ringWithInternal` / `basePayloadFor` / `issueInternalEnvelope` /
> `issueInternal` 被 verifier/manager 等多组测试共用；拆分时把它们集中放到一个
> `internal_helpers_test.go`（或就近的 `manager_clock_internal_test.go`），避免重复定义或编译期未使用报错。
