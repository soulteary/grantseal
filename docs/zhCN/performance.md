# 性能与 Benchmark

[English](../enUS/performance.md) | [中文文档](./performance.md) —— 返回[项目 README](../../README.md)

相关文档：[README](./README.md) · [架构](./architecture.md) · [质量与覆盖率](./quality.md) · [安全](../../SECURITY.md)

> **说明。** 下方所有数字由 benchmark 工作流基于某个具体提交与机器回填。任何
> `<!-- FILL: ... -->` 标记或 `TBD` 都是占位符——请勿把占位符当作实测值。benchmark 结果
> 仅代表单台机器，**并非**跨设备保证；CI runner 各异，不强制严格的性能门禁。

## 记录环境

- 日期（UTC）：2026-08-21
- Go 版本：`go1.26.6`
- OS / 架构：`darwin/arm64`
- CPU：Apple M5（10 核）
- 命令：`go test ./pkg/license ./pkg/fingerprint -run '^$' -bench . -benchmem -count=5`
- `-count`：`5`（下表为 5 次运行的中位数）

## 各路径包含的步骤

README 中的四种开销/副作用画像对应以下 benchmark：

1. **纯内存验签** —— `BenchmarkVerifySignature`。对预先解码的规范化字节做 Ed25519
   验证。无磁盘 I/O、无策略校验。
2. **完整策略校验** —— `BenchmarkValidateMemory`。验签之外，对内存输入做
   枚举/时间/设备/版本策略。不含文件 I/O。
3. **文件读取 + 回拨状态落盘** —— 在注明处单独测量；包含读取许可文件与读写防回拨状态
   文件（磁盘 I/O），因此结果取决于文件系统。
4. **设备指纹采集** —— `BenchmarkFingerprintCanonicalization` 使用注入的固定组件以摆脱
   对宿主硬件的依赖；它测量归一化 + 规范化 + 散列，**不**包含平台硬件采集（后者受 I/O
   限制且与宿主相关）。

## 结果 —— `pkg/license`

| Benchmark | ns/op | B/op | allocs/op |
| --------- | ----- | ---- | --------- |
| `BenchmarkParseEnvelope` | `2738` | `3248` | `13` |
| `BenchmarkVerifySignature` | `34552` | `5696` | `37` |
| `BenchmarkValidateMemory` | `33904` | `6072` | `41` |
| `BenchmarkValidateWithRevocation/0` | `34105` | `6072` | `41` |
| `BenchmarkValidateWithRevocation/100` | `33867` | `6072` | `41` |
| `BenchmarkValidateWithRevocation/10000` | `39976` | `6072` | `41` |
| `BenchmarkCanonicalBytes/small` | `6297` | `7624` | `132` |
| `BenchmarkCanonicalBytes/large` | `211142` | `289807` | `4986` |
| `BenchmarkCachedResult`（parallel） | `100.2` | `0` | `0` |
| `BenchmarkKeyRingLookup/1` | `17.96` | `0` | `0` |
| `BenchmarkKeyRingLookup/10` | `18.91` | `0` | `0` |
| `BenchmarkKeyRingLookup/100` | `19.75` | `0` | `0` |

## 结果 —— `pkg/fingerprint`

| Benchmark | ns/op | B/op | allocs/op |
| --------- | ----- | ---- | --------- |
| `BenchmarkFingerprintCanonicalization` | `763.9` | `1216` | `23` |

指纹包还提供了规模扫描
（`BenchmarkFingerprintCanonicalizationSizes/components={1,4,16}`）：中位数分别为
`149.5` / `523.4` / `2049` ns/op，均使用注入的固定组件。

## 头条数字（README）

实测后，其中 2-3 个会在 README 中展示：

- 纯内存验签：`~34.6 us/op`（`BenchmarkVerifySignature`，`34552 ns/op`）
- 完整策略校验：`~33.9 us/op`（`BenchmarkValidateMemory`，`33904 ns/op`）
- 信封解析：`~2.7 us/op`（`BenchmarkParseEnvelope`，`2738 ns/op`）
