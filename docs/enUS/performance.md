# Performance & Benchmarks

[English](./performance.md) | [中文文档](../zhCN/performance.md) — back to the [project README](../../README.md)

Related docs: [README](./README.md) · [architecture](./architecture.md) · [quality & coverage](./quality.md) · [security](../../SECURITY.md)

> **Note.** The numbers below were recorded by hand from a benchmark run on the
> specific commit and machine listed under **Environment of record**; they are
> **not** automatically backfilled into this doc. The
> [`.github/workflows/benchmark.yml`](../../.github/workflows/benchmark.yml)
> workflow is manually triggered (`workflow_dispatch`) plus a low-frequency
> weekly `schedule`, never runs on pull requests, sets **no** performance gate,
> and does **not** write back to the default branch. It runs
> `go test ... -bench . -benchmem -count=5` and uploads the full raw stdout plus
> environment metadata (commit SHA, runner OS/arch, `go version`, the exact
> command, and run duration) as a downloadable **artifact**; fetch it from the
> workflow run's *Artifacts* section to obtain fresh evidence. Do not confuse
> this with the `ci.yml` smoke benchmark (a `-benchtime=1x` build/execute check,
> also not a gate). Benchmark results reflect a single machine and are **not** a
> cross-device guarantee. Any `<!-- FILL: ... -->` marker or `TBD` is a
> placeholder — do not treat placeholders as measured values.

## Environment of record

- Date (UTC): 2026-08-21
- Go version: `go1.26.6`
- OS / arch: `darwin/arm64`
- CPU: Apple M5 (10 cores)
- Command: `go test ./pkg/license ./pkg/fingerprint -run '^$' -bench . -benchmem -count=5`
- `-count`: `5` (values below are the median of 5 runs)

## What each path includes

The four cost/side-effect profiles from the README map to these benchmarks:

1. **In-memory signature verify only** — `BenchmarkVerifySignature`. Ed25519
   verification over pre-decoded canonical bytes. No disk I/O, no policy checks.
2. **Full policy validation** — `BenchmarkValidateMemory`. Signature verify plus
   enum/time/device/version policy over in-memory input. Excludes file I/O.
3. **File load + rollback state persistence** — measured separately where noted;
   includes reading the license file and reading/writing the anti-rollback
   state file (disk I/O), so results depend on the filesystem.
4. **Device fingerprint collection** — `BenchmarkFingerprintCanonicalization`
   uses injected fixed components to stay independent of the host hardware; it
   measures normalization + canonicalization + hashing, **not** platform
   hardware collection (which is I/O-bound and host-specific).

## Results — `pkg/license`

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
| `BenchmarkCachedResult` (parallel) | `100.2` | `0` | `0` |
| `BenchmarkKeyRingLookup/1` | `17.96` | `0` | `0` |
| `BenchmarkKeyRingLookup/10` | `18.91` | `0` | `0` |
| `BenchmarkKeyRingLookup/100` | `19.75` | `0` | `0` |

## Results — `pkg/fingerprint`

| Benchmark | ns/op | B/op | allocs/op |
| --------- | ----- | ---- | --------- |
| `BenchmarkFingerprintCanonicalization` | `763.9` | `1216` | `23` |

The fingerprint package also reports a size sweep
(`BenchmarkFingerprintCanonicalizationSizes/components={1,4,16}`): median
`149.5` / `523.4` / `2049` ns/op respectively, using injected fixed components.

## Headline numbers (README)

Two or three of the above are surfaced in the README once measured:

- In-memory verify: `~34.6 us/op` (`BenchmarkVerifySignature`, `34552 ns/op`)
- Full policy validation: `~33.9 us/op` (`BenchmarkValidateMemory`, `33904 ns/op`)
- Envelope parse: `~2.7 us/op` (`BenchmarkParseEnvelope`, `2738 ns/op`)
