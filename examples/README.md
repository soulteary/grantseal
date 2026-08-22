# Examples — Multi-scenario license issuing & verification

[English](#english) | [简体中文](#简体中文) — back to the
[project README](../README.md)

---

## English

This directory shows how to use `cmd/license-tool` to issue a license for a
batch of **scenario configs**, then run `verify` (optionally with a revocation
list / device fingerprint / version) and **automatically assert** that each
scenario's `status` / `code` matches expectations.

One-shot run:

```bash
bash examples/run-scenarios.sh
```

The script will:

1. `keygen` on demand if keys are missing (reusing existing `keys/k1-*.key`);
2. `issue` each config into `examples/out/`;
3. build a revocation list `examples/out/revocation.lic` (revoking
   `lic_demo_revoked`);
4. run `verify` per scenario with the appropriate flags and assert actual ==
   expected;
5. print `PASS/FAIL` per scenario plus a summary, exiting non-zero if any
   scenario fails.

All artifacts land in `examples/out/` (git-ignored). The original
`examples/issue-config.json` and `examples/client/main.go` are left untouched.

### Scenario overview

All configs share `product_id=acme-app`, `key_id=k1`, and set `license_id`
explicitly.

- **01** `scenarios/01-valid-subscription.json` — valid subscription (far-future
  expiry); `-product acme-app -version 1.4.0` → `valid` / `LICENSE_OK`.
- **02** `scenarios/02-grace.json` — past hard expiry, still within grace window;
  `-product acme-app -version 1.4.0` → `grace` / `LICENSE_OK`.
- **03** `scenarios/03-expired.json` — past hard expiry, no grace;
  `-product acme-app -version 1.4.0` → `invalid` / `LICENSE_EXPIRED`.
- **04** `scenarios/04-not-yet-valid.json` — `not_before` in the future;
  `-product acme-app -version 1.4.0` → `invalid` / `LICENSE_NOT_YET_VALID`.
- **05** `scenarios/05-lifetime.json` — perpetual license (no expiry);
  `-product acme-app -version 1.4.0` → `valid` / `LICENSE_OK`.
- **06** `scenarios/06-trial.json` — trial license;
  `-product acme-app -version 1.4.0` → `valid` / `LICENSE_OK`.
- **07a** `scenarios/07-device-single.json` — single-device binding, fingerprint
  matches; `-device fp:v2:sha256:demo-device-fingerprint-0007` → `valid` /
  `LICENSE_OK`.
- **07b** `scenarios/07-device-single.json` — single-device binding, fingerprint
  mismatch; `-device sha256:some-other-device` → `invalid` /
  `LICENSE_DEVICE_MISMATCH`.
- **08a** `scenarios/08-version-constraint.json` — version in range;
  `-version 1.4.0` → `valid` / `LICENSE_OK`.
- **08b** `scenarios/08-version-constraint.json` — version out of range;
  `-version 3.0.0` → `invalid` / `LICENSE_VERSION_UNSUPPORTED`.
- **09** `scenarios/09-revoked.json` — revoked;
  `-revocation out/revocation.lic` → `invalid` / `LICENSE_REVOKED`.
- **10** `scenarios/10-product-mismatch.json` — product mismatch;
  `-product other-app` → `invalid` / `LICENSE_PRODUCT_MISMATCH`.

> On success `verify` exits `0` with `code = LICENSE_OK`; failing scenarios exit
> non-zero with the matching error code and `status = invalid`. `grace` counts
> as "still usable" and exits `0`.

### About the expired / grace timing (important)

The issuing pipeline **rejects** a certificate whose `expires_at` predates
`issued_at` during static validation (`LICENSE_MALFORMED`, see
`pkg/license/model.go`). So you **cannot directly issue an already-expired
certificate** — you cannot use an absolute past time like `2020`.

The verification pipeline also uses a **±5 minute clock skew** by default
(`DefaultClockSkew`, see `pkg/license/clock.go`): a license is only "expired"
once `now - skew > expires_at`. To avoid waiting 5 minutes in a demo, the
`verify` subcommand provides a `-clock-skew` flag (also tunable via the
`GRANTSEAL_CLOCK_SKEW` env var); the script passes a tiny skew (default `2s`)
for `expired` / `grace`, shrinking the boundary to a dozen seconds.

Combining both points, `expired` / `grace` use "**short TTL + small clock skew +
wait until after expiry, then verify**":

- at issue time, `expires_at` is set to a **near-future** time (placeholder
  `__EXPIRES_AT__` replaced by the script at runtime with `now +
  SHORT_TTL_SECONDS`, default 8s) so it passes static validation;
- `verify` is run with `-clock-skew 2s`; the script then `sleep`s until
  `now > expires_at + 2s`;
- `02-grace.json` has a large `grace_period_days` (still within the window) →
  `status=grace`;
- `03-expired.json` has `grace_period_days=0` (past hard expiry) →
  `code=LICENSE_EXPIRED`.
- both share one short TTL and are **merged into a single wait** to avoid
  waiting twice.

So a full run waits about **10–15 seconds** before grace/expired (short TTL +
small skew + buffer). Tunable via env vars:

```bash
# e.g. tune the boundary further (local demo/debug only)
SHORT_TTL_SECONDS=8 SKEW_SECONDS=2 WAIT_BUFFER_SECONDS=3 bash examples/run-scenarios.sh
```

- `SHORT_TTL_SECONDS`: seconds after issue until expiry (default 8);
- `SKEW_SECONDS`: clock skew passed to `verify -clock-skew` (default 2);
- `WAIT_BUFFER_SECONDS`: extra buffer after crossing the skew boundary
  (default 3).

> Safety note: `-clock-skew` / `GRANTSEAL_CLOCK_SKEW` only affects the tolerance
> of time comparisons; the library default is still ±5 minutes. Shrinking it
> only makes the demo cross the expiry boundary faster and does not affect
> signature or other checks.

### Directory layout

```
examples/
  scenarios/                # 10 scenario issue configs (02/03 contain time placeholders)
    01-valid-subscription.json
    02-grace.json
    03-expired.json
    04-not-yet-valid.json
    05-lifetime.json
    06-trial.json
    07-device-single.json
    08-version-constraint.json
    09-revoked.json
    10-product-mismatch.json
  run-scenarios.sh          # one-shot issue + verify + assert script
  out/                      # run artifacts (.lic / revocation list / rendered config), git-ignored
  README.md                 # this document
```

---

## 简体中文

本目录演示如何用 `cmd/license-tool` 对一批**场景化配置**逐个签发许可证,再用
`verify`(可带吊销列表 / 设备指纹 / 版本)跑出对应结果,并**自动断言**每个场景的
`status` / `code` 是否符合预期。

一键运行:

```bash
bash examples/run-scenarios.sh
```

脚本会:

1. 缺失密钥时自动 `keygen`(已有 `keys/k1-*.key` 则复用);
2. 逐个 `issue` 到 `examples/out/`;
3. 生成吊销列表 `examples/out/revocation.lic`(吊销 `lic_demo_revoked`);
4. 按场景带不同 `verify` 参数跑校验,并断言实际结果 == 预期;
5. 打印每个场景 `PASS/FAIL` 与总结,任一 `FAIL` 则以非零退出。

生成物统一放在 `examples/out/`(已加入 `.gitignore`)。原有
`examples/issue-config.json` 与 `examples/client/main.go` 保持不动。

## 场景一览

所有 config 统一 `product_id=acme-app`、`key_id=k1`,并显式写 `license_id`。

| # | Config | 场景 | verify 关键参数 | 预期 status | 预期 code |
|---|--------|------|-----------------|-------------|-----------|
| 01 | `scenarios/01-valid-subscription.json` | 有效订阅(远期到期) | `-product acme-app -version 1.4.0` | `valid` | `LICENSE_OK` |
| 02 | `scenarios/02-grace.json` | 已过硬到期、仍在宽限窗口 | `-product acme-app -version 1.4.0` | `grace` | `LICENSE_OK` |
| 03 | `scenarios/03-expired.json` | 已过硬到期、无宽限 | `-product acme-app -version 1.4.0` | `invalid` | `LICENSE_EXPIRED` |
| 04 | `scenarios/04-not-yet-valid.json` | `not_before` 在未来 | `-product acme-app -version 1.4.0` | `invalid` | `LICENSE_NOT_YET_VALID` |
| 05 | `scenarios/05-lifetime.json` | 永久授权(无到期) | `-product acme-app -version 1.4.0` | `valid` | `LICENSE_OK` |
| 06 | `scenarios/06-trial.json` | 试用授权 | `-product acme-app -version 1.4.0` | `valid` | `LICENSE_OK` |
| 07a | `scenarios/07-device-single.json` | 单设备绑定 · 指纹匹配 | `-device fp:v2:sha256:demo-device-fingerprint-0007` | `valid` | `LICENSE_OK` |
| 07b | `scenarios/07-device-single.json` | 单设备绑定 · 指纹不匹配 | `-device sha256:some-other-device` | `invalid` | `LICENSE_DEVICE_MISMATCH` |
| 08a | `scenarios/08-version-constraint.json` | 版本范围内 | `-version 1.4.0` | `valid` | `LICENSE_OK` |
| 08b | `scenarios/08-version-constraint.json` | 版本超范围 | `-version 3.0.0` | `invalid` | `LICENSE_VERSION_UNSUPPORTED` |
| 09 | `scenarios/09-revoked.json` | 已吊销 | `-revocation out/revocation.lic` | `invalid` | `LICENSE_REVOKED` |
| 10 | `scenarios/10-product-mismatch.json` | 产品不匹配 | `-product other-app` | `invalid` | `LICENSE_PRODUCT_MISMATCH` |

> 说明:`verify` 成功时退出码为 0、`code` 为 `LICENSE_OK`;失败场景退出码非 0,
> `code` 为对应的错误码,`status` 为 `invalid`。`grace` 属于"仍可用"状态,退出码为 0。

## 关于 expired / grace 的时间构造(重要)

签发管线在静态校验阶段会**拒绝** `expires_at` 早于 `issued_at` 的证书
(`LICENSE_MALFORMED`,见 `pkg/license/model.go`)。因此**无法直接签发一份"已经
过期"的证书**——不能用 `2020` 这类过去的绝对时间。

同时,验证管线**默认**使用 **±5 分钟时钟偏移**(`DefaultClockSkew`,见
`pkg/license/clock.go`),即只有当 `now - skew > expires_at` 时才判定为过期。为
避免演示时干等 5 分钟,`verify` 子命令提供了 `-clock-skew` flag(也可用环境变量
`GRANTSEAL_CLOCK_SKEW` 调整默认值),脚本对 `expired` / `grace` 传入一个很小的偏移
(默认 `2s`),把等待边界压缩到十几秒。

综合以上两点,本示例对 `expired` / `grace` 采用「**短有效期 + 小时钟偏移 + 等待到
过期后再 verify**」的方式:

- 签发时把 `expires_at` 设为"签发后不久"的**将来**时间(占位符 `__EXPIRES_AT__`
  由脚本在运行时替换为 `now + SHORT_TTL_SECONDS`,默认 8s),从而通过静态校验;
- `verify` 时传 `-clock-skew 2s`,脚本随后 `sleep` 到 `now > expires_at + 2s` 再执行;
- `02-grace.json` 的 `grace_period_days` 很大(仍在宽限窗口内)→ `status=grace`;
- `03-expired.json` 的 `grace_period_days=0`(已过硬到期)→ `code=LICENSE_EXPIRED`。
- 两者共用同一份短有效期,**合并为一次等待**,避免重复等待。

因此完整跑一次脚本会在 grace/expired 前等待约 **10~15 秒**(短 TTL + 小偏移 + 缓冲)。
可用环境变量微调:

```bash
# 例:进一步调整边界(仅用于本地演示/调试)
SHORT_TTL_SECONDS=8 SKEW_SECONDS=2 WAIT_BUFFER_SECONDS=3 bash examples/run-scenarios.sh
```

- `SHORT_TTL_SECONDS`:签发后多少秒过期(默认 8);
- `SKEW_SECONDS`:传给 `verify -clock-skew` 的时钟偏移秒数(默认 2);
- `WAIT_BUFFER_SECONDS`:越过偏移边界后的额外缓冲(默认 3)。

> 安全说明:`-clock-skew` / `GRANTSEAL_CLOCK_SKEW` 仅影响时间比较的容差,默认仍是
> 库内的 ±5 分钟;调小只是为了让演示更快越过过期边界,不影响签名与其它校验。

## 目录结构

```
examples/
  scenarios/                # 10 份场景化 issue config(其中 02/03 含时间占位符)
    01-valid-subscription.json
    02-grace.json
    03-expired.json
    04-not-yet-valid.json
    05-lifetime.json
    06-trial.json
    07-device-single.json
    08-version-constraint.json
    09-revoked.json
    10-product-mismatch.json
  run-scenarios.sh          # 一键签发 + 验证 + 断言脚本
  out/                      # 运行产物(.lic / 吊销列表 / 渲染后的 config),已被 .gitignore 忽略
  README.md                 # 本文档
```
