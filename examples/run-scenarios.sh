#!/usr/bin/env bash
#
# run-scenarios.sh — 多场景授权签发与验证示例
#
# 该脚本使用 cmd/license-tool 对一批场景化配置逐个签发许可证,并用 verify
# (含吊销列表 / 设备指纹 / 版本) 跑出对应结果,断言每个场景的实际
# status/code 与预期一致,最终打印 PASS/FAIL 总结。任一 FAIL 则以非零退出。
#
# 用法:
#   bash examples/run-scenarios.sh
#
# 关于 expired / grace 的时间构造(重要):
#   静态校验会拒绝 expires_at 早于 issued_at 的证书(LICENSE_MALFORMED),
#   因此无法直接签发一份"已经过期"的证书。同时验证管线固定 ±5 分钟时钟偏移
#   (DefaultClockSkew),且 CLI 的 verify 没有注入时钟的 flag。
#   所以本脚本对 expired / grace 采用「短有效期 + 等待到过期后再 verify」:
#     - 签发时把 expires_at 设为"签发后不久"的将来时间(通过静态校验);
#     - verify 时通过 -clock-skew 传入一个很小的偏移(默认 2s),把等待边界
#       从固定 5 分钟压缩到「短 TTL + 小 skew + 缓冲」,总计约 10~15s;
#     - grace 场景 grace_period_days 很大(仍在宽限窗口内)→ status=grace;
#     - expired 场景 grace_period_days=0(超过硬过期)→ code=LICENSE_EXPIRED。
#   expired 与 grace 共用同一份短有效期,合并为一次等待,避免重复等待。

set -euo pipefail

# ---- 路径 ----
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

SCEN_DIR="examples/scenarios"
OUT_DIR="examples/out"
# 示例密钥写入 gitignored 的 examples/out/keys,避免在仓库根 keys/ 落盘。
KEYS_DIR="$OUT_DIR/keys"
PRIV="$KEYS_DIR/k1-private.key"
PUB="$KEYS_DIR/k1-public.key"
KEY_ID="k1"

# 预编译 license-tool,避免每次 go run 的编译延迟影响短有效期时序。
BIN="$OUT_DIR/license-tool"
TOOL="$BIN"

# 时钟偏移:通过 verify 的 -clock-skew 传入一个很小的值,避免等待固定 5 分钟。
# 等待到过期需 now - skew > expires_at。
SKEW_SECONDS="${SKEW_SECONDS:-2}"
# expired/grace 短有效期(签发后多少秒过期)。留出静态校验与签发的富余时间。
SHORT_TTL_SECONDS="${SHORT_TTL_SECONDS:-8}"
# 过期后额外缓冲,确保稳过 skew 边界。
WAIT_BUFFER_SECONDS="${WAIT_BUFFER_SECONDS:-3}"

mkdir -p "$OUT_DIR"

# ---- 预编译工具 ----
echo "== build: 编译 license-tool -> $BIN =="
go build -o "$BIN" ./cmd/license-tool

# ---- 统计 ----
PASS_COUNT=0
FAIL_COUNT=0
RESULTS=()

# 记录一次断言结果。
record() {
  local name="$1" ok="$2" detail="$3"
  if [[ "$ok" == "1" ]]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    RESULTS+=("PASS  $name  |  $detail")
    echo ">>> PASS  $name  |  $detail"
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    RESULTS+=("FAIL  $name  |  $detail")
    echo ">>> FAIL  $name  |  $detail"
  fi
}

# 运行 verify,把 status/code 抓出来。verify 失败(非 0 退出)时也要继续,
# 因为失败本身可能就是期望结果。
# 输出全局变量:V_STATUS / V_CODE。
run_verify() {
  local out
  set +e
  out="$($TOOL verify "$@" 2>/dev/null)"
  set -e
  V_STATUS="$(printf '%s\n' "$out" | awk -F': ' '/^status:/{gsub(/ /,"",$2); print $2; exit}')"
  V_CODE="$(printf '%s\n' "$out" | awk -F': ' '/^code:/{gsub(/ /,"",$2); print $2; exit}')"
}

# 断言 status 与 code 同时匹配。
assert_status_code() {
  local name="$1" want_status="$2" want_code="$3"
  local detail="expect status=$want_status code=$want_code | got status=${V_STATUS:-<none>} code=${V_CODE:-<none>}"
  if [[ "${V_STATUS:-}" == "$want_status" && "${V_CODE:-}" == "$want_code" ]]; then
    record "$name" 1 "$detail"
  else
    record "$name" 0 "$detail"
  fi
}

# ---- 1. 密钥(缺失时生成)----
if [[ ! -f "$PRIV" || ! -f "$PUB" ]]; then
  echo "== keygen: 私钥/公钥缺失,生成 $KEY_ID =="
  $TOOL keygen -key-id "$KEY_ID" -out-dir "$KEYS_DIR" -force
else
  echo "== keygen: 复用已有密钥 $PRIV / $PUB =="
fi

# ---- 2. 计算 expired / grace 的短有效期时间戳(RFC3339 UTC)----
# 使用 GNU/BSD date 兼容写法。
now_plus_rfc3339() {
  local secs="$1"
  if date -u -d "@0" >/dev/null 2>&1; then
    # GNU date
    date -u -d "+${secs} seconds" +"%Y-%m-%dT%H:%M:%SZ"
  else
    # BSD/macOS date
    date -u -v+"${secs}"S +"%Y-%m-%dT%H:%M:%SZ"
  fi
}

SHORT_EXPIRES_AT="$(now_plus_rfc3339 "$SHORT_TTL_SECONDS")"
# 记录用于等待的过期时刻(epoch)。
if date -u -d "@0" >/dev/null 2>&1; then
  EXPIRES_EPOCH="$(date -u -d "$SHORT_EXPIRES_AT" +%s)"
else
  EXPIRES_EPOCH="$(date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "$SHORT_EXPIRES_AT" +%s)"
fi
echo "== expired/grace 短有效期 expires_at=$SHORT_EXPIRES_AT (epoch=$EXPIRES_EPOCH) =="

# 用占位符生成带时间戳的实际 config。
render_config() {
  local src="$1" dst="$2"
  sed "s|__EXPIRES_AT__|$SHORT_EXPIRES_AT|g" "$src" > "$dst"
}

# ---- 3. 逐个签发 ----
echo "== issue: 逐个签发许可证到 $OUT_DIR =="
issue_one() {
  local cfg="$1" lic="$2"
  $TOOL issue -config "$cfg" -key "$PRIV" -out "$lic" -force
}

# expired / grace 用渲染后的 config。
CFG_GRACE="$OUT_DIR/02-grace.rendered.json"
CFG_EXPIRED="$OUT_DIR/03-expired.rendered.json"
render_config "$SCEN_DIR/02-grace.json" "$CFG_GRACE"
render_config "$SCEN_DIR/03-expired.json" "$CFG_EXPIRED"

issue_one "$SCEN_DIR/01-valid-subscription.json" "$OUT_DIR/01-valid-subscription.lic"
issue_one "$CFG_GRACE"                            "$OUT_DIR/02-grace.lic"
issue_one "$CFG_EXPIRED"                          "$OUT_DIR/03-expired.lic"
issue_one "$SCEN_DIR/04-not-yet-valid.json"       "$OUT_DIR/04-not-yet-valid.lic"
issue_one "$SCEN_DIR/05-lifetime.json"            "$OUT_DIR/05-lifetime.lic"
issue_one "$SCEN_DIR/06-trial.json"               "$OUT_DIR/06-trial.lic"
issue_one "$SCEN_DIR/07-device-single.json"       "$OUT_DIR/07-device-single.lic"
issue_one "$SCEN_DIR/08-version-constraint.json"  "$OUT_DIR/08-version-constraint.lic"
issue_one "$SCEN_DIR/09-revoked.json"             "$OUT_DIR/09-revoked.lic"
issue_one "$SCEN_DIR/10-product-mismatch.json"    "$OUT_DIR/10-product-mismatch.lic"

# ---- 4. 生成吊销列表(吊销 revoked 场景的 license_id)----
echo "== revoke-list: 生成吊销列表 =="
$TOOL revoke-list -key "$PRIV" -key-id "$KEY_ID" -ids "lic_demo_revoked" \
  -list-id "acme-revocation" -sequence 1 -ttl 720h \
  -out "$OUT_DIR/revocation.lic" -force

# ---- 5. 验证:不依赖时间的场景先跑 ----
echo ""
echo "===== 开始验证(不依赖过期时间的场景)====="

# 01 valid-subscription → valid
run_verify -license "$OUT_DIR/01-valid-subscription.lic" -pubkey "$PUB" -product acme-app -version 1.4.0
assert_status_code "01-valid-subscription" "valid" "LICENSE_OK"

# 04 not-yet-valid → LICENSE_NOT_YET_VALID
run_verify -license "$OUT_DIR/04-not-yet-valid.lic" -pubkey "$PUB" -product acme-app -version 1.4.0
assert_status_code "04-not-yet-valid" "invalid" "LICENSE_NOT_YET_VALID"

# 05 lifetime → valid
run_verify -license "$OUT_DIR/05-lifetime.lic" -pubkey "$PUB" -product acme-app -version 1.4.0
assert_status_code "05-lifetime" "valid" "LICENSE_OK"

# 06 trial → valid
run_verify -license "$OUT_DIR/06-trial.lic" -pubkey "$PUB" -product acme-app -version 1.4.0
assert_status_code "06-trial" "valid" "LICENSE_OK"

# 07 device-single:匹配 → valid
run_verify -license "$OUT_DIR/07-device-single.lic" -pubkey "$PUB" -product acme-app \
  -device "fp:v2:sha256:0707070707070707070707070707070707070707070707070707070707070707"
assert_status_code "07-device-single (match)" "valid" "LICENSE_OK"

# 07 device-single:不匹配（有效但不同的版本化指纹）→ LICENSE_DEVICE_MISMATCH
run_verify -license "$OUT_DIR/07-device-single.lic" -pubkey "$PUB" -product acme-app \
  -device "fp:v2:sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
assert_status_code "07-device-single (mismatch)" "invalid" "LICENSE_DEVICE_MISMATCH"

# 08 version-constraint:范围内(1.4.0) → valid
run_verify -license "$OUT_DIR/08-version-constraint.lic" -pubkey "$PUB" -product acme-app -version 1.4.0
assert_status_code "08-version (in-range 1.4.0)" "valid" "LICENSE_OK"

# 08 version-constraint:超范围(3.0.0) → LICENSE_VERSION_UNSUPPORTED
run_verify -license "$OUT_DIR/08-version-constraint.lic" -pubkey "$PUB" -product acme-app -version 3.0.0
assert_status_code "08-version (out-of-range 3.0.0)" "invalid" "LICENSE_VERSION_UNSUPPORTED"

# 09 revoked:带吊销列表 → LICENSE_REVOKED
run_verify -license "$OUT_DIR/09-revoked.lic" -pubkey "$PUB" -product acme-app -version 1.4.0 \
  -revocation "$OUT_DIR/revocation.lic"
assert_status_code "09-revoked" "invalid" "LICENSE_REVOKED"

# 10 product-mismatch:传错误 product → LICENSE_PRODUCT_MISMATCH
run_verify -license "$OUT_DIR/10-product-mismatch.lic" -pubkey "$PUB" -product other-app -version 1.4.0
assert_status_code "10-product-mismatch" "invalid" "LICENSE_PRODUCT_MISMATCH"

# ---- 6. 等待到过期,再验证 expired / grace ----
echo ""
echo "===== 等待到短有效期过期后,验证 grace / expired 场景 ====="
# 需要 now - skew > expires_at,即 now > expires_at + skew。
TARGET_EPOCH=$((EXPIRES_EPOCH + SKEW_SECONDS + WAIT_BUFFER_SECONDS))
NOW_EPOCH="$(date -u +%s)"
WAIT_SECS=$((TARGET_EPOCH - NOW_EPOCH))
if (( WAIT_SECS > 0 )); then
  echo "== 需等待约 ${WAIT_SECS}s 以越过 +${SKEW_SECONDS}s 时钟偏移边界 =="
  sleep "$WAIT_SECS"
else
  echo "== 无需等待(已越过过期边界)=="
fi

# 传给 expired/grace verify 的时钟偏移参数(转成 Go duration,如 2s)。
SKEW_ARG="${SKEW_SECONDS}s"

# 02 grace:硬过期后仍在宽限窗口内 → status=grace
run_verify -license "$OUT_DIR/02-grace.lic" -pubkey "$PUB" -product acme-app -version 1.4.0 \
  -clock-skew "$SKEW_ARG"
assert_status_code "02-grace" "grace" "LICENSE_OK"

# 03 expired:硬过期且无宽限 → LICENSE_EXPIRED
run_verify -license "$OUT_DIR/03-expired.lic" -pubkey "$PUB" -product acme-app -version 1.4.0 \
  -clock-skew "$SKEW_ARG"
assert_status_code "03-expired" "invalid" "LICENSE_EXPIRED"

# ---- 7. 总结 ----
echo ""
echo "================= 场景验证总结 ================="
for line in "${RESULTS[@]}"; do
  echo "  $line"
done
echo "------------------------------------------------"
echo "  PASS: $PASS_COUNT   FAIL: $FAIL_COUNT   TOTAL: $((PASS_COUNT + FAIL_COUNT))"
echo "================================================"

if (( FAIL_COUNT > 0 )); then
  echo "存在失败场景,退出码非 0。"
  exit 1
fi
echo "全部场景 PASS。"
