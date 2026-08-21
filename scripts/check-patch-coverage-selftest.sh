#!/usr/bin/env bash
#
# check-patch-coverage-selftest.sh — proves scripts/check-patch-coverage.sh both
# PASSES fully-covered changed code and FAILS uncovered changed code, using a
# throwaway git repo and synthetic coverage profiles. Runs in CI so the gate
# logic itself is regression-tested (dependency-free: git + bash + python3).
#
# Exit codes:
#   0  the gate accepted covered code and rejected uncovered code
#   1  the gate misbehaved
#   2  usage / environment error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="$SCRIPT_DIR/check-patch-coverage.sh"

if [ ! -f "$GATE" ]; then
  echo "error: gate script not found: $GATE" >&2
  exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cd "$WORK"
git init -q
git config user.email selftest@example.com
git config user.name selftest
git config commit.gpgsign false

# Base commit: a file with one function.
mkdir -p pkg/demo
cat >pkg/demo/demo.go <<'GO'
package demo

func Base() int {
	return 1
}
GO
git add -A
git commit -qm base
BASE="$(git rev-parse HEAD)"

# Change commit: add two functions (added lines).
cat >pkg/demo/demo.go <<'GO'
package demo

func Base() int {
	return 1
}

func Added() int {
	return 2
}

func Uncovered() int {
	return 3
}
GO
git add -A
git commit -qm change

# The added lines are the bodies of Added() (lines 7-9) and Uncovered() (11-13).
# Build a profile that covers Added() but NOT Uncovered().
cat >covered.out <<'PROF'
mode: atomic
example.com/m/pkg/demo/demo.go:3.14,5.2 1 1
example.com/m/pkg/demo/demo.go:7.15,9.2 1 1
example.com/m/pkg/demo/demo.go:11.20,13.2 1 1
PROF

# Same, but Uncovered()'s block has count 0.
cat >partial.out <<'PROF'
mode: atomic
example.com/m/pkg/demo/demo.go:3.14,5.2 1 1
example.com/m/pkg/demo/demo.go:7.15,9.2 1 1
example.com/m/pkg/demo/demo.go:11.20,13.2 1 0
PROF

fail=0

# Case 1: everything covered -> gate PASSES at 90%.
if bash "$GATE" covered.out "$BASE" 90 >/tmp/pc_pass.log 2>&1; then
  echo "PASS: fully-covered change accepted"
else
  echo "FAIL: fully-covered change was rejected" >&2
  cat /tmp/pc_pass.log >&2
  fail=1
fi

# Case 2: one of two changed funcs uncovered -> 50% < 90% -> gate FAILS.
if bash "$GATE" partial.out "$BASE" 90 >/tmp/pc_fail.log 2>&1; then
  echo "FAIL: half-covered change was accepted (should fail)" >&2
  cat /tmp/pc_fail.log >&2
  fail=1
else
  echo "PASS: half-covered change rejected"
fi

# Case 3: a lower threshold accepts the same half-covered change.
if bash "$GATE" partial.out "$BASE" 40 >/tmp/pc_thr.log 2>&1; then
  echo "PASS: threshold tuning honored (40% accepts 50%)"
else
  echo "FAIL: threshold tuning not honored" >&2
  cat /tmp/pc_thr.log >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "check-patch-coverage self-test FAILED" >&2
  exit 1
fi
echo "check-patch-coverage self-test passed"
exit 0
