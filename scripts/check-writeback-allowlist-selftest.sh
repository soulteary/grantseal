#!/usr/bin/env bash
#
# check-writeback-allowlist-selftest.sh — self-test for
# check-writeback-allowlist.sh.
#
# It builds a throwaway git repo, stages various file sets, and asserts the
# gate passes for allowlisted report paths and fails for anything else.
#
# Cases:
#   1. Only allowlisted report files staged   -> gate passes (exit 0)
#   2. An extra non-report file staged         -> gate fails  (exit 1)
#   3. Nothing staged                          -> gate passes (no-op, exit 0)
#
# Exit codes:
#   0  all cases behaved as expected (gate is working)
#   1  a case behaved unexpectedly (gate regression)
#   2  usage / environment error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="$SCRIPT_DIR/check-writeback-allowlist.sh"

if [ ! -f "$GATE" ]; then
  echo "error: gate not found at $GATE" >&2
  exit 2
fi

tmp="$(mktemp -d)"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT

cd "$tmp"
git init -q
git config user.name "selftest"
git config user.email "selftest@example.com"
git config commit.gpgsign false
mkdir -p .github scripts
cp "$GATE" scripts/check-writeback-allowlist.sh

# Seed an initial commit so `git diff --cached` has a baseline.
echo "seed" >seed.txt
git add seed.txt
git commit -qm "seed"

# Case 1: only allowlisted report files staged -> must PASS.
echo '{}' >.github/go-test-report.json
echo '# report' >.github/go-test-report.md
echo '<svg/>' >.github/coverage.svg
echo '<svg/>' >.github/goreportcard.svg
echo '# grc' >.github/goreportcard-report.md
mkdir -p docs/enUS docs/zhCN
echo '# quality' >docs/enUS/quality.md
echo '# 质量' >docs/zhCN/quality.md
git add -- \
  .github/go-test-report.json \
  .github/go-test-report.md \
  .github/coverage.svg \
  .github/goreportcard.svg \
  .github/goreportcard-report.md \
  docs/enUS/quality.md \
  docs/zhCN/quality.md
if ! bash scripts/check-writeback-allowlist.sh >/dev/null 2>&1; then
  echo "SELFTEST FAIL: gate rejected an allowlisted-only staged set" >&2
  exit 1
fi
git reset -q

# Case 2: an extra non-report file staged -> must FAIL.
echo '{}' >.github/go-test-report.json
echo 'malicious' >evil.sh
git add -- .github/go-test-report.json evil.sh
if bash scripts/check-writeback-allowlist.sh >/dev/null 2>&1; then
  echo "SELFTEST FAIL: gate accepted a staged file outside the allowlist (evil.sh)" >&2
  exit 1
fi
git reset -q

# Case 3: nothing staged -> must PASS (no-op).
if ! bash scripts/check-writeback-allowlist.sh >/dev/null 2>&1; then
  echo "SELFTEST FAIL: gate errored with an empty staging area" >&2
  exit 1
fi

echo "write-back allowlist self-test passed: allowlisted-only commits allowed, extras rejected"
exit 0
