#!/usr/bin/env bash
#
# check-doc-consistency.sh — lightweight guard against documentation drift that
# the plain prose/coverage generators cannot catch.
#
# It fails when any of the following regressions reappear:
#   1. A GitHub workflow references a Go version matrix (`matrix.go`) or pins a
#      literal `go-version:` — the single source of truth is `go-version-file:
#      go.mod`, so these must never come back.
#   2. A Markdown doc hardcodes a stale stable-error-code count ("23 codes" /
#      "23 个") instead of the current wire-code total.
#   3. A Markdown doc claims `LICENSE_FEATURE_DENIED` is a distinct *wire* code
#      (the stable wire string is `LICENSE_FEATURE_UNAVAILABLE`; CodeFeatureDenied
#      is only a Go-identifier alias). The bare identifier `CodeFeatureDenied`
#      and mentions that explicitly call it an alias are fine.
#   4. A doc still uses the deprecated anti-rollback phrasing that a corrupt
#      state is "reset" for lifetime licenses ("state is reset" / "重置状态" /
#      "并重置"). The correct model: lifetime licenses do not touch the state at
#      all, and a corrupt state is never silently reset.
#
# Usage:
#   scripts/check-doc-consistency.sh [root-dir]
#
# Exit codes:
#   0  no drift found
#   1  at least one drift condition matched
#   2  usage / environment error
#
# Requires ripgrep (rg).

set -euo pipefail

ROOT="${1:-.}"

if ! command -v rg >/dev/null 2>&1; then
  echo "error: ripgrep (rg) is required but not installed" >&2
  exit 2
fi
if [ ! -d "$ROOT" ]; then
  echo "error: root dir not found: $ROOT" >&2
  exit 2
fi

violations=0

report() {
  # $1 = human description, $2 = rg matches (possibly empty)
  if [ -n "$2" ]; then
    echo "drift: $1" >&2
    echo "$2" | sed 's/^/  /' >&2
    violations=$((violations + 1))
  fi
}

WF_DIR="$ROOT/.github/workflows"
if [ -d "$WF_DIR" ]; then
  # 1a. Go version matrix reference.
  m="$(rg --no-heading --line-number --color never -e 'matrix\.go' "$WF_DIR" || true)"
  report "workflow references a Go version matrix (matrix.go)" "$m"

  # 1b. Active (non-commented) go-version: pin. Allow go-version-file:.
  m="$(rg --no-heading --line-number --color never -e '^\s*go-version:\s' "$WF_DIR" || true)"
  report "workflow pins a literal go-version: (use go-version-file: go.mod)" "$m"
fi

# 2. Stale hardcoded error-code count.
m="$(rg --no-heading --line-number --color never -g '*.md' -e '23 codes' -e '23 个' "$ROOT" || true)"
report "doc hardcodes a stale error-code count (23 codes / 23 个)" "$m"

# 3. Claiming LICENSE_FEATURE_DENIED is a live wire code. The correct wire
#    string is LICENSE_FEATURE_UNAVAILABLE. Lines that explicitly explain the
#    alias / deny that the wire string exists are legitimate, so exclude lines
#    carrying a negation/alias marker (no / not / there is no / alias / 不存在 /
#    别名 / 不等于).
m="$(rg --no-heading --line-number --color never -g '*.md' -e 'LICENSE_FEATURE_DENIED' "$ROOT" \
  | rg -v -e '\bno\b' -e '\bnot\b' -e '\balias\b' -e '不存在' -e '别名' -e '不等于' || true)"
report "doc references LICENSE_FEATURE_DENIED as a live wire code (use LICENSE_FEATURE_UNAVAILABLE)" "$m"

# 4. Deprecated "state is reset" phrasing for lifetime licenses.
m="$(rg --no-heading --line-number --color never -g '*.md' \
  -e 'state is reset' -e 'the state is reset' \
  -e '并重置状态' -e '容忍并重置' "$ROOT" || true)"
report "doc uses deprecated 'state is reset' anti-rollback phrasing" "$m"

if [ "$violations" -gt 0 ]; then
  echo "error: found $violations documentation-consistency drift condition(s)" >&2
  exit 1
fi

echo "doc-consistency check passed: no drift found"
exit 0
