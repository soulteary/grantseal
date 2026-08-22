#!/usr/bin/env bash
#
# check-doc-consistency-selftest.sh — self-test for check-doc-consistency.sh.
#
# It builds a temporary fixture tree that plants each drift condition and
# asserts the checker FAILS on it, then plants a clean tree and asserts the
# checker PASSES. This guards the checker against silently rotting into a
# no-op.
#
# Exit codes:
#   0  the checker behaves correctly on all fixtures
#   1  the checker missed a planted drift or false-positived on a clean tree
#   2  usage / environment error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECKER="$SCRIPT_DIR/check-doc-consistency.sh"

if [ ! -f "$CHECKER" ]; then
  echo "error: checker not found at $CHECKER" >&2
  exit 2
fi
if ! command -v rg >/dev/null 2>&1; then
  echo "error: ripgrep (rg) is required but not installed" >&2
  exit 2
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail=0

expect_fail() {
  # $1 = dir, $2 = case description
  if bash "$CHECKER" "$1" >/dev/null 2>&1; then
    echo "MISS: checker passed but should have failed: $2" >&2
    fail=1
  else
    echo "ok (detected): $2"
  fi
}

expect_pass() {
  if bash "$CHECKER" "$1" >/dev/null 2>&1; then
    echo "ok (clean): $2"
  else
    echo "FALSE POSITIVE: checker failed on a clean tree: $2" >&2
    fail=1
  fi
}

# Case 1a: matrix.go in a workflow.
d="$TMP/c1a"; mkdir -p "$d/.github/workflows"
printf 'jobs:\n  x:\n    strategy:\n      matrix:\n        go: ["1.26"]\n    steps:\n      - run: echo ${{ matrix.go }}\n' >"$d/.github/workflows/ci.yml"
expect_fail "$d" "workflow matrix.go"

# Case 1b: literal go-version: pin.
d="$TMP/c1b"; mkdir -p "$d/.github/workflows"
printf 'steps:\n  - uses: actions/setup-go@v7\n    with:\n      go-version: "1.26.6"\n' >"$d/.github/workflows/ci.yml"
expect_fail "$d" "workflow literal go-version:"

# Case 2: stale error-code count.
d="$TMP/c2"; mkdir -p "$d"
printf 'The full set (23 codes):\n' >"$d/README.md"
expect_fail "$d" "stale 23 codes count"

# Case 3: LICENSE_FEATURE_DENIED wire string in a doc.
d="$TMP/c3"; mkdir -p "$d"
printf 'Returns `LICENSE_FEATURE_DENIED` when denied.\n' >"$d/x.md"
expect_fail "$d" "LICENSE_FEATURE_DENIED wire string"

# Case 4: deprecated "state is reset" phrasing.
d="$TMP/c4"; mkdir -p "$d"
printf 'a lifetime license is tolerated and the state is reset.\n' >"$d/x.md"
expect_fail "$d" "state is reset phrasing"

# Clean tree: uses only the correct forms.
d="$TMP/clean"; mkdir -p "$d/.github/workflows"
printf 'steps:\n  - uses: actions/setup-go@v7\n    with:\n      go-version-file: "go.mod"\n      check-latest: false\n' >"$d/.github/workflows/ci.yml"
{
  echo 'The full set is 31 distinct wire codes (LICENSE_OK plus 30 failure codes).'
  echo 'RequireFeature returns `CodeFeatureUnavailable` (wire `LICENSE_FEATURE_UNAVAILABLE`).'
  echo 'CodeFeatureDenied is a Go alias for the same wire code.'
  echo 'A corrupt state is never silently reset; lifetime licenses do not touch it.'
} >"$d/README.md"
expect_pass "$d" "clean documentation tree"

if [ "$fail" -ne 0 ]; then
  echo "error: check-doc-consistency self-test FAILED" >&2
  exit 1
fi

echo "check-doc-consistency self-test passed"
exit 0
