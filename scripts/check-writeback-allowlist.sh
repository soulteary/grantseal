#!/usr/bin/env bash
#
# check-writeback-allowlist.sh — verify a report write-back job only stages
# generated report files. Used by the restricted write-back jobs in CI, which
# are the only jobs holding `contents: write`. The report-generating Action
# itself runs read-only and hands its output to this gate before any commit,
# so a compromised or buggy generator can never push arbitrary files.
#
# It inspects the staged (git index) changes and fails if any staged path is
# outside the allowlist of known report artifacts. Run after `git add` of the
# report files and before `git commit`.
#
# Allowlisted paths (exact, repo-relative):
#   .github/go-test-report.json
#   .github/go-test-report.md
#   .github/coverage.svg
#   .github/goreportcard.svg
#   .github/goreportcard-report.md
#   docs/enUS/quality.md
#   docs/zhCN/quality.md
#
# Exit codes:
#   0  every staged path is allowlisted (or nothing is staged)
#   1  a staged path is outside the allowlist
#   2  usage / environment error

set -euo pipefail

# Exact repo-relative paths the report write-back is permitted to commit.
ALLOWLIST=(
  ".github/go-test-report.json"
  ".github/go-test-report.md"
  ".github/coverage.svg"
  ".github/goreportcard.svg"
  ".github/goreportcard-report.md"
  "docs/enUS/quality.md"
  "docs/zhCN/quality.md"
)

is_allowed() {
  local path="$1"
  local allowed
  for allowed in "${ALLOWLIST[@]}"; do
    if [ "$path" = "$allowed" ]; then
      return 0
    fi
  done
  return 1
}

if ! command -v git >/dev/null 2>&1; then
  echo "error: git not found" >&2
  exit 2
fi

# Read staged paths NUL-delimited directly from git (command substitution would
# strip the NULs, so stream via process substitution instead).
violation=0
staged_any=0
while IFS= read -r -d '' path; do
  [ -z "$path" ] && continue
  staged_any=1
  if ! is_allowed "$path"; then
    echo "disallowed staged path (outside report allowlist): $path" >&2
    violation=1
  fi
done < <(git diff --cached --name-only -z)

if [ "$staged_any" -eq 0 ]; then
  echo "note: nothing staged, write-back allowlist check is a no-op"
  exit 0
fi

if [ "$violation" -ne 0 ]; then
  echo "error: write-back staged files outside the report allowlist; refusing to commit" >&2
  exit 1
fi

echo "write-back allowlist check passed: all staged files are allowlisted report artifacts"
exit 0
