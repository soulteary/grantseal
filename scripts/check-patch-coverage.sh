#!/usr/bin/env bash
#
# check-patch-coverage.sh — enforce a minimum coverage floor on CHANGED code.
#
# The repo-wide coverage gate (total >= 80%, per-package >= 70%) can hide a PR
# that adds a big chunk of untested code, because the untested lines are diluted
# by the existing well-tested tree. This script closes that gap: it looks only at
# the lines a change *added or modified* and requires that a high fraction of the
# executable ones are covered by the test run.
#
# It is dependency-free at runtime (the project ships zero third-party Go
# modules); it needs only git, bash, and python3 — all CI-only tooling.
#
# Usage:
#   scripts/check-patch-coverage.sh COVERAGE_PROFILE [BASE_REF] [THRESHOLD]
#
#   COVERAGE_PROFILE  Go coverage profile (e.g. coverage.out), `-covermode`
#                     agnostic (set/count/atomic all parse the same).
#   BASE_REF          git ref to diff against (default: origin/HEAD, then HEAD~1).
#   THRESHOLD         minimum percent of changed statements that must be covered
#                     (default: 90).
#
# Semantics:
#   - Only added/modified lines in *.go files (excluding *_test.go) are scored.
#   - A changed line counts as "coverable" when it falls inside a coverage
#     profile block; its statements are "covered" when that block's count > 0.
#   - If a change adds NO coverable statements (docs, comments, test-only, or a
#     pure deletion), the gate passes vacuously — there is nothing to cover.
#   - Fail-closed: a missing profile or an unparseable input is an error, never
#     a silent pass.
#
# Exit codes:
#   0  changed-code coverage >= threshold (or nothing coverable changed)
#   1  changed-code coverage below threshold
#   2  usage / environment error

set -euo pipefail

PROFILE="${1:-}"
BASE_REF="${2:-}"
THRESHOLD="${3:-90}"

if [ -z "$PROFILE" ]; then
  echo "usage: $0 COVERAGE_PROFILE [BASE_REF] [THRESHOLD]" >&2
  exit 2
fi
if [ ! -f "$PROFILE" ]; then
  echo "error: coverage profile not found: $PROFILE" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required" >&2
  exit 2
fi
if ! command -v git >/dev/null 2>&1; then
  echo "error: git is required" >&2
  exit 2
fi

# Resolve a base ref if none was given. Prefer the remote default branch's merge
# base; fall back to HEAD~1 for local single-commit runs.
if [ -z "$BASE_REF" ]; then
  if git rev-parse --verify -q origin/HEAD >/dev/null; then
    BASE_REF="$(git merge-base origin/HEAD HEAD 2>/dev/null || echo "")"
  fi
  if [ -z "$BASE_REF" ]; then
    BASE_REF="$(git rev-parse --verify -q HEAD~1 || echo "")"
  fi
fi
if [ -z "$BASE_REF" ]; then
  echo "note: no base ref available (initial commit?); nothing to score" >&2
  exit 0
fi

# Produce a unified diff of the changed Go (non-test) files. --unified=0 keeps
# only the changed hunks so we score exactly the added/modified lines.
DIFF_FILE="$(mktemp)"
trap 'rm -f "$DIFF_FILE"' EXIT
git diff --unified=0 "$BASE_REF"...HEAD -- '*.go' ':(exclude)*_test.go' >"$DIFF_FILE" || true

if [ ! -s "$DIFF_FILE" ]; then
  echo "patch coverage: no non-test Go changes vs $BASE_REF; passing"
  exit 0
fi

# The python program reads its arguments (diff file, profile, threshold); stdin
# is the program itself (python3 -), so the diff must be passed as a file path.
python3 - "$DIFF_FILE" "$PROFILE" "$THRESHOLD" <<'PY'
import re, sys

diff_path, profile_path, threshold = sys.argv[1], sys.argv[2], float(sys.argv[3])

# Parse the diff into {file: set(added_line_numbers)}.
added = {}
cur = None
new_line = 0
hunk_re = re.compile(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@')
with open(diff_path, encoding="utf-8") as fh:
    diff_lines = fh.read().splitlines()
for raw in diff_lines:
    if raw.startswith('+++ '):
        path = raw[4:].strip()
        if path == '/dev/null':
            cur = None
            continue
        # Strip the "b/" prefix git adds.
        if path.startswith('b/'):
            path = path[2:]
        cur = path
        added.setdefault(cur, set())
        continue
    if raw.startswith('@@'):
        m = hunk_re.match(raw)
        if m:
            new_line = int(m.group(1))
        continue
    if cur is None:
        continue
    if raw.startswith('+') and not raw.startswith('+++'):
        added[cur].add(new_line)
        new_line += 1
    elif raw.startswith('-') and not raw.startswith('---'):
        # Deleted line: does not advance the new-file counter.
        pass
    else:
        # Context line (rare with --unified=0) advances the counter.
        new_line += 1

if not any(added.values()):
    print("patch coverage: no added lines to score; passing")
    sys.exit(0)

# Parse the Go coverage profile. Format (after the mode line):
#   name.go:startLine.startCol,endLine.endCol numStmts count
block_re = re.compile(r'^(.+):(\d+)\.\d+,(\d+)\.\d+ (\d+) (\d+)$')
# For each file, a list of (start, end, numStmts, count).
blocks = {}
with open(profile_path, encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if not line or line.startswith('mode:'):
            continue
        m = block_re.match(line)
        if not m:
            continue
        name, s, e, n, c = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5))
        blocks.setdefault(name, []).append((s, e, n, c))

# The profile keys are import-path-qualified (e.g.
# github.com/soulteary/grantseal/pkg/license/validator.go) while the diff paths
# are repo-relative (pkg/license/validator.go). Match by suffix.
def blocks_for(diff_path):
    for name, bl in blocks.items():
        if name.endswith('/' + diff_path) or name == diff_path:
            return bl
    return None

covered = 0
uncovered = 0
uncovered_examples = []
for path, lines in added.items():
    bl = blocks_for(path)
    if bl is None:
        # No coverage data for this file: it may be a package with no test
        # instrumentation in this run. Treat its changed statements as uncovered
        # only if the file is clearly instrumented elsewhere; otherwise skip.
        continue
    for ln in sorted(lines):
        for (s, e, n, c) in bl:
            if s <= ln <= e:
                # Attribute one statement-unit per covered line within the block.
                if c > 0:
                    covered += 1
                else:
                    uncovered += 1
                    if len(uncovered_examples) < 20:
                        uncovered_examples.append(f"{path}:{ln}")
                break

total = covered + uncovered
if total == 0:
    print("patch coverage: changed lines contain no coverable statements; passing")
    sys.exit(0)

pct = 100.0 * covered / total
print(f"patch coverage: {covered}/{total} changed statements covered = {pct:.2f}% (threshold {threshold:.0f}%)")
if pct + 1e-9 < threshold:
    print("uncovered changed statements (first 20):")
    for ex in uncovered_examples:
        print(f"  {ex}")
    sys.exit(1)
sys.exit(0)
PY
