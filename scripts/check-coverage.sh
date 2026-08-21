#!/usr/bin/env bash
#
# check-coverage.sh — enforce a minimum total test-coverage gate.
#
# Usage:
#   scripts/check-coverage.sh <min-percent> [coverage-profile]
#
#   <min-percent>       Required. Minimum acceptable total coverage, e.g. 70
#                       or 70.5. The gate FAILS (non-zero exit) when the measured
#                       total is strictly below this threshold.
#   [coverage-profile]  Optional. Path to a coverage profile produced by
#                       `go test -coverprofile=...`. Defaults to coverage.out.
#                       If the profile does not exist, it is generated with:
#                         go test ./... -covermode=atomic -coverprofile=<profile>
#
# The script parses the `total:` line emitted by `go tool cover -func`, which
# looks like:
#   total:  (statements)   72.4%
# and compares the percentage against the threshold using awk (no bc/python
# dependency, works in minimal CI images).
#
# CI note: run this after building the profile, or let it build the profile
# itself. It only reads the workspace and never writes to tracked files.

set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "error: missing required <min-percent> argument" >&2
  echo "usage: $0 <min-percent> [coverage-profile]" >&2
  exit 2
fi

MIN="$1"
PROFILE="${2:-coverage.out}"

# Validate the threshold is a number (integer or decimal).
if ! printf '%s' "$MIN" | grep -Eq '^[0-9]+(\.[0-9]+)?$'; then
  echo "error: min-percent must be a number, got: $MIN" >&2
  exit 2
fi

# Generate the profile if it is missing so the script is usable standalone.
if [ ! -f "$PROFILE" ]; then
  echo "coverage profile $PROFILE not found; generating..." >&2
  go test ./... -covermode=atomic -coverprofile="$PROFILE"
fi

FUNC_OUTPUT="$(go tool cover -func="$PROFILE")"
TOTAL_LINE="$(printf '%s\n' "$FUNC_OUTPUT" | grep -E '^total:' || true)"

if [ -z "$TOTAL_LINE" ]; then
  echo "error: could not find a 'total:' line in coverage output" >&2
  echo "$FUNC_OUTPUT" >&2
  exit 2
fi

# The last field is the percentage, e.g. "72.4%". Strip the trailing percent.
TOTAL_PCT="$(printf '%s\n' "$TOTAL_LINE" | awk '{gsub(/%/,"",$NF); print $NF}')"

echo "total coverage: ${TOTAL_PCT}% (gate: >= ${MIN}%)"

# Compare with awk to avoid depending on bc. Exit 1 when below threshold.
if awk -v got="$TOTAL_PCT" -v min="$MIN" 'BEGIN { exit (got + 0 < min + 0) ? 0 : 1 }'; then
  echo "error: total coverage ${TOTAL_PCT}% is below the required ${MIN}%" >&2
  exit 1
fi

echo "coverage gate passed"
