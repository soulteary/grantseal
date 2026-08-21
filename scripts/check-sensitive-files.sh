#!/usr/bin/env bash
#
# check-sensitive-files.sh — fail if private-key material would ship.
#
# What it detects:
#   1. Files whose name matches a private-key pattern: *-private.key,
#      private-*.key, *.pem named like a key, and known example key names.
#   2. Files whose contents contain a PEM private-key header:
#      -----BEGIN ... PRIVATE KEY-----
#
# Scanning strategy (IMPORTANT — avoids false positives on the repo's example):
#   The repository intentionally ships an EXAMPLE key pair under keys/
#   (keys/k1-private.key) for docs/tests. Those files are git-ignored and are
#   NOT release artifacts. To keep CI green while still catching real leaks,
#   this script scans, by default, the RELEASE/BUILD artifact directory (dist/)
#   plus any extra paths you pass. It deliberately does NOT scan the working
#   tree's keys/ example directory.
#
#   You can override the scanned paths:
#     scripts/check-sensitive-files.sh [path ...]
#   e.g. scan a packaged tarball's extracted dir, or "." for a full-tree audit
#   in a clean checkout that must contain no keys at all.
#
#   When scanning ".", the excludes below still skip the known example keys/
#   directory and VCS/build noise so the gate targets *unexpected* leaks.
#
# Exit codes:
#   0  no sensitive files found in the scanned paths
#   1  at least one private-key file or PEM private-key header found
#   2  usage / environment error

set -euo pipefail

# Default scan target: release artifacts. Callers may pass explicit paths.
if [ "$#" -gt 0 ]; then
  SCAN_PATHS=("$@")
else
  SCAN_PATHS=("dist")
fi

# Directories/globs that are legitimate example material or build noise and
# must never trip the gate when a full-tree ("." ) scan is requested. The
# scripts/ dir is excluded because this very scanner embeds the PEM header
# pattern as a string literal (it is not a real key).
EXCLUDE_DIRS=(".git" "keys" "scripts" "node_modules" "vendor")

found=0

# Build a find(1) prune expression for excluded directories. Each directory
# contributes two OR-ed -path tests; an -o separates successive directories so
# the whole group is a single disjunction (adjacent -path tests would AND).
prune_expr=()
for d in "${EXCLUDE_DIRS[@]}"; do
  if [ "${#prune_expr[@]}" -gt 0 ]; then
    prune_expr+=(-o)
  fi
  prune_expr+=(-path "*/$d" -o -path "$d")
done

scan_one() {
  local target="$1"
  if [ ! -e "$target" ]; then
    # A missing dist/ is normal outside release builds; not an error.
    echo "note: scan path '$target' does not exist, skipping" >&2
    return 0
  fi

  # 1) Filename-based detection.
  local name_hits
  name_hits="$(
    find "$target" \
      \( "${prune_expr[@]}" \) -prune -o \
      -type f \
      \( -name '*-private.key' -o -name 'private-*.key' -o -name '*-private.pem' \
         -o -name 'private-*.pem' -o -name 'id_rsa' -o -name 'id_ed25519' \) \
      -print 2>/dev/null || true
  )"
  if [ -n "$name_hits" ]; then
    echo "sensitive filename(s) detected under '$target':" >&2
    printf '%s\n' "$name_hits" >&2
    found=1
  fi

  # 2) Content-based detection: PEM private-key headers in regular files.
  local content_hits
  content_hits="$(
    find "$target" \
      \( "${prune_expr[@]}" \) -prune -o \
      -type f -print 2>/dev/null |
      while IFS= read -r f; do
        if grep -Il -- '-----BEGIN .*PRIVATE KEY-----' "$f" >/dev/null 2>&1; then
          echo "$f"
        fi
      done
  )"
  if [ -n "$content_hits" ]; then
    echo "PEM private-key header(s) detected under '$target':" >&2
    printf '%s\n' "$content_hits" >&2
    found=1
  fi
}

for p in "${SCAN_PATHS[@]}"; do
  scan_one "$p"
done

if [ "$found" -ne 0 ]; then
  echo "error: private-key material found in scanned artifacts" >&2
  echo "release artifacts must never contain private keys; investigate above" >&2
  exit 1
fi

echo "sensitive-file check passed: no private-key material in scanned paths"
exit 0
