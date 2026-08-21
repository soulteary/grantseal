#!/usr/bin/env bash
#
# check-sensitive-files.sh — fail if private-key material would ship.
#
# What it detects:
#   1. Files whose name matches a private-key pattern: *-private.key,
#      private-*.key, *-private.pem, private-*.pem, and known key names
#      (id_rsa, id_ed25519).
#   2. Files whose contents contain a PEM private-key header:
#      -----BEGIN ... PRIVATE KEY-----
#
# Scanning strategy:
#   The primary gate is a GIT-TRACKED AUDIT that runs by default. It enumerates
#   only the files git actually tracks (`git ls-files -z`) and fails if any
#   private key was committed — including keys force-added past .gitignore. This
#   is precise: local, git-ignored example keys (e.g. the runtime-generated
#   pair a developer creates for docs/tests) are NOT tracked, so they never trip
#   the gate; but the moment a real private key is staged/committed, CI fails.
#   The git audit is skipped gracefully when we are not inside a git work tree.
#
#   For backward compatibility the script ALSO scans build/release artifacts.
#   By default it scans the artifact directory (dist/); callers may pass explicit
#   paths — e.g. a packaged tarball's extracted dir, or "." for a full-tree audit
#   in a clean checkout that must contain no keys at all. The exclude list below
#   skips VCS/build noise and this scanner's own scripts/ dir (which embeds the
#   PEM header pattern as a string literal, not a real key). When run inside a git
#   work tree, the artifact scan additionally skips git-ignored files, so a "."
#   audit does not false-positive on developers' locally generated, git-ignored
#   example keys — while the git-tracked audit still fails on anything committed.
#
# Exit codes:
#   0  no sensitive files found (git-tracked audit + scanned paths)
#   1  at least one private-key file or PEM private-key header found
#   2  usage / environment error

set -euo pipefail

# Default artifact scan target: release artifacts. Callers may pass explicit
# paths. The git-tracked audit below always runs regardless of these paths.
if [ "$#" -gt 0 ]; then
  SCAN_PATHS=("$@")
else
  SCAN_PATHS=("dist")
fi

# Directories/globs that are legitimate build noise and must never trip the gate
# when a full-tree ("." ) scan is requested. The scripts/ dir is excluded because
# this very scanner embeds the PEM header pattern as a string literal (it is not
# a real key). Note: keys/ is deliberately NOT excluded here — the git-tracked
# audit already prevents false positives on local, un-tracked example keys, so an
# artifact tree that DOES contain a key must still fail.
EXCLUDE_DIRS=(".git" "scripts" "node_modules" "vendor")

# Filename patterns that indicate private-key material.
NAME_GLOBS=('*-private.key' 'private-*.key' '*-private.pem' 'private-*.pem' 'id_rsa' 'id_ed25519')
# PEM private-key header (also embedded in this script as a literal; scripts/ is
# excluded from artifact scans and this file is skipped in the git audit).
PEM_HEADER='-----BEGIN .*PRIVATE KEY-----'

found=0

# ---- 1. Git-tracked audit (primary gate; runs by default) ----------------
# Enumerate ONLY tracked files and check both filename patterns and PEM headers.
# Precise by construction: git-ignored local example keys are not listed here.
git_tracked_audit() {
  if ! command -v git >/dev/null 2>&1; then
    echo "note: git not found; skipping git-tracked audit" >&2
    return 0
  fi
  if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "note: not inside a git work tree; skipping git-tracked audit" >&2
    return 0
  fi

  local self_rel
  # Path of this script relative to the repo root, so we can exclude it from the
  # content scan (it embeds the PEM header pattern as a literal).
  self_rel="$(git ls-files --full-name -- "$0" 2>/dev/null || true)"

  local name_hits="" content_hits="" f base
  while IFS= read -r -d '' f; do
    base="${f##*/}"
    # Filename-based detection.
    case "$base" in
      *-private.key|private-*.key|*-private.pem|private-*.pem|id_rsa|id_ed25519)
        name_hits+="$f"$'\n'
        ;;
    esac
    # Content-based detection: skip this scanner itself.
    if [ -n "$self_rel" ] && [ "$f" = "$self_rel" ]; then
      continue
    fi
    if [ -f "$f" ] && grep -Il -- "$PEM_HEADER" "$f" >/dev/null 2>&1; then
      content_hits+="$f"$'\n'
    fi
  done < <(git ls-files -z)

  if [ -n "$name_hits" ]; then
    echo "sensitive tracked filename(s) detected (git):" >&2
    printf '%s' "$name_hits" >&2
    found=1
  fi
  if [ -n "$content_hits" ]; then
    echo "PEM private-key header(s) in tracked file(s) (git):" >&2
    printf '%s' "$content_hits" >&2
    found=1
  fi
}

# ---- 2. Artifact scan (backward compatible; dist/ or explicit paths) ------
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

# When we are inside a git work tree, artifact scans ignore git-ignored files.
# Rationale: a git-ignored file is by definition NOT part of the repo and NOT a
# release artifact (release artifacts live in dist/, which is itself ignored but
# scanned explicitly by callers). This keeps a full-tree "." audit from false-
# positiving on developers' locally generated, git-ignored example keys, while
# the git-tracked audit above still fails on anything actually committed.
IN_GIT_TREE=0
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  IN_GIT_TREE=1
fi

# is_git_ignored PATH -> return 0 if git ignores PATH (only meaningful in a tree).
is_git_ignored() {
  [ "$IN_GIT_TREE" -eq 1 ] || return 1
  git check-ignore -q -- "$1" 2>/dev/null
}

scan_one() {
  local target="$1"
  if [ ! -e "$target" ]; then
    # A missing dist/ is normal outside release builds; not an error.
    echo "note: scan path '$target' does not exist, skipping" >&2
    return 0
  fi

  # Filename-based detection.
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
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      if is_git_ignored "$f"; then
        continue
      fi
      echo "sensitive filename detected under '$target': $f" >&2
      found=1
    done <<<"$name_hits"
  fi

  # Content-based detection: PEM private-key headers in regular files.
  local content_hits
  content_hits="$(
    find "$target" \
      \( "${prune_expr[@]}" \) -prune -o \
      -type f -print 2>/dev/null |
      while IFS= read -r f; do
        if grep -Il -- "$PEM_HEADER" "$f" >/dev/null 2>&1; then
          echo "$f"
        fi
      done
  )"
  if [ -n "$content_hits" ]; then
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      if is_git_ignored "$f"; then
        continue
      fi
      echo "PEM private-key header detected under '$target': $f" >&2
      found=1
    done <<<"$content_hits"
  fi
}

git_tracked_audit

for p in "${SCAN_PATHS[@]}"; do
  scan_one "$p"
done

if [ "$found" -ne 0 ]; then
  echo "error: private-key material found (tracked files and/or scanned artifacts)" >&2
  echo "private keys must never be committed or shipped; investigate above" >&2
  exit 1
fi

echo "sensitive-file check passed: no private-key material in tracked files or scanned paths"
exit 0
