#!/usr/bin/env bash
#
# check-doc-language.sh — ban unverifiable marketing/quality labels in docs.
#
# Rationale:
#   grantseal documentation follows a "证据而非口号 / evidence, not slogans"
#   policy. This gate prevents regressions where hollow quality labels such as
#   "commercial-grade / 商业级 / enterprise-grade / 企业级 / military-grade /
#   bank-grade / production-grade" creep back into Markdown docs.
#
# What is NOT banned:
#   The protocol/edition enum value "enterprise" (see pkg/license/model.go,
#   EditionEnterprise = "enterprise") is a legitimate identifier and MUST keep
#   working. We only ban the *compound quality label* "enterprise-grade" and the
#   Chinese quality label "企业级" — never the bare word "enterprise".
#
# Allowlist:
#   Some documents legitimately mention a banned phrase inside a *negation* or
#   quotation to explain why the project avoids such wording (e.g. SECURITY.md
#   stating it is "not military-grade / 并非绝对安全"). Those lines are exempted
#   via scripts/doc-language-allowlist.txt, which lists "path:substring" pairs.
#   A hit is only reported when the matched line does NOT appear in the
#   allowlist for that file.
#
# Usage:
#   scripts/check-doc-language.sh [root-dir]
#
# Exit codes:
#   0  no banned phrases found (or all hits are allowlisted)
#   1  at least one non-allowlisted banned phrase found
#   2  usage / environment error
#
# Requires ripgrep (rg).

set -euo pipefail

ROOT="${1:-.}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALLOWLIST="$SCRIPT_DIR/doc-language-allowlist.txt"

if ! command -v rg >/dev/null 2>&1; then
  echo "error: ripgrep (rg) is required but not installed" >&2
  exit 2
fi

# Case-insensitive, word-ish matching. The English labels are hyphenated
# compounds so "enterprise" alone never matches. Chinese labels have no word
# boundaries, matched as substrings.
PATTERN='(commercial-grade|enterprise-grade|military-grade|bank-grade|banking-grade|production-grade|商业级|企业级|军工级|银行级)'

# Collect matches as "file:line:content" across Markdown files only.
# rg exits 1 when there are no matches; guard with `|| true` around the capture
# only, then decide status ourselves (we do NOT use `|| true` to hide failures).
matches="$(rg --no-heading --line-number --color never -i -g '*.md' -e "$PATTERN" "$ROOT" || true)"

if [ -z "$matches" ]; then
  echo "doc-language check passed: no banned quality labels found"
  exit 0
fi

# Filter out allowlisted lines. An allowlist entry is "relpath|||substring".
# We normalize the matched file path relative to ROOT for comparison.
violations=0
while IFS= read -r line; do
  [ -z "$line" ] && continue
  file="${line%%:*}"
  rest="${line#*:}"
  content="${rest#*:}"

  allowed=0
  if [ -f "$ALLOWLIST" ]; then
    while IFS= read -r entry; do
      # Skip comments and blank lines in the allowlist.
      case "$entry" in
        ''|'#'*) continue ;;
      esac
      apath="${entry%%|||*}"
      asub="${entry#*|||}"
      # Match when the file path ends with the allowlisted path AND the line
      # content contains the allowlisted substring.
      case "$file" in
        *"$apath")
          case "$content" in
            *"$asub"*) allowed=1; break ;;
          esac
          ;;
      esac
    done <"$ALLOWLIST"
  fi

  if [ "$allowed" -eq 0 ]; then
    echo "banned quality label: $line" >&2
    violations=$((violations + 1))
  fi
done <<<"$matches"

if [ "$violations" -gt 0 ]; then
  echo "error: found $violations non-allowlisted banned quality label(s)" >&2
  echo "add a justified exemption to scripts/doc-language-allowlist.txt if intentional" >&2
  exit 1
fi

echo "doc-language check passed: all hits are allowlisted negations/quotations"
exit 0
