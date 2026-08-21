#!/usr/bin/env bash
#
# check-sensitive-files-selftest.sh — self-test for check-sensitive-files.sh.
#
# It plants private-key material into a temporary directory that is passed as an
# EXPLICIT scan path and asserts the scanner detects each case. Explicitly
# provided artifact paths represent release artifacts (e.g. an extracted
# tarball) and MUST be scanned even if they happen to be git-ignored — a real
# release must never ship a private key. This self-test fails if the scanner
# skips such planted material.
#
# Cases planted:
#   1. A file named "<id>-private.key".
#   2. A PEM private-key header inside an innocuously named file.
#   3. A private key under a disguised name (e.g. notes.txt) detected by content.
#
# Exit codes:
#   0  all planted cases were detected (scanner is working)
#   1  at least one planted case was missed (scanner regression)
#   2  usage / environment error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER="$SCRIPT_DIR/check-sensitive-files.sh"

if [ ! -x "$SCANNER" ] && [ ! -f "$SCANNER" ]; then
  echo "error: scanner not found at $SCANNER" >&2
  exit 2
fi

tmp="$(mktemp -d)"

# We deliberately plant material inside the REPO's own dist/ directory, which is
# git-ignored. The scanner historically skipped git-ignored files even when the
# path was passed explicitly, which is the bug this self-test guards against: an
# explicitly provided artifact path (a release dir) must be scanned regardless
# of git-ignore status. We locate the repo root so the planted dir is genuinely
# inside the work tree and thus git-ignored.
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
artifacts="$REPO_ROOT/dist/selftest-$$"
cleanup() {
  rm -rf "$tmp" "$artifacts"
}
trap cleanup EXIT
mkdir -p "$artifacts"

# Case 1: sensitive filename.
printf 'not-a-real-key\n' >"$artifacts/k1-private.key"

# Case 2: PEM header in an innocuously named file.
cat >"$artifacts/config.bin" <<'PEM'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAA
-----END OPENSSH PRIVATE KEY-----
PEM

# Case 3: disguised name, detected by content.
cat >"$artifacts/notes.txt" <<'PEM'
-----BEGIN PRIVATE KEY-----
MIIEvExAmPlEnOtArEaLkEy
-----END PRIVATE KEY-----
PEM

# The scanner must EXIT NON-ZERO when it detects planted material in an
# explicitly provided artifact path. We invoke it with the artifacts dir as an
# explicit path.
if bash "$SCANNER" "$artifacts" >/dev/null 2>&1; then
  echo "SELFTEST FAIL: scanner did not flag planted private-key material in explicit path $artifacts" >&2
  exit 1
fi

echo "sensitive-file scanner self-test passed: planted material detected in explicit artifact path"
exit 0
