#!/usr/bin/env bash
#
# check-archive-allowlist-selftest.sh — self-test for
# check-archive-allowlist.sh (P1-4).
#
# It exercises BOTH modes of the allowlist checker against deliberately planted
# disallowed material and asserts the checker FAILS (non-zero) for each planted
# case, and PASSES for a clean, correctly-shaped artifact. This guards against a
# silently-weakened allowlist that would let a private key, source tree, config
# file, or a file planted under /usr/share, /etc/grantseal, /var/lib slip into a
# published archive or container image.
#
# Archive-mode cases (real tar.gz / zip built on the fly):
#   A0. Clean archive (license-tool + LICENSE + README)      -> PASS
#   A1. Archive containing private.key                       -> FAIL
#   A2. Archive containing source.go                          -> FAIL
#   A3. Archive containing config.json                        -> FAIL
#
# Image-mode cases (synthetic "MODE SHA256 PATH" manifests, no docker needed —
# runs the SAME allowlist logic via --manifest):
#   I0. Clean manifest (static-debian13 base files + runtime-injected
#       dev/console + etc/hostname|hosts|resolv.conf + /license-tool + LICENSE) -> PASS
#   I1. Manifest with /usr/share/grantseal/private.key        -> FAIL
#   I2. Manifest with /etc/grantseal/config.json              -> FAIL
#   I3. Manifest with /var/lib/grantseal/source.go            -> FAIL
#   I4. Manifest with a stray /app/config.json                -> FAIL
#   I5. Manifest with license-tool present but non-executable -> FAIL
#   I6. Manifest planting license-tool at /usr/bin/license-tool
#       (right basename, wrong path)                          -> FAIL
#   I7. Manifest with an unknown /var/lib/dpkg/status.d entry  -> FAIL
#   I8. Manifest with a stray file under an unknown /usr/share -> FAIL
#   I9. Manifest with an unknown /dev node (not the injected set) -> FAIL
#
# Exit codes:
#   0  every planted case failed AND every clean case passed (checker is working)
#   1  a planted case was accepted OR a clean case was rejected (regression)
#   2  usage / environment error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECKER="$SCRIPT_DIR/check-archive-allowlist.sh"

if [ ! -f "$CHECKER" ]; then
  echo "error: checker not found at $CHECKER" >&2
  exit 2
fi

tmp="$(mktemp -d)"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT

fail() { echo "SELFTEST FAIL: $*" >&2; exit 1; }

# assert_pass DESC -- CMD...   : CMD must exit 0
assert_pass() {
  local desc="$1"; shift
  [ "$1" = "--" ] && shift
  if ! "$@" >/dev/null 2>&1; then
    fail "expected PASS but checker failed: $desc"
  fi
}

# assert_fail DESC -- CMD...   : CMD must exit non-zero
assert_fail() {
  local desc="$1"; shift
  [ "$1" = "--" ] && shift
  if "$@" >/dev/null 2>&1; then
    fail "expected FAIL but checker passed: $desc"
  fi
}

# ---------------------------------------------------------------------------
# Archive mode: build real tar.gz / zip archives and check them.
# ---------------------------------------------------------------------------
mk_archive_dir() {
  # mk_archive_dir DIRNAME EXTRA_FILE...  -> creates $tmp/DIRNAME/pkg.tar.gz (and
  # a matching .zip when unzip is present) containing the base allowlisted files
  # plus any EXTRA_FILE relative paths.
  local dirname="$1"; shift
  local d="$tmp/$dirname"
  local stage="$d/stage"
  mkdir -p "$stage"
  printf '#!/bin/sh\necho binary\n' >"$stage/license-tool"
  printf 'Apache-2.0\n' >"$stage/LICENSE"
  printf '# readme\n' >"$stage/README.md"
  local f
  for f in "$@"; do
    mkdir -p "$stage/$(dirname "$f")"
    printf 'planted\n' >"$stage/$f"
  done
  ( cd "$stage" && tar -czf "$d/pkg.tar.gz" . )
  if command -v zip >/dev/null 2>&1; then
    ( cd "$stage" && zip -q -r "$d/pkg.zip" . )
  fi
  echo "$d"
}

# A0: clean archive -> PASS
d="$(mk_archive_dir clean)"
assert_pass "clean archive (license-tool + LICENSE + README)" -- bash "$CHECKER" "$d"

# A1..A3: planted disallowed files -> FAIL
d="$(mk_archive_dir with-key private.key)"
assert_fail "archive containing private.key" -- bash "$CHECKER" "$d"

d="$(mk_archive_dir with-src source.go)"
assert_fail "archive containing source.go" -- bash "$CHECKER" "$d"

d="$(mk_archive_dir with-cfg config.json)"
assert_fail "archive containing config.json" -- bash "$CHECKER" "$d"

# ---------------------------------------------------------------------------
# Image mode: synthetic manifests fed through the shared allowlist logic.
# ---------------------------------------------------------------------------
# A representative clean distroless static-debian13 manifest, matching what
# base_path_allowed() permits, plus the shipped application files. Includes a
# sampling of the tzdata / base-files / netbase / media-types package contents
# so the self-test asserts the widened base allowlist accepts real base files.
clean_base_manifest() {
  cat <<'EOF'
0644 - etc/passwd
0644 - etc/group
0644 - etc/nsswitch.conf
0644 - etc/ssl/certs/ca-certificates.crt
0644 - etc/os-release
0644 - usr/lib/os-release
0755 - home/nonroot
0777 - tmp
0644 - .dockerenv
0755 - dev/console
0644 - etc/hostname
0644 - etc/hosts
0644 - etc/resolv.conf
0644 - etc/debian_version
0644 - etc/protocols
0644 - etc/services
0644 - etc/mime.types
0644 - usr/share/base-files/profile
0644 - usr/share/common-licenses/Apache-2.0
0644 - usr/share/doc/base-files/copyright
0644 - usr/share/doc/netbase/copyright
0644 - usr/share/zoneinfo/Asia/Shanghai
0644 - usr/share/zoneinfo/right/Etc/UTC
0644 - usr/share/lintian/overrides/tzdata
0644 - var/lib/dpkg/status.d/tzdata
0644 - var/lib/dpkg/status.d/base-files.md5sums
EOF
}

mk_manifest() {
  # mk_manifest NAME < body ; body appended to a clean base + app files
  local name="$1"
  local f="$tmp/$name.manifest"
  {
    clean_base_manifest
    echo "0755 - license-tool"
    echo "0644 - LICENSE"
    cat
  } >"$f"
  echo "$f"
}

# I0: clean manifest -> PASS
f="$(printf '' | mk_manifest clean)"
assert_pass "clean image manifest" -- bash "$CHECKER" --manifest "$f"

# I1: private key under /usr/share/grantseal -> FAIL
f="$(printf '0600 - usr/share/grantseal/private.key\n' | mk_manifest usr-share-key)"
assert_fail "manifest with /usr/share/grantseal/private.key" -- bash "$CHECKER" --manifest "$f"

# I2: config under /etc/grantseal -> FAIL
f="$(printf '0644 - etc/grantseal/config.json\n' | mk_manifest etc-grantseal)"
assert_fail "manifest with /etc/grantseal/config.json" -- bash "$CHECKER" --manifest "$f"

# I3: source under /var/lib/grantseal -> FAIL
f="$(printf '0644 - var/lib/grantseal/source.go\n' | mk_manifest var-lib)"
assert_fail "manifest with /var/lib/grantseal/source.go" -- bash "$CHECKER" --manifest "$f"

# I4: stray config at /app -> FAIL
f="$(printf '0644 - app/config.json\n' | mk_manifest app-cfg)"
assert_fail "manifest with stray /app/config.json" -- bash "$CHECKER" --manifest "$f"

# I5: license-tool present but not executable -> FAIL
# (rebuild manifest by hand so the binary line carries a non-exec mode)
f="$tmp/nonexec.manifest"
{
  clean_base_manifest
  echo "0644 - license-tool"
  echo "0644 - LICENSE"
} >"$f"
assert_fail "manifest with non-executable license-tool" -- bash "$CHECKER" --manifest "$f"

# I6: license-tool basename at a wrong path -> FAIL (exact-path allowlist)
f="$(printf '0755 - usr/bin/license-tool\n' | mk_manifest wrong-path-binary)"
assert_fail "manifest with license-tool at /usr/bin (wrong path)" -- bash "$CHECKER" --manifest "$f"

# I7: an UNKNOWN dpkg status.d entry (not one of the pinned base packages) ->
# FAIL. Proves the widened base allowlist enumerates specific package metadata
# rather than blanket-allowing all of /var/lib/dpkg/status.d.
f="$(printf '0644 - var/lib/dpkg/status.d/openssl\n' | mk_manifest unknown-dpkg-pkg)"
assert_fail "manifest with unknown /var/lib/dpkg/status.d/openssl" -- bash "$CHECKER" --manifest "$f"

# I8: a stray file under an UNKNOWN /usr/share subtree -> FAIL. Proves we did not
# blanket-allow /usr/share when widening for base-files/tzdata/etc.
f="$(printf '0644 - usr/share/grantseal/notes.txt\n' | mk_manifest unknown-usr-share)"
assert_fail "manifest with stray /usr/share/grantseal/notes.txt" -- bash "$CHECKER" --manifest "$f"

# I9: an UNKNOWN /dev node -> FAIL. The runtime-injected set (dev/console, plus
# the etc/hostname etc/hosts etc/resolv.conf files docker bind-mounts) is
# enumerated explicitly and lives in the clean base manifest above; this proves
# we did NOT blanket-allow /dev when accepting those runtime artifacts.
f="$(printf '0666 - dev/full\n' | mk_manifest unknown-dev-node)"
assert_fail "manifest with unknown /dev/full node" -- bash "$CHECKER" --manifest "$f"

echo "archive/image allowlist self-test passed: planted material rejected, clean artifacts accepted"
exit 0
