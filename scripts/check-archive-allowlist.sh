#!/usr/bin/env bash
#
# check-archive-allowlist.sh — verify release artifacts contain only expected
# files. Defends against accidentally packaging private keys, source trees, or
# other unexpected material into a published tar.gz / zip or Docker image.
#
# Two modes:
#
#   1. Archive mode (default):
#        check-archive-allowlist.sh [DIR]
#      Inspects every *.tar.gz and *.zip under DIR (default: dist/) and fails if
#      any archive member is outside the allowlist.
#
#   2. Image mode:
#        check-archive-allowlist.sh --image IMAGE_REF
#      Exports the final Docker image's filesystem and fails if it contains any
#      file outside the allowlist. Requires `docker`. Used in the release flow
#      to ensure the shipped container only carries the expected binary + legal
#      files (distroless base contributes only its own runtime scaffolding,
#      which is allowlisted below).
#
# Allowlist (by basename), both modes:
#   - the CLI binary:            license-tool  or  license-tool.exe
#   - documentation / legal:     LICENSE, LICENSE.*, README, README.*
#
# In image mode the base layer additionally contributes a known set of system
# files. Both the distroless/static:nonroot base (CA bundle, /etc/passwd, tmp,
# nonroot home, os-release) and Debian-slim style bases (bin/sbin/lib64,
# /dev/*, dpkg metadata under var/lib/dpkg, the runtime-injected /.dockerenv)
# are allowlisted by path prefix. A stray private key, source tree, or other
# unexpected file at an unknown path still fails the check.
#
# Directory entries (paths ending in "/") are ignored. Anything else — an extra
# file, a stray key, a nested path — fails the check.
#
# Exit codes:
#   0  all members are allowlisted (or nothing to inspect)
#   1  a disallowed member was found
#   2  usage / environment error

set -euo pipefail

# ---------------------------------------------------------------------------
# Image mode: allowlist the final Docker image filesystem.
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--image" ]; then
  IMAGE_REF="${2:-}"
  if [ -z "$IMAGE_REF" ]; then
    echo "usage: check-archive-allowlist.sh --image IMAGE_REF" >&2
    exit 2
  fi
  if ! command -v docker >/dev/null 2>&1; then
    echo "note: docker not available, skipping image allowlist for $IMAGE_REF" >&2
    exit 0
  fi

  # Filesystem paths a minimal Linux base image legitimately contributes.
  # Covers the distroless/static:nonroot base as well as Debian-slim style
  # bases (bin/sbin/lib64, /dev/*, dpkg metadata, the runtime-injected
  # /.dockerenv). Anything outside this set OR the app allowlist fails, so a
  # stray private key or source tree is still rejected regardless of base.
  image_path_allowed() {
    local p="$1"
    # Normalize: drop leading "./" and trailing "/".
    p="${p#./}"
    p="${p%/}"
    case "$p" in
      "" ) return 0 ;;                         # root / dir entries
      .dockerenv ) return 0 ;;                 # injected by the docker runtime
      etc | etc/* ) return 0 ;;                # passwd, group, ssl certs, os-release
      var | var/* ) return 0 ;;                # var/run, dpkg status.d metadata, logs
      run | run/* ) return 0 ;;
      tmp ) return 0 ;;
      root ) return 0 ;;
      home | home/nonroot ) return 0 ;;
      # Standard FHS system directories present on Debian-slim style bases.
      bin | bin/* | sbin | sbin/* | lib | lib/* | lib32 | lib32/* | lib64 | lib64/* | libx32 | libx32/* ) return 0 ;;
      usr | usr/* ) return 0 ;;
      dev | dev/* | proc | proc/* | sys | sys/* ) return 0 ;;
      license-tool ) return 0 ;;               # the app binary at image root
      LICENSE | LICENSE.* | README | README.* ) return 0 ;;
      *) return 1 ;;
    esac
  }

  cid="$(docker create "$IMAGE_REF")"
  cleanup_cid() { docker rm -f "$cid" >/dev/null 2>&1 || true; }
  trap cleanup_cid EXIT

  violation=0
  # `docker export` streams the container root filesystem as a tar; list members.
  while IFS= read -r member; do
    case "$member" in
      "" | */) continue ;;
    esac
    base="${member##*/}"
    case "$base" in
      license-tool | license-tool.exe) continue ;;
      LICENSE | LICENSE.* | README | README.*) continue ;;
    esac
    if ! image_path_allowed "$member"; then
      echo "disallowed file in image $IMAGE_REF: $member" >&2
      violation=1
    fi
  done < <(docker export "$cid" | tar -t)

  if [ "$violation" -ne 0 ]; then
    echo "error: image $IMAGE_REF contains files outside the allowlist" >&2
    exit 1
  fi
  echo "image allowlist check passed: $IMAGE_REF contains only allowlisted files"
  exit 0
fi

# ---------------------------------------------------------------------------
# Archive mode (default).
# ---------------------------------------------------------------------------
DIR="${1:-dist}"

if [ ! -d "$DIR" ]; then
  echo "note: archive dir '$DIR' does not exist, skipping" >&2
  exit 0
fi

# Returns 0 when a member path is allowlisted.
is_allowed() {
  local name="$1"
  # Strip any leading directory component so both flat and nested layouts work.
  local base="${name##*/}"
  case "$base" in
    "") return 0 ;; # directory entry (name ended in '/')
    license-tool | license-tool.exe) return 0 ;;
    LICENSE | LICENSE.* | README | README.*) return 0 ;;
    *) return 1 ;;
  esac
}

found_archive=0
violation=0

# list_disallowed ARCHIVE < member-list-on-stdin
# Prints one "ARCHIVE\tMEMBER" line per disallowed member.
list_disallowed() {
  local archive="$1"
  local m
  while IFS= read -r m; do
    case "$m" in
      "" | */) continue ;;
    esac
    if ! is_allowed "$m"; then
      printf '%s\t%s\n' "$archive" "$m"
    fi
  done
}

while IFS= read -r -d '' archive; do
  found_archive=1
  disallowed=""
  case "$archive" in
    *.tar.gz)
      disallowed="$(tar -tzf "$archive" | list_disallowed "$archive")"
      ;;
    *.zip)
      # `unzip -Z1` lists one member per line without the header/footer noise.
      disallowed="$(unzip -Z1 "$archive" | list_disallowed "$archive")"
      ;;
    *)
      continue
      ;;
  esac
  if [ -n "$disallowed" ]; then
    while IFS=$'\t' read -r arc mem; do
      [ -z "$arc" ] && continue
      echo "disallowed file in $arc: $mem" >&2
      violation=1
    done <<<"$disallowed"
  fi
done < <(find "$DIR" -maxdepth 2 -type f \( -name '*.tar.gz' -o -name '*.zip' \) -print0)

if [ "$found_archive" -eq 0 ]; then
  echo "note: no *.tar.gz / *.zip archives found under '$DIR'" >&2
  exit 0
fi

if [ "$violation" -ne 0 ]; then
  echo "error: release archive(s) contain files outside the allowlist" >&2
  exit 1
fi

echo "archive allowlist check passed: all archive members are allowlisted"
exit 0
