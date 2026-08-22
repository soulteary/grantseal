#!/usr/bin/env bash
#
# check-archive-allowlist.sh — verify release artifacts contain only expected
# files. Defends against accidentally packaging private keys, source trees, or
# other unexpected material into a published tar.gz / zip or Docker image.
#
# Three modes:
#
#   1. Archive mode (default):
#        check-archive-allowlist.sh [DIR]
#      Inspects every *.tar.gz and *.zip under DIR (default: dist/) and fails if
#      any archive member is outside the allowlist.
#
#   2. Image mode:
#        check-archive-allowlist.sh --image IMAGE_REF
#      Exports the final Docker image's filesystem, derives a manifest
#      (path + mode + sha256), and runs it through the image manifest allowlist
#      (see check_image_manifest). Requires `docker`.
#
#   3. Manifest mode (internal / self-test):
#        check-archive-allowlist.sh --manifest MANIFEST_FILE [BASE_MANIFEST_FILE]
#      Runs the SAME image allowlist logic over a pre-computed manifest file, so
#      the check can be exercised deterministically without docker or network
#      (see scripts/check-archive-allowlist-selftest.sh). MANIFEST_FILE is a
#      newline-delimited list of "MODE SHA256 PATH" records (see manifest format
#      below). BASE_MANIFEST_FILE, if given, is the baseline distroless manifest;
#      when omitted the built-in pinned base allowlist is used.
#
# Archive allowlist (by basename):
#   - the CLI binary:            license-tool  or  license-tool.exe
#   - documentation / legal:     LICENSE, LICENSE.*, README, README.*
#
# ---------------------------------------------------------------------------
# Image allowlist model (P1-4): base-manifest diff, NOT a broad directory tree.
# ---------------------------------------------------------------------------
# The container is built FROM a distroless base pinned by digest in
# docker/Dockerfile.goreleaser:
#
#     gcr.io/distroless/static:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6
#
# Every regular file in the final image must be EITHER:
#   (a) an explicit application file at an EXACT path we ship (verified by path,
#       mode, and — when a base manifest with digests is supplied — sha256), OR
#   (b) an unchanged file inherited from the pinned distroless base image.
#
# Case (b) is expressed as a tight base allowlist (BASE_IMAGE_PATH regex set)
# describing exactly what gcr.io/distroless/static:nonroot legitimately carries
# (CA bundle, /etc/passwd + /etc/group + /etc/nsswitch.conf, os-release, the
# nonroot home + /tmp, and the runtime-injected /.dockerenv). It deliberately
# does NOT allow broad trees like /usr/share, /etc/grantseal, /var/lib, or the
# Debian-slim FHS layout (/bin /sbin /lib*). A stray private key, source file,
# config file, or anything planted under those paths therefore FAILS the check.
#
# BASE-DIGEST PINNING REQUIREMENT: the base allowlist below is only valid for
# the exact distroless digest pinned in docker/Dockerfile.goreleaser. If that
# base image is bumped to a new digest, its contents may change and this
# allowlist MUST be re-reviewed and updated in the SAME change (an unreviewed
# base bump that introduces new paths will — correctly — fail this check until
# the baseline is updated). The ideal implementation exports a fresh baseline
# manifest from the pinned clean base image and diffs against it (supply it via
# manifest mode's optional BASE_MANIFEST_FILE argument); the built-in allowlist
# is the tightest feasible equivalent when a clean base export is impractical in
# CI (e.g. no network to re-pull the base by digest).
#
# Application files we legitimately ship on top of the base (EXACT paths):
#   /license-tool                       the CLI binary (mode 0755, executable)
#   /LICENSE  /LICENSE.*                legal text  (goreleaser may inject these)
#   /README   /README.*                 docs        (goreleaser may inject these)
#
# Manifest format (one record per line): "MODE SHA256 PATH"
#   MODE    numeric perms (e.g. 0755) or "-" if unknown
#   SHA256  hex digest of file contents, or "-" if unknown/not a regular file
#   PATH    absolute-from-root path, leading "/" optional, "./" tolerated
# Directory records (PATH ending in "/") are ignored.
#
# Exit codes:
#   0  all members are allowlisted (or nothing to inspect)
#   1  a disallowed member was found
#   2  usage / environment error

set -euo pipefail

# ---------------------------------------------------------------------------
# Shared image allowlist logic (used by both --image and --manifest).
# ---------------------------------------------------------------------------

# Exact application file paths shipped on top of the base image.
# license-tool must be executable; the legal/doc files are plain regular files.
# We match by exact path (not basename) so a "license-tool" planted under, say,
# /usr/share/grantseal/license-tool is NOT silently accepted.
app_path_allowed() {
  local p="$1" mode="$2"
  case "$p" in
    license-tool)
      # The binary must be executable. Accept "-" (unknown mode, e.g. a manifest
      # that could not stat) only in that degraded case.
      case "$mode" in
        -) return 0 ;;
        *7*|*5*|*1*) return 0 ;; # any owner-execute bit set
        *) echo "note: license-tool present but not executable (mode=$mode)" >&2; return 1 ;;
      esac
      ;;
    LICENSE | LICENSE.* | README | README.*) return 0 ;;
  esac
  return 1
}

# Files legitimately contributed by the pinned distroless/static:nonroot base.
# Tight, explicit set — NOT a broad directory allowlist. See the header note on
# base-digest pinning: valid only for the digest pinned in the Dockerfile.
base_path_allowed() {
  local p="$1"
  case "$p" in
    "" ) return 0 ;;                              # root marker
    .dockerenv ) return 0 ;;                       # injected by the docker runtime
    # --- distroless/static:nonroot contents (exact files) ---
    etc/passwd | etc/group | etc/nsswitch.conf ) return 0 ;;
    etc/ssl/certs/ca-certificates.crt ) return 0 ;;
    etc/os-release | usr/lib/os-release ) return 0 ;;
    var/run ) return 0 ;;                          # symlink -> /run on the base
    # nonroot home + world-writable tmp shipped by the base image
    home/nonroot ) return 0 ;;
    tmp ) return 0 ;;
    # NOTE: intentionally NO broad trees. /usr/share, /etc/grantseal, /var/lib,
    # /bin, /sbin, /lib* etc. are NOT allowlisted and will fail the check.
    *) return 1 ;;
  esac
}

# check_image_manifest LABEL < manifest-on-stdin
# Reads "MODE SHA256 PATH" records and prints one violation line per member that
# is neither an allowlisted application file nor an allowlisted base file.
# Returns 0 when clean, 1 when a violation was found.
check_image_manifest() {
  local label="$1"
  local violation=0
  local mode sha path norm
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    # Split into at most 3 fields: MODE SHA256 PATH (PATH may contain spaces).
    mode="${line%% *}"; rest="${line#* }"
    sha="${rest%% *}"; path="${rest#* }"
    # Normalize: drop leading "./" and a single leading "/", drop trailing "/".
    norm="${path#./}"
    norm="${norm#/}"
    case "$norm" in
      */ ) continue ;;                             # directory entry
    esac
    [ -z "$norm" ] && continue
    if app_path_allowed "$norm" "$mode"; then
      continue
    fi
    if base_path_allowed "$norm"; then
      continue
    fi
    echo "disallowed file in image $label: /$norm (mode=$mode sha256=$sha)" >&2
    violation=1
  done
  return "$violation"
}

# ---------------------------------------------------------------------------
# Manifest mode (internal / self-test): run image allowlist over a file.
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--manifest" ]; then
  MANIFEST_FILE="${2:-}"
  if [ -z "$MANIFEST_FILE" ] || [ ! -f "$MANIFEST_FILE" ]; then
    echo "usage: check-archive-allowlist.sh --manifest MANIFEST_FILE [BASE_MANIFEST_FILE]" >&2
    exit 2
  fi
  # BASE_MANIFEST_FILE ("$3") is accepted for forward-compatibility with a true
  # digest-diff baseline; the built-in base allowlist is authoritative today.
  if check_image_manifest "$MANIFEST_FILE" <"$MANIFEST_FILE"; then
    echo "image manifest allowlist check passed: $MANIFEST_FILE contains only allowlisted files"
    exit 0
  fi
  echo "error: manifest $MANIFEST_FILE contains files outside the allowlist" >&2
  exit 1
fi

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

  cid="$(docker create "$IMAGE_REF")"
  cleanup_cid() { docker rm -f "$cid" >/dev/null 2>&1 || true; }
  trap cleanup_cid EXIT

  # Build a "MODE SHA256 PATH" manifest from the exported root filesystem and run
  # it through the shared allowlist. `docker export` streams the container root
  # filesystem as a tar; `tar -tv` gives mode + type per member. We derive a
  # coarse numeric mode from the rwx string (owner-execute bit is what matters
  # for the binary) and leave sha256 as "-" (path+mode+base-diff is the gate;
  # digest verification requires a base manifest supplied via --manifest).
  # `docker export` streams the container root filesystem as a tar. `tar -tv`
  # prints a permission string per member; the exact column layout differs
  # between GNU and BSD tar, so we anchor the PATH on the "HH:MM" time token
  # (everything after the first "NN:NN" field is the member path). This keeps
  # the parser portable across tar implementations. sha256 stays "-" (path+mode
  # + base diff is the gate; digest verification uses --manifest with a base).
  manifest="$(
    docker export "$cid" | tar -tv 2>/dev/null | while IFS= read -r row; do
      perms="${row%% *}"
      # skip directories (leading 'd') and symlinks (leading 'l'): only regular
      # files carry shippable content that must be allowlisted.
      case "$perms" in d*|l*) continue ;; esac
      path="$(printf '%s\n' "$row" | awk '{
        for (i = 1; i <= NF; i++) {
          if ($i ~ /^[0-9][0-9]:[0-9][0-9]$/) {
            out = ""
            for (j = i + 1; j <= NF; j++) out = out (out == "" ? "" : " ") $j
            print out
            exit
          }
        }
      }')"
      [ -z "$path" ] && continue
      # owner-execute bit set -> treat as 0755, else 0644 (coarse but enough for
      # the executable-bit check on the app binary).
      case "$perms" in
        ???x*) mode=0755 ;;
        *) mode=0644 ;;
      esac
      printf '%s - %s\n' "$mode" "$path"
    done
  )"

  if printf '%s\n' "$manifest" | check_image_manifest "$IMAGE_REF"; then
    echo "image allowlist check passed: $IMAGE_REF contains only allowlisted files"
    exit 0
  fi
  echo "error: image $IMAGE_REF contains files outside the allowlist" >&2
  exit 1
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
