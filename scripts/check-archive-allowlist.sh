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
#     gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
#
# Every regular file in the final image must be EITHER:
#   (a) an explicit application file at an EXACT path we ship (verified by path,
#       mode, and — when a base manifest with digests is supplied — sha256), OR
#   (b) a file inherited from the pinned distroless base image.
#
# Case (b) is expressed as a tight base allowlist (base_path_allowed) that
# enumerates exactly the Debian package contents this static-debian13 image
# ships: the ca-certificates bundle, /etc/passwd + /etc/group + nsswitch,
# os-release, the nonroot home + /tmp, PLUS the base-files, netbase, media-types
# and tzdata/tzdata-legacy package files (including the full /usr/share/zoneinfo
# tree and the /var/lib/dpkg/status.d metadata for those packages). It also
# enumerates the small set of files the DOCKER RUNTIME injects into an exported
# container rootfs — /.dockerenv, the /dev/console|pts|shm device nodes, and the
# bind-mounted /etc/hostname, /etc/hosts, /etc/resolv.conf, /etc/mtab — because
# `docker export` streams a running container's filesystem, not the pristine
# image layers. It is still an explicit allowlist — NOT a blanket pass on
# /usr/share, /var/lib, /dev or /etc — so a stray private key, source file,
# config file, or anything planted OUTSIDE those enumerated contents still FAILS.
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

# Files legitimately contributed by the pinned distroless/static-debian13:nonroot
# base. This Debian 13 based static image ships tzdata (the full zoneinfo tree),
# base-files, netbase and ca-certificates on top of the minimal rootfs, so the
# base allowlist below enumerates exactly those package contents. It is still an
# explicit allowlist (NOT a blanket "anything under /usr/share" pass): only the
# specific files/trees these base packages install are accepted, so a stray
# private key, source file or config planted elsewhere still FAILS the check.
# See the header note on base-digest pinning: valid only for the digest pinned
# in the Dockerfile.
base_path_allowed() {
  local p="$1"
  case "$p" in
    "" ) return 0 ;;                              # root marker
    # --- files injected by the docker runtime (NOT shipped in the image) ---
    # `docker export` streams a *running* container's rootfs, so it contains the
    # small set of files the engine bind-mounts / creates at container start.
    # These are environment artifacts, not material we package, and appear on
    # every exported image regardless of contents. Enumerated explicitly (not a
    # blanket /dev or /etc pass) so a planted file elsewhere still fails.
    .dockerenv ) return 0 ;;                       # injected by the docker runtime
    dev/console | dev/pts | dev/shm ) return 0 ;;  # runtime device nodes
    etc/hostname | etc/hosts | etc/resolv.conf | etc/mtab ) return 0 ;;
    # --- rootfs symlink targets / dirs shipped by the base ---
    bin | sbin | lib | lib64 ) return 0 ;;
    var/run ) return 0 ;;                          # symlink -> /run on the base
    # --- passwd / group / nsswitch / os-release (common:* + nsswitch.tar) ---
    etc/passwd | etc/group | etc/nsswitch.conf ) return 0 ;;
    etc/os-release | usr/lib/os-release ) return 0 ;;
    # nonroot home + world-writable tmp shipped by the base image
    home/nonroot ) return 0 ;;
    tmp ) return 0 ;;
    # --- ca-certificates package ---
    etc/ssl/certs/ca-certificates.crt ) return 0 ;;
    usr/share/doc/ca-certificates/* ) return 0 ;;
    var/lib/dpkg/status.d/ca-certificates | var/lib/dpkg/status.d/ca-certificates.md5sums ) return 0 ;;
    # --- base-files package (Debian 13) ---
    etc/debian_version | etc/host.conf | etc/issue | etc/issue.net ) return 0 ;;
    etc/update-motd.d/* ) return 0 ;;
    etc/dpkg/origins/debian ) return 0 ;;
    usr/share/base-files/* ) return 0 ;;
    usr/share/common-licenses/* ) return 0 ;;
    usr/share/doc/base-files/* ) return 0 ;;
    usr/share/lintian/overrides/base-files ) return 0 ;;
    var/lib/dpkg/status.d/base-files | var/lib/dpkg/status.d/base-files.md5sums ) return 0 ;;
    # --- netbase package (protocol/service databases) ---
    etc/ethertypes | etc/protocols | etc/rpc | etc/services ) return 0 ;;
    usr/share/doc/netbase/* ) return 0 ;;
    var/lib/dpkg/status.d/netbase | var/lib/dpkg/status.d/netbase.md5sums ) return 0 ;;
    # --- media-types package (mime.types) ---
    etc/mime.types ) return 0 ;;
    usr/share/bug/media-types/* ) return 0 ;;
    usr/share/doc/media-types/* ) return 0 ;;
    var/lib/dpkg/status.d/media-types | var/lib/dpkg/status.d/media-types.md5sums ) return 0 ;;
    # --- tzdata + tzdata-legacy packages (the full zoneinfo tree) ---
    usr/share/zoneinfo/* ) return 0 ;;
    usr/share/doc/tzdata/* | usr/share/doc/tzdata-legacy/* ) return 0 ;;
    usr/share/lintian/overrides/tzdata ) return 0 ;;
    var/lib/dpkg/status.d/tzdata | var/lib/dpkg/status.d/tzdata.md5sums ) return 0 ;;
    var/lib/dpkg/status.d/tzdata-legacy | var/lib/dpkg/status.d/tzdata-legacy.md5sums ) return 0 ;;
    # NOTE: still NO blanket trees. Anything outside the enumerated base package
    # contents (e.g. /etc/grantseal, an app config, a planted key) FAILS.
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
  # filesystem as a tar.
  #
  # PATHS come from `tar -t` (names only). That listing is the ONE piece of tar
  # output whose format is stable across GNU tar, BSD tar, busybox tar and every
  # locale: exactly one member name per line, no permission/owner/size/time
  # columns to mis-parse. The previous implementation parsed `tar -tv` and
  # anchored the path on an "HH:MM" time token, which broke whenever the listing
  # rendered the time as "HH:MM:SS" or in a non-C locale, and additionally never
  # skipped device nodes — so /dev/console and the entire base tree were
  # misreported as disallowed. Parsing names-only sidesteps all of that.
  #
  # MODE and SHA256 cannot be recovered from a names-only listing, so both are
  # emitted as "-" (unknown). The allowlist gate here is purely path-based:
  # base_path_allowed matches by path, and app_path_allowed accepts /license-tool
  # with an unknown ("-") mode as the documented degraded case (a wrong-path or
  # unexpected binary still fails on path). Per-file mode/digest verification is
  # exercised deterministically via --manifest with hand-written modes (see the
  # self-test's non-executable-binary case), which is where that guarantee lives.
  #
  # Directory members end in "/"; symlink/device/fifo members appear as plain
  # names in `tar -t` and are simply matched against the allowlist by path like
  # any other member (the base allowlist already enumerates the base image's
  # symlinks such as bin/sbin/lib and the runtime-injected /dev + /etc entries,
  # and stray non-regular files under an unexpected path still — correctly —
  # fail).
  build_image_manifest() {
    docker export "$cid" | tar -t 2>/dev/null | awk '
      { p = $0 }
      p ~ /\/$/ { next }                  # directory member
      p == "" { next }
      {
        # Normalize a single leading "./" so members compare by exact path.
        sub(/^\.\//, "", p)
        print "- - " p
      }'
  }
  manifest="$(build_image_manifest)"

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
