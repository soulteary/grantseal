#!/usr/bin/env bash
#
# inject-report-environment.sh — merge an `environment` block (commit, generated
# time, Go version, OS/arch) into .github/go-test-report.json.
#
# The third-party test-report Action only writes test/coverage stats, but the
# quality docs (docs/*/quality.md) render the environment of record from the
# same JSON so it cannot drift. This script stamps that environment after the
# report is generated and before it is committed, keeping the JSON the single
# machine-readable source of truth for BOTH coverage and environment.
#
# Usage:
#   scripts/inject-report-environment.sh [path-to-json]
#
# Environment overrides (all optional; sensible defaults are derived):
#   REPORT_COMMIT        commit sha            (default: git rev-parse HEAD)
#   REPORT_GENERATED_AT  RFC3339 UTC timestamp (default: current UTC time)
#   REPORT_GO_VERSION    e.g. go1.26.6         (default: parsed from `go version`)
#   REPORT_OS            e.g. linux            (default: `go env GOOS`)
#   REPORT_ARCH          e.g. amd64            (default: `go env GOARCH`)
#
# Exit codes:
#   0  environment injected
#   2  missing dependency / input

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JSON="${1:-$REPO_ROOT/.github/go-test-report.json}"

if [ ! -f "$JSON" ]; then
  echo "error: report not found: $JSON" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required" >&2
  exit 2
fi

COMMIT="${REPORT_COMMIT:-$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)}"
GENERATED_AT="${REPORT_GENERATED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
GO_VERSION="${REPORT_GO_VERSION:-$(go version 2>/dev/null | awk '{print $3}' || echo unknown)}"
OS="${REPORT_OS:-$(go env GOOS 2>/dev/null || echo unknown)}"
ARCH="${REPORT_ARCH:-$(go env GOARCH 2>/dev/null || echo unknown)}"

COMMIT="$COMMIT" GENERATED_AT="$GENERATED_AT" GO_VERSION="$GO_VERSION" OS="$OS" ARCH="$ARCH" \
python3 - "$JSON" <<'PY'
import json, os, sys

json_path = sys.argv[1]
with open(json_path, encoding="utf-8") as fh:
    data = json.load(fh)

env = {
    "commit": os.environ["COMMIT"],
    "generated_at": os.environ["GENERATED_AT"],
    "go_version": os.environ["GO_VERSION"],
    "os": os.environ["OS"],
    "arch": os.environ["ARCH"],
}

# Rebuild the object with `environment` right after `schema_version` so the
# on-disk key order stays stable across runs (avoids noisy diffs).
out = {}
for k, v in data.items():
    out[k] = v
    if k == "schema_version":
        out["environment"] = env
if "environment" not in out:
    out = {"environment": env, **out}

with open(json_path, "w", encoding="utf-8") as fh:
    json.dump(out, fh, indent=2)
    fh.write("\n")

print(f"injected environment into {os.path.relpath(json_path)}: {env}")
PY
