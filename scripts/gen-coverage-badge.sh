#!/usr/bin/env bash
#
# gen-coverage-badge.sh — render a static coverage badge SVG.
#
# Usage:
#   scripts/gen-coverage-badge.sh <total-percent> [output-svg]
#
#   <total-percent>  Required. Coverage percentage, e.g. 72.4 (no % sign).
#   [output-svg]     Optional. Output path, default .github/coverage.svg.
#
# The SVG is a self-contained flat "shields"-style badge with no external
# dependencies (pure shell + printf). Color thresholds:
#   >= 80  green, >= 70 yellow-green, >= 50 yellow, >= 30 orange, else red.
#
# This keeps badge generation dependency-free and reproducible in CI. The
# coverage-badge job commits the result to .github/coverage.svg only on pushes
# to the default branch/tag.

set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "error: missing required <total-percent> argument" >&2
  echo "usage: $0 <total-percent> [output-svg]" >&2
  exit 2
fi

PCT="$1"
OUT="${2:-.github/coverage.svg}"

if ! printf '%s' "$PCT" | grep -Eq '^[0-9]+(\.[0-9]+)?$'; then
  echo "error: total-percent must be a number, got: $PCT" >&2
  exit 2
fi

# Pick a color based on the coverage bucket (integer comparison via awk).
color="$(awk -v p="$PCT" 'BEGIN {
  if (p+0 >= 80) print "#4c1";
  else if (p+0 >= 70) print "#a3c51c";
  else if (p+0 >= 50) print "#dfb317";
  else if (p+0 >= 30) print "#fe7d37";
  else print "#e05d44";
}')"

label="coverage"
value="${PCT}%"

# Approximate text widths (px) for the default badge font at 11px.
label_w=62
value_w=$(( ${#value} * 7 + 10 ))
total_w=$(( label_w + value_w ))
label_x=$(( label_w * 10 / 2 ))
value_x=$(( label_w * 10 + value_w * 10 / 2 ))

mkdir -p "$(dirname "$OUT")"

cat >"$OUT" <<SVG
<svg xmlns="http://www.w3.org/2000/svg" width="${total_w}" height="20" role="img" aria-label="${label}: ${value}">
  <title>${label}: ${value}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="${total_w}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${label_w}" height="20" fill="#555"/>
    <rect x="${label_w}" width="${value_w}" height="20" fill="${color}"/>
    <rect width="${total_w}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="110" text-rendering="geometricPrecision">
    <text x="${label_x}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="$(( (label_w - 10) * 10 ))">${label}</text>
    <text x="${label_x}" y="140" transform="scale(.1)" textLength="$(( (label_w - 10) * 10 ))">${label}</text>
    <text x="${value_x}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="$(( (value_w - 10) * 10 ))">${value}</text>
    <text x="${value_x}" y="140" transform="scale(.1)" textLength="$(( (value_w - 10) * 10 ))">${value}</text>
  </g>
</svg>
SVG

echo "wrote coverage badge -> $OUT (${value}, color ${color})"
