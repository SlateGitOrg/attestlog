#!/usr/bin/env bash
# Measures statement coverage of the core library (./pkg/...) across the
# whole test suite and fails below the threshold.
set -euo pipefail
THRESHOLD="${1:-80}"
cd "$(dirname "$0")/.."
go test -count=1 -coverpkg=./pkg/... -coverprofile=coverage.out ./... >/dev/null
TOTAL=$(go tool cover -func=coverage.out | awk '/^total:/ {sub(/%/,"",$3); print $3}')
echo "core coverage (./pkg/..., whole suite): ${TOTAL}% (threshold ${THRESHOLD}%)"
awk -v t="$TOTAL" -v min="$THRESHOLD" 'BEGIN { exit (t + 0 >= min + 0) ? 0 : 1 }' || {
  echo "coverage ${TOTAL}% is below ${THRESHOLD}%" >&2
  exit 1
}
