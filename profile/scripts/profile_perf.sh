#!/usr/bin/env bash
set -euo pipefail

CASE_DIR="${1:-tests/inner_sumcheck_spartan}"
OUT_PREFIX="${2:-profile/out/perf_m61}"
PROFILE="${3:-m61}"
WARMUP="${4:-1}"
RUNS="${5:-10}"
PERF_OUT="${OUT_PREFIX}.perf.txt"

if ! command -v perf >/dev/null 2>&1; then
  echo "error: 'perf' command not found (Linux perf required)"
  exit 1
fi

mkdir -p "$(dirname "$OUT_PREFIX")"

perf stat \
  -e cycles,instructions,cache-references,cache-misses,branches,branch-misses \
  cargo run --release --bin metrics_runner -- \
  "$CASE_DIR" "$OUT_PREFIX" "$PROFILE" "$WARMUP" "$RUNS" \
  2> "$PERF_OUT"

echo "wrote: ${OUT_PREFIX}.json"
echo "wrote: ${OUT_PREFIX}.csv"
echo "wrote: ${PERF_OUT}"
