#!/usr/bin/env bash
set -euo pipefail

CASE_DIR="${1:-tests/inner_sumcheck_spartan}"
OUT_PREFIX="${2:-profile/out/metrics_m61}"
PROFILE="${3:-m61}"
WARMUP="${4:-1}"
RUNS="${5:-10}"

mkdir -p "$(dirname "$OUT_PREFIX")"

cargo run --release --bin metrics_runner -- \
  "$CASE_DIR" "$OUT_PREFIX" "$PROFILE" "$WARMUP" "$RUNS"

echo "wrote: ${OUT_PREFIX}.json"
echo "wrote: ${OUT_PREFIX}.csv"
