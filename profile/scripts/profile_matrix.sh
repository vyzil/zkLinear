#!/usr/bin/env bash
set -euo pipefail

CASE_DIR="${1:-tests/inner_sumcheck_spartan}"
RUNS="${2:-5}"
PROFILES="${3:-toy,m61,gold}"
OUT_MD="${4:-profile/out/profile_matrix.md}"

mkdir -p "$(dirname "$OUT_MD")"

cargo run --release --bin profile_matrix_metrics -- "$CASE_DIR" "$RUNS" "$PROFILES" > "$OUT_MD"

echo "wrote: $OUT_MD"
