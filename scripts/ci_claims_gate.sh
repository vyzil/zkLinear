#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   scripts/ci_claims_gate.sh [case_dir] [profile] [out_dir]
#
# Purpose:
#   A local CI-like gate to run before sharing performance/security claims.

CASE_DIR="${1:-tests/inner_sumcheck_spartan}"
PROFILE="${2:-m61}"
OUT_DIR="${3:-/tmp/zklinear_claims_gate}"
OUT_PREFIX="${OUT_DIR}/metrics"

echo "[gate] case_dir=${CASE_DIR}"
echo "[gate] profile=${PROFILE}"
echo "[gate] out_dir=${OUT_DIR}"

mkdir -p "${OUT_DIR}"

echo
echo "[1/4] full test suite"
cargo test -q

echo
echo "[2/4] core integration checks"
cargo test -q --test compiler
cargo test -q --test spartan2
cargo test -q --test brakedown
cargo test -q --test e2e
cargo test -q --test leakage

echo
echo "[3/4] metrics runner sanity"
cargo run --quiet --bin metrics_runner -- "${CASE_DIR}" "${OUT_PREFIX}" "${PROFILE}" 0 1

JSON_PATH="${OUT_PREFIX}.json"
CSV_PATH="${OUT_PREFIX}.csv"
if [[ ! -s "${JSON_PATH}" ]]; then
  echo "[gate] missing or empty metrics json: ${JSON_PATH}" >&2
  exit 1
fi
if [[ ! -s "${CSV_PATH}" ]]; then
  echo "[gate] missing or empty metrics csv: ${CSV_PATH}" >&2
  exit 1
fi

echo
echo "[4/4] clippy checks"
cargo clippy -q --all-targets

echo
echo "[gate] PASS"
echo "  metrics_json=${JSON_PATH}"
echo "  metrics_csv=${CSV_PATH}"
