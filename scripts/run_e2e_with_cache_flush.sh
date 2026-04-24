#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   scripts/run_e2e_with_cache_flush.sh [case_dir] [out_dir] [profile]
#   scripts/run_e2e_with_cache_flush.sh --k <k> [out_dir] [profile]
#
# Example:
#   scripts/run_e2e_with_cache_flush.sh tests/inner_sumcheck_spartan /tmp/zklinear_e2e m61
#   scripts/run_e2e_with_cache_flush.sh --k 17 /tmp/zklinear_run_k17 m61

CASE_DIR_DEFAULT="tests/inner_sumcheck_spartan"
OUT_DIR_DEFAULT="/tmp/zklinear_e2e"
PROFILE_DEFAULT="m61"

CASE_DIR=""
OUT_DIR=""
PROFILE=""
K=""

if [[ "${1:-}" == "--k" ]]; then
  if [[ -z "${2:-}" ]]; then
    echo "usage: $0 --k <k> [out_dir] [profile]" >&2
    exit 1
  fi
  K="${2}"
  OUT_DIR="${3:-${OUT_DIR_DEFAULT}}"
  PROFILE="${4:-${PROFILE_DEFAULT}}"
  CASE_DIR="tests/generated_cases/circom_repeat_2pow${K}/case"
else
  CASE_DIR="${1:-${CASE_DIR_DEFAULT}}"
  OUT_DIR="${2:-${OUT_DIR_DEFAULT}}"
  PROFILE="${3:-${PROFILE_DEFAULT}}"
fi

COMPILED_JSON="${OUT_DIR}/compiled.json"
PROOF_JSON="${OUT_DIR}/proof.json"
PUBLIC_JSON="${OUT_DIR}/public.json"

now_ms() {
  date +%s%3N
}

elapsed_ms() {
  local start_ms="$1"
  local end_ms="$2"
  echo $((end_ms - start_ms))
}

flush_caches() {
  echo "[cache] sync"
  sync

  if [[ -w /proc/sys/vm/drop_caches ]]; then
    echo "[cache] dropping page cache via /proc/sys/vm/drop_caches"
    echo 3 > /proc/sys/vm/drop_caches
    return 0
  fi

  if command -v sudo >/dev/null 2>&1; then
    echo "[cache] trying sudo -n drop_caches"
    if sudo -n sh -c 'sync; echo 3 > /proc/sys/vm/drop_caches' 2>/dev/null; then
      return 0
    fi
  fi

  echo "[cache] warning: drop_caches unavailable (need root). only sync applied."
}

mkdir -p "${OUT_DIR}"

if [[ -n "${K}" && ! -f "${CASE_DIR}/_A.data" ]]; then
  if ! command -v circom >/dev/null 2>&1; then
    echo "[error] 'circom' not found in PATH." >&2
    echo "        k-mode case generation needs: circom + snarkjs + node" >&2
    echo "        options:" >&2
    echo "          1) install circom/snarkjs and rerun" >&2
    echo "          2) pre-generate case at: ${CASE_DIR}" >&2
    echo "          3) run without --k using existing case dir" >&2
    exit 1
  fi
  if ! command -v snarkjs >/dev/null 2>&1; then
    echo "[error] 'snarkjs' not found in PATH." >&2
    echo "        install snarkjs (npm i -g snarkjs) and rerun." >&2
    exit 1
  fi
  if ! command -v node >/dev/null 2>&1; then
    echo "[error] 'node' not found in PATH." >&2
    echo "        install Node.js and rerun." >&2
    exit 1
  fi
  echo "[case] missing generated case for k=${K}; generating via circom_repeat_casegen"
  cargo run --quiet --bin circom_repeat_casegen -- "${K}"
fi

echo "[build] cargo build --bin spark_e2e_cli"
cargo build --quiet --bin spark_e2e_cli
CLI="./target/debug/spark_e2e_cli"

echo
echo "=== 1) Compile ==="
t0_compile="$(now_ms)"
"${CLI}" compile "${CASE_DIR}" "${COMPILED_JSON}" "${PROFILE}"
t1_compile="$(now_ms)"
compile_ms="$(elapsed_ms "${t0_compile}" "${t1_compile}")"
echo "[time] compile_wall_ms=${compile_ms}"

echo
echo "--- flush between Compile and Prove ---"
flush_caches

echo
echo "=== 2) Prove ==="
t0_prove="$(now_ms)"
"${CLI}" prove "${COMPILED_JSON}" "${CASE_DIR}" "${PROOF_JSON}" "${PUBLIC_JSON}"
t1_prove="$(now_ms)"
prove_ms="$(elapsed_ms "${t0_prove}" "${t1_prove}")"
echo "[time] prove_wall_ms=${prove_ms}"

echo
echo "--- flush between Prove and Verify ---"
flush_caches

echo
echo "=== 3) Verify ==="
t0_verify="$(now_ms)"
"${CLI}" verify "${COMPILED_JSON}" "${PROOF_JSON}" "${PUBLIC_JSON}"
t1_verify="$(now_ms)"
verify_ms="$(elapsed_ms "${t0_verify}" "${t1_verify}")"
echo "[time] verify_wall_ms=${verify_ms}"

echo
total_ms="$((compile_ms + prove_ms + verify_ms))"
echo "[summary]"
echo "  case_dir:   ${CASE_DIR}"
if [[ -n "${K}" ]]; then
  echo "  constraints: 2^${K}"
fi
echo "  profile:    ${PROFILE}"
echo "  compile_ms: ${compile_ms}"
echo "  prove_ms:   ${prove_ms}"
echo "  verify_ms:  ${verify_ms}"
echo "  total_ms:   ${total_ms}"
echo
echo "[done]"
echo "  compiled: ${COMPILED_JSON}"
echo "  proof:    ${PROOF_JSON}"
echo "  public:   ${PUBLIC_JSON}"
