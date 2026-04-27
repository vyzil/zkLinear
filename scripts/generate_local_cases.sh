#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CIRCOM_K="${1:-10}"

echo "[instancegen] generating local zkif instances"
cargo run --release --features zkif --bin zkif_import_demo
cargo run --release --features zkif --bin zkif_zkml_toy_demo

if command -v circom >/dev/null 2>&1 && command -v snarkjs >/dev/null 2>&1 && command -v node >/dev/null 2>&1; then
  echo "[instancegen] generating local circom instance (2^${CIRCOM_K})"
  # Keep the legacy binary name for compatibility with existing local scripts.
  cargo run --release --bin circom_repeat_casegen -- "${CIRCOM_K}"
else
  echo "[instancegen] circom toolchain not found; skipping circom instance generation"
  echo "          required commands: circom, snarkjs, node"
fi

echo "[instancegen] done"
