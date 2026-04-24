#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CIRCOM_K="${1:-10}"

echo "[casegen] generating local zkif cases"
cargo run --release --features zkif --bin zkif_import_demo
cargo run --release --features zkif --bin zkif_zkml_toy_demo

if command -v circom >/dev/null 2>&1 && command -v snarkjs >/dev/null 2>&1 && command -v node >/dev/null 2>&1; then
  echo "[casegen] generating local circom case (2^${CIRCOM_K})"
  cargo run --release --bin circom_repeat_casegen -- "${CIRCOM_K}"
else
  echo "[casegen] circom toolchain not found; skipping circom case generation"
  echo "          required commands: circom, snarkjs, node"
fi

echo "[casegen] done"
