#!/usr/bin/env bash
set -euo pipefail

CASE_DIR="${1:-tests/inner_sumcheck_spartan}"
PROFILE="${2:-m61}"
HEAD_LEN="${3:-8}"

cargo run --release --bin profile_e2e_explain -- "$CASE_DIR" "$PROFILE" "$HEAD_LEN"
