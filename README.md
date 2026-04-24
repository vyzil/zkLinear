# zkLinear

A Rust codebase for researching and validating a Spartan2-like + Brakedown-like PCS stack.
The current public verification path is `nizk::spartan_brakedown`.

## Key Points
- Maintains a minimized NIZK proof/public boundary.
- Keeps metadata (`reference_profile`, `context_fingerprint`) in sidecars.
- Provides a compile/prove/verify workflow through `spark_e2e_cli`.
- Provides a dedicated `profile/` workspace for explain/profiling runs.

## Project Structure
- `src/nizk/`: proof/public types and prove/verify boundaries
- `src/pcs/brakedown/`: PCS (encoding/commit/open/verify/wire)
- `src/sumcheck/`: inner/outer sumcheck
- `src/protocol/`: transcript/spec/shared helpers
- `src/io/`: case and R1CS import
- `src/bin/spark_e2e_cli.rs`: operational CLI entrypoint
- `profile/`: analysis/profiling scripts and output workspace

For details on structure and design:
- `docs/DESIGN.md`
- `docs/STRUCTURE.md`
- `docs/RUNBOOK.md`
- `docs/SPEC_V1.md`

## Quick Start
```bash
cargo run --bin spark_e2e_cli -- compile tests/inner_sumcheck_spartan /tmp/compiled.json m61
cargo run --bin spark_e2e_cli -- prove /tmp/compiled.json tests/inner_sumcheck_spartan /tmp/proof.json /tmp/public.json
cargo run --bin spark_e2e_cli -- verify /tmp/compiled.json /tmp/proof.json /tmp/public.json
```

## Profiling Workspace
```bash
./profile/scripts/explain_e2e.sh
./profile/scripts/profile_matrix.sh
./profile/scripts/profile_metrics.sh
./profile/scripts/profile_perf.sh
```

See `profile/README.md` for arguments and outputs.

## Tests
```bash
cargo test -q
```

The current test suite is intentionally trimmed to core correctness checks
(PCS/NIZK/compiled boundary/shape guard/leakage probe).
