# File Structure

## Runtime Modules
- `src/nizk/`
  - real proof/public boundary and verification logic
- `src/pcs/brakedown/`
  - commitment/open/verify, wire codec, encoder, challenge sampling
- `src/sumcheck/`
  - inner/outer sumcheck core
- `src/protocol/`
  - transcript/spec/shared helpers
- `src/io/`
  - case and R1CS import

## Entrypoints
- `src/bin/spark_e2e_cli.rs`
  - compile / prove / verify / inspect
- `src/bin/profile_e2e_explain.rs`
  - verbose E2E flow explanation (data handoff, transcript labels, proof boundary)
- `src/main.rs`
  - developer demo entrypoint

## Profiling Workspace
- `profile/README.md`
  - profiling/explain workflow guide
- `profile/scripts/`
  - explain and benchmark runners
- `profile/out/`
  - generated profile outputs (markdown/json/csv/perf logs)

## Test Scope (kept)
- PCS correctness and serialization
- NIZK prove/verify boundaries
- compiled-boundary consistency
- core shape guard / field profile / transcript checks
- leakage probe (reference-style risk reproduction)

## Excluded from Default Scope
- parity snapshot comparisons
- external reference repository pinning checks
- long-running profiling / metrics document generation tests
