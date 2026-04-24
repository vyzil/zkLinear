# Runbook

## Build
```bash
cargo build
```

## Main CLI (Recommended)
```bash
cargo run --bin spark_e2e_cli -- compile tests/inner_sumcheck_spartan /tmp/compiled.json m61
cargo run --bin spark_e2e_cli -- prove /tmp/compiled.json tests/inner_sumcheck_spartan /tmp/proof.json /tmp/public.json
cargo run --bin spark_e2e_cli -- verify /tmp/compiled.json /tmp/proof.json /tmp/public.json
cargo run --bin spark_e2e_cli -- inspect /tmp/proof.json
```

## Profiling / Analysis Workspace
Use scripts in `profile/scripts/` for explain/profiling runs.

```bash
./profile/scripts/explain_e2e.sh
./profile/scripts/profile_matrix.sh
./profile/scripts/profile_metrics.sh
./profile/scripts/profile_perf.sh
```

For options and output paths, see `profile/README.md`.

## Local Case Generation (Circom / ZKIF)
`tests/generated_cases/` is local-only and not tracked in Git.

Generate local cases:
```bash
./scripts/generate_local_cases.sh
./scripts/generate_local_cases.sh 12
```

Circom case generation requires:
- `circom`
- `snarkjs`
- `node`

ZKIF flows are optional and require:
- `cargo ... --features zkif`
- Cargo access to fetch the `zkinterface` dependency

Example:
```bash
cargo run --release --features zkif --bin zkif_import_demo
```

## Metadata Sidecars
During `prove`, the following sidecar files are generated:
- `proof.meta.json`, `proof.meta.wire`
- `public.meta.json`, `public.meta.wire`

Core proof/public files are used for verification decisions.
Meta files are for operations, traceability, and debugging context.

## Minimal Test Set
```bash
cargo test -q
```

The suite is intentionally trimmed to core paths.
Add extra profiling/extended tests separately as needed.
