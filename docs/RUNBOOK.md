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
