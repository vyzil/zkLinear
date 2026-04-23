# External Parity Import

This repository can compare local parity snapshots with external reference snapshots.

## Expected files

Place JSON files at:

- `tests/reference_vectors/external/spartan2_case_01.json`
- `tests/reference_vectors/external/lcpc_case_01.json`

The JSON schema should match `ParitySnapshot` in:
- `src/parity/reference.rs`

## Run

```bash
cargo test --test parity_with_external_reference -- --nocapture
```

Behavior:
- if neither file exists, test prints a note and exits successfully
- if one or both files exist, test compares **must-match** fields only:
  - shape
  - `Az/Bz/Cz`
  - residual
  - outer initial claim
  - outer/inner round counts

Fields intentionally allowed to differ (by transcript schedule) are documented in:
- `docs/PARITY_TRACE_MATRIX.md`
