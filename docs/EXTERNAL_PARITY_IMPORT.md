# External Parity Import

This repository can compare local parity snapshots with external reference snapshots.

## Expected files

Place JSON files at:

- `tests/reference_vectors/external/spartan2_case_01.json`
- `tests/reference_vectors/external/lcpc_like_case_01.json`

Current status in this repo:
- `spartan2_case_01.json` is populated for the shared case and parity-checked
- `lcpc_like_case_01.json` compares PCS-boundary must-match fields
  (`n_rows`, `n_per_row`, `n_cols`, `n_degree_tests`, `n_col_opens`,
  `opened_cols`, `p_eval_len`, `p_random_count`)

JSON schema:
- `spartan2_case_01.json` should match `ParitySnapshot` in:
  - `src/parity/reference.rs`
- `lcpc_like_case_01.json` should match `LcpcLikeParitySnapshot` in:
  - `src/parity/lcpc_like.rs`

## Run

```bash
cargo test --test parity_with_external_reference -- --nocapture
```

Reference-repo pin check (fast):
```bash
cargo test --test external_ref_repos external_ref_repo_revisions_match_snapshot -- --nocapture
```

Opt-in external repo execution (slow, ignored by default):
```bash
cargo test --test external_ref_repos -- --ignored --nocapture
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

## Ref repo location

Default external root:
- `../ref` (relative to this repository root)

Override with environment variable:
- `ZKLINEAR_REF_ROOT=/absolute/path/to/ref`

Pinned external revision snapshot:
- `tests/reference_vectors/external/ref_repo_revisions.json`

Update command:
```bash
ZKLINEAR_UPDATE_EXTERNAL_REFS=1 cargo test --test external_ref_repos external_ref_repo_revisions_match_snapshot -- --nocapture
```
