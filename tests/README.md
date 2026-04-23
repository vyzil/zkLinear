# Test Layout

Each test area uses a case folder under `tests/<part_name>/`.

Example:
- `tests/inner_sumcheck_naive/`
  - `_A.data`
  - `_y.data`
- `tests/inner_sumcheck_spartan/`
  - `_A.data`
  - `_B.data`
  - `_C.data`
  - `_z.data`

## Recommended Data File Format
Use:
- `size:` for dimensions
- `data:` for values (comma/space separated)

Example:
```text
size: 2,8
data:
3,1,4,1,5,9,2,6,
5,8,9,7,9,3,2,3
```

## Run
```bash
cargo test --test inner_sumcheck_naive -- --nocapture
cargo test --test inner_sumcheck_spartan -- --nocapture
cargo test --test brakedown_pcs -- --nocapture
cargo test --test spartan_brakedown_pipeline -- --nocapture
cargo test --test spartan_brakedown_nizk -- --nocapture
cargo test --test r1cs_mtx_pipeline_smoke -- --nocapture
cargo test --test r1cs_zkif_pipeline_smoke -- --nocapture
```

## Adding a New Part
1. Create `tests/<new_part>/`
2. Add input `.data` files
3. Add `tests/<new_part>/test.rs` that calls API functions from `src/api/`
4. Add a thin integration test shim `tests/<new_part>.rs`:
   `#[path = "<new_part>/test.rs"] mod test;`

Note:
- Some tests are direct integration tests (single-file), while others use the folder + shim pattern.
- Keep test naming explicit (`*_pipeline`, `*_nizk`) for protocol-layer clarity.
- `r1cs_mtx_pipeline_smoke` demonstrates importing sparse Matrix-Market R1CS
  (`A.mtx/B.mtx/C.mtx + z.vec`) into the existing `_A/_B/_C/_z` case path.
- `r1cs_zkif_pipeline_smoke` demonstrates importing a zkInterface workspace
  (`header.zkif/witness.zkif/constraints_*.zkif`) into the same case path.
