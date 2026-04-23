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
