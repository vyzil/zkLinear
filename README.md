# zkLinear

`zkLinear` is a standalone research workbench for:
- Spartan-style sumcheck flow analysis
- Brakedown-style (linear-code + Merkle opening) execution tracing
- profiling, consistency testing, and future accelerator-oriented experimentation

## Goals
- Exercise and inspect prover sub-phases in software
- Compare runtime/proof-size behavior across schemes
- Validate prove/verify consistency boundaries
- Prepare for future extension-field experiments and hardware acceleration

## Project Structure
- `src/core/`
  - shared field and transcript primitives
- `src/sumcheck/`
  - `inner.rs`: inner-sumcheck core implementation
  - `outer.rs`: outer-sumcheck core used by the Spartan-like test path
- `src/io/`
  - input case parser (`_A.data`, `_B.data`, `_C.data`, `_y.data`, `_z.data`)
- `src/api/`
  - API entrypoints used by tests/binaries
- `src/spartan/`
  - matrix-vector inner-sumcheck orchestration/reporting
- `src/pcs/`
  - `traits.rs`: lightweight PCS trait (`commit/open/verify`)
  - `brakedown/`: modular mini Brakedown-style path
    - `types.rs`: commitment/proof/parameter types
    - `encoding.rs`: linear-code row encoding
    - `merkle.rs`: Merkle hashing/path verification
    - `commit.rs`: commitment + column opening
    - `prove.rs`: prover-side opening proof generation
    - `verify.rs`: verifier-side checks
    - `demo.rs`: human-readable demo trace
- `src/lcpc_trace.rs`
  - backward-compatible wrapper that calls `src/pcs/brakedown/demo.rs`
- `tests/`
  - integration test shims: `tests/inner_sumcheck_naive.rs`, `tests/inner_sumcheck_spartan.rs`, `tests/brakedown_pcs.rs`
  - per-test folders with code+data: `tests/<part>/test.rs` and `tests/<part>/*.data`

## Run
```bash
cargo run
```

## Test
```bash
cargo test -q
cargo test --test inner_sumcheck_naive -- --nocapture
cargo test --test inner_sumcheck_spartan -- --nocapture
cargo test --test brakedown_pcs -- --nocapture
```

## Input Format
Example matrix file:
```text
size: 2,8
data:
3,1,4,1,5,9,2,6,
5,8,9,7,9,3,2,3
```

Example vector file:
```text
size: 8
data:
2,7,1,8,2,8,1,8
```

## Notes
This repository is intentionally modular and inspection-friendly.
It is not intended to be a byte-for-byte production clone of Spartan2/lcpc.
