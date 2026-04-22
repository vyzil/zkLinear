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
- `src/spartan/`
  - Spartan orchestration and report formatting
- `src/io/`
  - input case parser (`_A.data`, `_y.data`)
- `src/api/`
  - API entrypoints used by tests/binaries
- `src/lcpc_trace.rs`
  - independent mini Brakedown-style commit/open/verify trace
- `tests/`
  - integration test shims: `tests/inner_sumcheck_naive.rs`, `tests/inner_sumcheck_spartan.rs`
  - per-test folders with code+data: `tests/<part>/test.rs` and `tests/<part>/*.data`

## Run
```bash
cargo run
```

## Data-Driven Test (Inner Sumcheck)
Case folder:
- `tests/inner_sumcheck_naive/`
  - `_A.data`
  - `_y.data`

Run with full logs:
```bash
cargo test --test inner_sumcheck_naive -- --nocapture
```

## Spartan-like Two-Phase Test (A/B/C/z)
Case folder:
- `tests/inner_sumcheck_spartan/`
  - `_A.data`
  - `_B.data`
  - `_C.data`
  - `_z.data`

Run with full logs:
```bash
cargo test --test inner_sumcheck_spartan -- --nocapture
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
