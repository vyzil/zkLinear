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
- `src/field_profiles/`
  - staged field-profile module for migration experiments
  - includes:
    - `Mersenne61` base field
    - `Goldilocks64` base field
    - `Ext2` skeletons for both (`D=2`)
- `src/protocol/`
  - shared protocol helpers used by both `bridge/` and `nizk/`
  - case/transcript binding, row-binding helpers, shared tensor utilities
- `src/sumcheck/`
  - `inner.rs`: inner-sumcheck core implementation
  - `outer.rs`: outer-sumcheck core used by the Spartan-like test path
- `src/io/`
  - input case parser (`_A.data`, `_B.data`, `_C.data`, `_y.data`, `_z.data`)
- `src/api/`
  - API entrypoints used by tests/binaries
- `src/bridge/`
  - protocol-skeleton bridge for Spartan-like + Brakedown-style flow
  - includes:
    - proof bundle type
    - verifier query boundary type
    - top-level bridge verify function
- `src/nizk/`
  - research full-style path with single-transcript flow and transcript-bound masking
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
    - `wire.rs`: explicit LE wire format for verifier commitment / opening proof
    - `demo.rs`: human-readable demo trace
  - staged parameter tuning:
    - `BrakedownParams::new_with_field_profile(...)`
    - auto-tunes `n_degree_tests` and `n_col_opens` from field profile + security bits
    - `BrakedownSecurityPreset` for cleaner preset-driven setup
- `src/lcpc_trace.rs`
  - backward-compatible wrapper that calls `src/pcs/brakedown/demo.rs`
- `tests/`
  - `tests/inner_sumcheck_naive.rs`: naive inner-sumcheck trace from file inputs
  - `tests/inner_sumcheck_spartan.rs`: Spartan-like outer+inner trace
  - `tests/brakedown_pcs.rs`: standalone Brakedown-style PCS checks
  - `tests/spartan_brakedown_pipeline.rs`: staged bridge (protocol-skeleton)
  - `tests/spartan_brakedown_nizk.rs`: research full-style single-transcript path
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
cargo test --test spartan_brakedown_pipeline -- --nocapture
cargo test --test spartan_brakedown_nizk -- --nocapture
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

## Docs
- `docs/SPEC_V1.md`: pinned transcript/message/verify boundary for v1
- `docs/REFERENCE_DIFF.md`: Spartan2-like vs lcpc/brakedown-like dual-reference boundary
- `docs/PRODUCTION_CHECKLIST.md`: prioritized production-upgrade checklist


## Demo Caveats (Important)
- The current Brakedown path is a **research/demo implementation** for inspection and testing.
- The encoder path in `src/pcs/brakedown/encoding.rs` is now **configurable**:
  - `SpielmanLike` (default): SDIG-inspired sparse precode/postcode + base RS-like layer
  - `ToyHybrid`: systematic + RS-like parity + fixed sparse parity (legacy demo mode)
- It is still **not** a full production Brakedown implementation or a drop-in replacement for audited reference code.
- Tensors/challenges in tests are chosen for reproducible protocol tracing, not for production parameterization.
- Use this repo to understand flow and verify invariants; do not treat current parameters/encoding as final cryptographic settings.
- The bridge and NIZK paths are still **protocol skeletons**:
  - useful for phase-by-phase analysis and interface validation
  - not a production-ready Spartan2 integration
- In the NIZK skeleton:
  - outer/inner/PCS use transcript-shaped flow
  - masking uses transcript-bound two-component form:
    - `masked_claim = unblinded_claim + blind_eval_1 + alpha_blind * blind_eval_2`
    - with dedicated PCS openings for main / blind1 / blind2 checks
  - despite stronger masking flow, this path is still research-oriented and not a final audited ZK construction
