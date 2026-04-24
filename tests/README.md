# Tests

This directory is organized by runtime behavior categories for
Spartan2-like + Brakedown + Spielman encoding.

## Test Suites
- `compiler.rs`
  - case/shape validation, deterministic compile metadata, profile-driven fingerprint checks
- `spartan2.rs`
  - outer/inner sumcheck unit checks and Spartan-like flow consistency checks
- `brakedown.rs`
  - Spielman encoder behavior, PCS open/verify, challenge sampling contract, wire contract
- `e2e.rs`
  - NIZK public/compiled verification boundaries and CLI boundary lock
- `leakage.rs`
  - leakage probes for current reference-like degree-test exposure

## Naming Convention
- Test IDs are prefixed by suite and sequence number:
  - `compiler_###_*`
  - `spartan2_###_*`
  - `brakedown_###_*`
  - `e2e_###_*`
  - `leakage_###_*`

## Fixture Data
- `tests/inner_sumcheck_spartan/`
  - `_A.data`, `_B.data`, `_C.data`, `_z.data`

## Run
```bash
cargo test -q
```
