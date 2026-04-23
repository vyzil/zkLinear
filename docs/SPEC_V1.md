# zkLinear Spec v1 (Pinned)

This document pins the protocol-skeleton boundary used for production-oriented iteration.

## 1. Transcript Engine

- Engine: `merlin` (single transcript engine for integrated prove/verify paths)
- Domain separation: `zklinear/v1/spartan-brakedown`

## 2. Domain/Label Constants

- bridge transcript label: `zklinear/v1/spartan-brakedown/bridge`
- nizk transcript label: `zklinear/v1/spartan-brakedown/nizk`
- pcs demo transcript label: `zklinear/v1/spartan-brakedown/pcs-demo`
- outer sumcheck round label: `spartan-outer-sumcheck`
- inner sumcheck round label: `spartan-inner-sumcheck`
- joint inner label: `spartan-inner-joint`

## 3. Round Message Shape

- outer round message: prover sends `g(0), g(2), g(3)`
  - verifier derives `g(1)` from current claim
- inner round message: prover sends `h(0), h(1), h(2)`

## 4. Public Input Binding

Transcript binds:
- circuit/witness public shape and values used by verifier path (`A,B,C,z`, rows, cols)
- reference profile (`Spartan2Like`, `LcpcBrakedownLike`)
- bridge/nizk public metadata (`case_digest`, `gamma`, `claimed_value` as applicable)

## 5. PCS Verify Boundary

Pinned API boundary:
- `verify(commitment, proof, outer_tensor, inner_tensor, claimed_value, transcript) -> Result<()>`

Verifier accepts/rejects caller-provided `claimed_value`.

## 5.1 NIZK Masking Contract

For the full-style NIZK path, the masked claim is transcript-bound as:

- `masked_claim = unblinded_claim + blind_eval_1 + alpha_blind * blind_eval_2`

where:
- `blind_eval_1 = <blind_vec_1, z>`
- `blind_eval_2 = <blind_vec_2, z>`
- `alpha_blind` is sampled from the same transcript

PCS openings are verified for:
- main tensor (masked claim)
- blind tensor #1 (`blind_eval_1`)
- blind tensor #2 (`blind_eval_2`)

## 6. Serialization in Transcript/Hash Input

- field element encoding: `u64` little-endian
- integer scalar encoding (e.g. round/ncols): `u64` little-endian

## 6.1 Brakedown Wire Envelope (Pinned)

Verifier-commitment and eval-proof wire payloads are versioned by fixed 8-byte tags:
- verifier commitment tag: `ZKVCB001`
- eval proof tag: `ZKPFB002`

Compatibility policy:
- unknown tag/version is rejected at decode boundary
- trailing bytes are rejected at decode boundary
- field element decode enforces canonical range: `0 <= x < modulus`
  - encoded `u64` values `>= modulus` are rejected

This repository treats the wire boundary as strict and fail-closed.

## 6.2 Challenge/Query Sampling (Pinned)

Brakedown challenge/query sampling in this repository is transcript-driven and
deterministic:

- degree-test vectors and column-open queries are derived directly from merlin
  challenge bytes
- no external RNG seed injection at verifier boundary
- degree-test vectors are sampled with explicit round binding (`round_idx`)
- column-open query sampler is bound to `(n_cols, n_open)` metadata
- bounded integer sampling uses rejection sampling to reduce modulo bias
- field-element sampling enforces canonical `0 <= x < modulus`

This keeps prover/verifier replay consistent and makes sampling behavior
explicit for profiling and regression tests.

## 7. Reference Profile Policy

Default enforced profile:
- protocol: `Spartan2Like`
- pcs: `LcpcBrakedownLike`

Default runtime field profile in this repository:
- `Mersenne61Ext2` (`BrakedownParams::new(...)`)
- toy profile remains available only through explicit constructors/presets (`new_toy`, `DemoToy`)

Any profile mismatch at verification boundary is rejected.

## 7.1 Brakedown Production-Candidate Parameter Contract

For production-oriented profiling (still non-audited), this repository pins the
following Brakedown parameter shape:

- `field_profile`: non-toy (`Mersenne61Ext2` or `Goldilocks64Ext2`)
- `auto_tune_security`: `true`
- `encoder_kind`: `SpielmanLike`
- `encoder_seed`: `0`
- `spel_layers`: `3`
- `spel_pre_density`: `5`
- `spel_post_density`: `4`
- `spel_base_rs_parity`: `16`

Code-level predicate:
- `BrakedownParams::is_spec_v1_production_candidate() == true`

This contract is intended to keep benchmark/profiling runs comparable and
fail-fast on accidental parameter drift.

Auto-tuned security counts are pinned to:

- `n_degree_tests = ceil(lambda / max(1, flog2(|F|) - floor(log2(n_cols))))`
- `n_col_opens = clamp[1, n_cols]( ceil( -lambda / log2(1 - delta/3) ) )`
  - `delta = rel_distance_hint(encoder_kind)`
  - `rel_distance_hint(SpielmanLike) = 0.040105193951347796`
  - `rel_distance_hint(ToyHybrid) = 0.08`

where `lambda = security_bits`.

## 8. Scope Note

This pinning applies to the protocol skeleton and verification boundary in this repository.
It does not claim full production cryptographic equivalence to Spartan2 or lcpc reference code.
