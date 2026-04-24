# NIZK Masking Model (Current)

This note documents the current masking construction used in the `spartan_brakedown` NIZK path.

## Construction

Current masked claim relation:

- `masked_claim = unblinded_claim + blind_eval_1 + alpha_blind * blind_eval_2`

where:
- `blind_eval_1 = <blind_vec_1, z>`
- `blind_eval_2 = <blind_vec_2, z>`
- `blind_vec_1`, `blind_vec_2` are sampled from prover RNG (not transcript-deterministic)
- `alpha_blind` is transcript-derived **after** commitment metadata is bound

Verifier checks:
- transcript replay for `alpha_blind` with commit-then-challenge ordering
- proof-level claim binding:
  - `claimed_unblinded == inner_trace.claim_initial`
  - `claimed_masked = claimed_unblinded + blind_eval_1 + alpha_blind * blind_eval_2`
- algebraic consistency of masked claim relation
- PCS opening for:
  - main tensor (masked claim)
  - blind component #1 (`blind_eval_1`)
  - blind component #2 (`blind_eval_2`)

## Intended Security Effect

Compared with single-blind masking, this adds:
- one extra independent blind component
- transcript-bound random mixing via `alpha_blind`
- stronger resistance to simple one-term cancellation mistakes in the staged flow

## Scope / Non-Claims

This remains a research implementation and does **not** claim:
- full production ZK proof of security
- audited leakage bounds under all side-channel models
- final parity with Spartan2/lcpc production constructions
- full witness-binding guarantees in the succinct (proof+public-only) path

Use this model for protocol skeleton validation and profiling, not as a finalized cryptographic statement.
