# zkLinear Spec v1 (Current)

This document fixes the current verification boundary and transcript contract of the codebase.

## 1. Transcript
- engine: `merlin`
- domain: `zklinear/v1/spartan-brakedown`
- NIZK label: `zklinear/v1/spartan-brakedown/nizk`

## 2. Canonical Sumcheck Messages
- outer round: prover sends `g(0), g(2), g(3)` to verifier
- inner round: prover sends `h(0), h(1), h(2)` to verifier
- each round challenge is verified by transcript replay

## 3. Public/Proof Boundary

### Included in `proof`
- compact outer/inner trace
- `gamma`
- `verifier_commitment`
- `pcs_proof_joint_eval_at_r`

### Included in `public`
- `rows`, `cols`
- `case_digest`
- `field_profile`

### Included in metadata sidecars
- `reference_profile`
- `context_fingerprint`

Metadata is for observability/operations and is not a required input for verification acceptance.

## 4. Verify APIs
- `verify_public(proof, public)`:
  - public-boundary verification
  - sumcheck transition checks + PCS claimed-evaluation check
- `verify_with_compiled(compiled, proof, public)`:
  - `verify_public` plus compiled/public consistency checks

## 5. PCS Wire Contract
- verifier commitment tag: `ZKVCB001`
- eval proof tag: `ZKPFB002`
- unknown tag/version and trailing bytes are rejected
- field decoding enforces canonical range

## 6. Column Sampling Contract
- opened columns are sampled deterministically from transcript
- sampling range is `[col_open_start, n_cols)`
- enforce `n_open <= n_cols - col_open_start`

## 7. Profile Contract
- default reference profile: `Spartan2Like + LcpcBrakedownLike`
- default field profile: `Mersenne61Ext2`
- production-like preset uses fixed challenge counts:
  - `n_degree_tests = 8`
  - `n_col_opens = 16`

## 8. Scope
- This spec defines the current implementation boundary in this repository.
- It does not claim byte-level equivalence with Spartan2/lcpc references.
