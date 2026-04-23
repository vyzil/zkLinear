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

## 6. Serialization in Transcript/Hash Input

- field element encoding: `u64` little-endian
- integer scalar encoding (e.g. round/ncols): `u64` little-endian

## 7. Reference Profile Policy

Default enforced profile:
- protocol: `Spartan2Like`
- pcs: `LcpcBrakedownLike`

Any profile mismatch at verification boundary is rejected.

## 8. Scope Note

This pinning applies to the protocol skeleton and verification boundary in this repository.
It does not claim full production cryptographic equivalence to Spartan2 or lcpc reference code.
