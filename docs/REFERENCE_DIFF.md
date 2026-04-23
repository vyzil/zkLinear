# Spartan2 Interface vs LCPC/Brakedown PCS Interface (Dual Reference)

This note fixes the reference point used in `zkLinear`:
- Upper protocol semantics reference: **Spartan2-like**
- Lower PCS mechanism reference: **lcpc/brakedown-like**

## 1) Layer Responsibility

- Spartan2-like layer (IOP / protocol semantics):
  - R1CS claim construction
  - outer/inner sumcheck message flow
  - transcript challenge schedule
  - verifier-side recomputation and consistency checks
- lcpc/brakedown-like PCS layer:
  - linear-code encoding
  - Merkle commitment over encoded columns
  - open/decommit and verification against root

In this repo, those responsibilities are separated as:
- protocol/sumcheck/orchestration: `src/protocol/`, `src/sumcheck/`, `src/bridge/`, `src/nizk/`
- PCS implementation: `src/pcs/`

## 2) API Boundary Difference (Key)

The main boundary this repo enforces is:
- `verify(commitment, proof, outer_tensor, inner_tensor, claimed_value, transcript) -> Result<()>`

This means verifier API **accepts/rejects an explicit claimed value** instead of returning one.
That matches proof-system semantics better than a "reconstruct-and-return" verify API.

## 3) Transcript Coupling

- Spartan-like challenges are bound to transcript in upper flow.
- PCS query/opening challenges are also transcript-bound in PCS flow.
- `ReferenceProfile` is appended to transcript so prove/verify agree on reference mode:
  - protocol tag: Spartan2-like
  - PCS tag: lcpc-brakedown-like

## 4) What is still intentionally not identical to production Spartan2/lcpc

- field/parameter choices are still research defaults
- encoder implementation is modular and inspectable, not yet an audited production clone
- NIZK path is protocol-shaped but still labeled research/demo in security-hardening terms

## 5) Practical Use

Use dual reference as follows:
1. Validate upper-flow correctness and transcript wiring using Spartan2-like semantics.
2. Swap/tune PCS internals against lcpc/brakedown-style expectations.
3. Keep boundary stable (`claimed_value`-checking verify API) while iterating internals.
