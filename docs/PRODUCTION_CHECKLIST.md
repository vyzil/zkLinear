# Production Upgrade Checklist (Prioritized)

This checklist describes what remains after current dual-reference reconciliation.

## P0 (Must-have correctness/security boundary)

- [x] Explicit verifier boundary: `verify(..., claimed_value, ...) -> Result<()>`
- [x] Negative tests for wrong claimed value / tampered proof / tampered root
- [x] Transcript-bound reference profile and metadata checks
- [ ] Freeze transcript spec and domain-separation labels as versioned constants
- [ ] Add cross-implementation transcript test vectors

## P1 (Protocol fidelity to references)

- [x] Dual reference profile added (Spartan2-like + lcpc-brakedown-like)
- [ ] Full Spartan2 message-level parity audit (round objects, challenge order, public inputs)
- [ ] Full lcpc/brakedown parameter parity audit (code parameters, sampling rules)
- [ ] Deterministic compatibility tests against selected reference snapshots

## P2 (PCS hardening)

- [x] Modular PCS split under `src/pcs/`
- [ ] Finalize encoder spec and remove demo-only branches for production profile
- [ ] Strengthen Merkle/opening validation invariants and malformed-proof rejection coverage
- [ ] Add serialization format and stability tests for commitment/proof payloads

## P3 (Field and arithmetic plan)

- [ ] Replace toy field defaults with chosen production field profile
- [ ] If targeting Mersenne/extension field: formalize arithmetic module + test vectors
- [ ] Add property/fuzz tests for arithmetic and transcript challenge reduction

## P4 (Engineering readiness)

- [ ] Benchmark harness for per-kernel timing and memory
- [ ] CI matrix (stable/nightly, feature flags, deterministic test seeds)
- [ ] Structured logging levels (human report vs machine metrics)
- [ ] API docs for prover/verifier payload boundaries

## Current Reality

`zkLinear` is now a coherent protocol skeleton with modular PCS and stable verification boundary,
but it is still not a production-audited implementation.
