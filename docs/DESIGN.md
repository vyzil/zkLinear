# Design

`zkLinear` is a codebase for researching and implementing a Spartan2-like + Brakedown-like PCS stack.
In the current codebase, the primary verification path is `nizk::spartan_brakedown` via `verify_public` and `verify_with_compiled`.

## Core Principles
- Minimize the Proof/Public boundary:
  - `proof` contains only canonical sumcheck messages and PCS openings.
  - `public` contains only shape/digest/profile information.
- Separate metadata:
  - `reference_profile` and `context_fingerprint` are stored as sidecar metadata.
  - Accept/reject decisions are based on proof/public core checks plus compiled consistency checks.
- Transcript consistency:
  - outer/inner/PCS challenges follow one transcript-domain contract.

## Verification Boundaries
- `verify_public(proof, public)`:
  - verifies compact sumcheck transitions and PCS claimed evaluation from public inputs only.
- `verify_with_compiled(compiled, proof, public)`:
  - runs `verify_public` and also checks compiled/public/proof consistency for shape/profile/digest.
- `verify_from_dir_strict(...)`:
  - debug/replay path that reloads the input case.

## PCS Notes
- The encoder is selected by `BrakedownEncoderKind`.
- In the public verification path, opened columns are sampled with `col_open_start`.
- Wire format is defined in `pcs/brakedown/wire.rs`.

## Non-Goals
- This repository is not a fully production-hardened implementation.
- Byte-for-byte equivalence with external references is not a goal.
