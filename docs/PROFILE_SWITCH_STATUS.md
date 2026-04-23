# Profile Switch Status

This document tracks what is already profile-switchable (`toy`, `m61`, `gold`)
and what is still pending for full production-grade field generalization.

## What Works Now

- End-to-end NIZK path supports profile selection:
  - `prove_from_dir_with_profile(case_dir, profile)`
  - `verify_from_dir(case_dir, proof)` replays with proof-bound profile
- End-to-end bridge path supports profile selection:
  - `prove_bridge_from_dir_with_profile(case_dir, profile)`
  - `verify_bridge_bundle(...)` replays with bundle-bound profile
- Three profiles currently run end-to-end:
  - `ToyF97`
  - `Mersenne61Ext2` (default)
  - `Goldilocks64Ext2`

## What Is Still Not Fully Generalized

- Spartan core arithmetic is still `Fp`-typed (single-limb storage), with profile
  modulus switching via `ModulusScope`.
- `Ext2` profile names are available and exercised as profile contracts, but
  sumcheck/claim objects are not yet represented as native `Ext2` element types
  in the main Spartan path.
- Wire format currently serializes field elements as one `u64` limb.

## Next Technical Step (Exact)

1. Introduce a minimal field trait for Spartan/sumcheck path.
2. Lift `sumcheck::{inner,outer}`, transcript challenge derivation, and shared
   claim helpers to generic field type.
3. Add explicit two-limb wire encoding for `Ext2` values with version tag.
4. Keep current `Fp` path as compatibility mode until generic path is stable.
