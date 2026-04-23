# Module Layering Guide

This repository uses a **4-layer split** rather than a strict 3-layer split.

Why 4 layers:
- A pure "core/protocol/app" split is still too coarse for this codebase.
- We need to separate reusable protocol math from orchestration that binds case I/O, transcript domains, and PCS calls.
- We also want report/CLI formatting to stay outside protocol execution paths.

## Layer A: Algebra/Primitives
- `src/core/`
- `src/field_profiles/`
- `src/sumcheck/`
- `src/pcs/brakedown/scalar.rs`

Rules:
- deterministic math only
- no file I/O
- no report/string formatting

## Layer B: Protocol Core
- `src/pcs/traits.rs`
- `src/pcs/brakedown/{types,encoding,merkle,commit,prove,verify,wire,challenges,profiles}.rs`
- `src/protocol/`

Rules:
- protocol-state transforms and proof objects
- verifier boundaries are explicit
- avoid test/demo-specific formatting

## Layer C: Orchestration / Pipelines
- `src/bridge/`
- `src/nizk/spartan_brakedown.rs`
- `src/api/spartan_like/data.rs`
- `src/spartan/data.rs`

Rules:
- build end-to-end flows by composing Layer A+B
- case loading and transcript domain wiring are allowed
- no large report building blocks here

## Layer D: Presentation / Demo
- `src/api/spartan_like/report.rs`
- `src/nizk/report.rs`
- `src/spartan/report.rs`
- `src/pcs/brakedown/demo.rs`
- `src/bin/*`

Rules:
- formatting, logs, demos, CLI UX
- should consume structs from Layer C/B
- should not own core verification logic

## Current Status
- `spartan` split is now physical (`data.rs` + `report.rs`).
- `nizk` report formatting is already split (`report.rs`).
- profile/mapping duplication has been reduced into shared field-profile helpers.

## Remaining Cleanup
- move remaining formatting helpers out of any Layer C module if they reappear
- keep profile/preset parsing centralized under `pcs/brakedown/types.rs` and `profiles.rs`
- avoid introducing `ModulusScope` logic into new Layer B code paths; prefer field-generic code where feasible
