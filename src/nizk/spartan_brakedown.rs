//! Facade for the NIZK API.
//! New internal layout:
//! - `types.rs`: protocol-visible objects
//! - `flow.rs`: prove/verify orchestration
//!
//! Verification entrypoints:
//! - `verify_public(proof, public)`: default succinct verifier path
//! - `verify_strict(instance_dir, proof)`: debug/full replay path

pub use super::flow::{
    compile, compile_with_profile, parse_field_profile, prove, prove_with_compiled,
    prove_with_profile, verify_public, verify_strict, verify_with_compiled,
};
pub use super::meta::{SpartanBrakedownProofMeta, SpartanBrakedownPublicMeta};
pub use super::metrics::{
    collect_nizk_metrics, mean as metrics_mean, stddev as metrics_stddev, NizkMeasuredRun,
    NizkMetricsReport,
};
pub use super::types::{
    KernelTimingMs, NizkInnerRound, NizkInnerTrace, NizkJointChallenges, NizkOuterRound,
    NizkOuterTrace, SpartanBrakedownCompiledCircuit, SpartanBrakedownPipelineResult,
    SpartanBrakedownProof, SpartanBrakedownProver, SpartanBrakedownPublic,
    SpartanBrakedownVerifier, VerifyMode, NIZK_BLINDED_LAYOUT_ROWS,
};
