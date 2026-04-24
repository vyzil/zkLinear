//! Backward-compatible facade for the NIZK pipeline API.
//! New internal layout:
//! - `types.rs`: protocol-visible objects
//! - `flow.rs`: prove/verify orchestration
//! - `report.rs`: human-readable formatting
//!
//! Verification entrypoints:
//! - `verify_public(proof, public)`: default succinct verifier path
//! - `verify_from_dir_strict(case_dir, proof)`: debug/full replay path

pub use super::flow::{
    build_pipeline_report_from_dir, build_pipeline_report_from_dir_with_profile, parse_field_profile,
    compile_from_dir, compile_from_dir_with_profile, prove_from_dir, prove_from_dir_with_profile,
    prove_with_compiled_from_dir, verify_from_dir, verify_from_dir_strict, verify_public,
    verify_with_compiled,
};
pub use super::metrics::{collect_nizk_metrics, mean as metrics_mean, stddev as metrics_stddev, NizkMeasuredRun, NizkMetricsReport};
pub use super::meta::{SpartanBrakedownProofMeta, SpartanBrakedownPublicMeta};
pub use super::types::{
    NizkInnerRound, NizkInnerTrace, NizkOuterRound, NizkOuterTrace,
    KernelTimingMs, SpartanBrakedownCompiledCircuit, SpartanBrakedownPipelineResult,
    SpartanBrakedownProof, SpartanBrakedownProver, SpartanBrakedownPublic,
    SpartanBrakedownVerifier, VerifyMode,
    NIZK_BLINDED_LAYOUT_ROWS,
};
