//! Backward-compatible facade for the NIZK pipeline API.
//! New internal layout:
//! - `types.rs`: protocol-visible objects
//! - `flow.rs`: prove/verify orchestration
//! - `report.rs`: human-readable formatting

pub use super::flow::{
    build_pipeline_report_from_dir, build_pipeline_report_from_dir_with_profile, parse_field_profile,
    compile_from_dir, compile_from_dir_with_profile, prove_from_dir, prove_from_dir_with_profile,
    prove_with_compiled_from_dir, verify_from_dir, verify_public, verify_with_compiled,
};
pub use super::types::{
    KernelTimingMs, SpartanBrakedownCompiledCircuit, SpartanBrakedownPipelineResult,
    SpartanBrakedownProof, SpartanBrakedownProver, SpartanBrakedownPublic,
    SpartanBrakedownVerifier, VerifyMode,
};
