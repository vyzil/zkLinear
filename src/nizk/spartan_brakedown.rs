//! Backward-compatible facade for the NIZK pipeline API.
//! New internal layout:
//! - `types.rs`: protocol-visible objects
//! - `flow.rs`: prove/verify orchestration
//! - `report.rs`: human-readable formatting

pub use super::flow::{
    build_pipeline_report_from_dir, build_pipeline_report_from_dir_with_profile, parse_field_profile,
    prove_from_dir, prove_from_dir_with_profile, verify_from_dir,
};
pub use super::types::{
    KernelTimingMs, SpartanBrakedownPipelineResult, SpartanBrakedownProof, SpartanBrakedownPublic,
};
