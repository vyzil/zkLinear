use crate::{
    api::spartan_like::SpartanLikeReportData,
    core::field::Fp,
    pcs::brakedown::types::{
        BrakedownEvalProof, BrakedownParams, BrakedownVerifierCommitment,
    },
    protocol::reference::ReferenceProfile,
    sumcheck::{
        inner::{SumcheckTrace, VerifyTrace},
        outer::{OuterSumcheckTrace, OuterVerifyTrace},
    },
};

pub const BRIDGE_TRANSCRIPT_LABEL: &[u8] = crate::protocol::spec_v1::BRIDGE_TRANSCRIPT_LABEL;

#[derive(Debug, Clone)]
pub struct BridgeProofBundle {
    pub outer_trace: OuterSumcheckTrace,
    pub inner_trace: SumcheckTrace,
    pub verifier_commitment: BrakedownVerifierCommitment,
    pub pcs_opening_proof: BrakedownEvalProof,
    pub claimed_evaluation: Fp,
    pub gamma: Fp,
    pub public_case_digest: [u8; 32],
    pub reference_profile: ReferenceProfile,
    pub pcs_params: BrakedownParams,
}

#[derive(Debug, Clone)]
pub struct BridgeVerifierQuery {
    pub outer_tensor: Vec<Fp>,
    pub inner_tensor: Vec<Fp>,
    pub claimed_value: Fp,
    pub gamma: Fp,
    pub public_case_digest: [u8; 32],
    pub reference_profile: ReferenceProfile,
}

#[derive(Debug, Clone)]
pub struct BridgeTimingMs {
    pub k0_input_parse_ms: f64,
    pub k1_spartan_ms: f64,
    pub k2_pcs_ms: f64,
}

#[derive(Debug, Clone)]
pub struct BridgeBuildResult {
    pub bundle: BridgeProofBundle,
    pub verifier_query: BridgeVerifierQuery,
    pub spartan_data: SpartanLikeReportData,
    pub timings: BridgeTimingMs,
}

#[derive(Debug, Clone)]
pub struct BridgeVerifyReport {
    pub outer_verify: OuterVerifyTrace,
    pub inner_verify: VerifyTrace,
}
