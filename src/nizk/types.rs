use crate::{
    core::field::Fp,
    pcs::brakedown::types::{BrakedownEvalProof, BrakedownFieldProfile, BrakedownVerifierCommitment},
    protocol::reference::ReferenceProfile,
    sumcheck::{inner::SumcheckTrace, outer::OuterSumcheckTrace},
};

pub const NIZK_BLINDED_LAYOUT_ROWS: usize = 6;

#[derive(Debug, Clone)]
pub struct SpartanBrakedownProof {
    pub outer_trace: OuterSumcheckTrace,
    pub inner_trace: SumcheckTrace,
    pub gamma: Fp,
    // Transcript-bound inner claim carried inside proof (not public input).
    pub claimed_value_unblinded: Fp,
    pub claimed_value: Fp,
    pub blind_eval_1: Fp,
    pub blind_eval_2: Fp,
    pub blind_mix_alpha: Fp,
    pub reference_profile: ReferenceProfile,
    pub verifier_commitment: BrakedownVerifierCommitment,
    pub pcs_proof_main: BrakedownEvalProof,
    pub pcs_proof_blind_1: BrakedownEvalProof,
    pub pcs_proof_blind_2: BrakedownEvalProof,
    pub pcs_proof_joint_eval_at_r: BrakedownEvalProof,
    pub pcs_proof_z_eval_at_r: BrakedownEvalProof,
    pub context_fingerprint: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct SpartanBrakedownPublic {
    pub rows: usize,
    pub cols: usize,
    pub case_digest: [u8; 32],
    pub field_profile: BrakedownFieldProfile,
    // Public claims only (no witness-like evaluation tensors on this boundary).
    // Masking/claim-binding remains research/demo and is not a production ZK construction.
    pub claimed_value_masked: Fp,
    pub reference_profile: ReferenceProfile,
    pub context_fingerprint: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct SpartanBrakedownCompiledCircuit {
    pub rows: usize,
    pub cols: usize,
    pub case_digest: [u8; 32],
    pub field_profile: BrakedownFieldProfile,
    pub reference_profile: ReferenceProfile,
    pub context_fingerprint: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct KernelTimingMs {
    pub k0_input_parse_ms: f64,
    pub k1_spartan_prove_ms: f64,
    pub k2_pcs_prove_ms: f64,
    pub k3_verify_ms: f64,
}

impl KernelTimingMs {
    pub fn total_ms(&self) -> f64 {
        self.k0_input_parse_ms + self.k1_spartan_prove_ms + self.k2_pcs_prove_ms + self.k3_verify_ms
    }

    pub fn pct(&self, v: f64) -> f64 {
        let total = self.total_ms();
        if total <= 0.0 {
            0.0
        } else {
            (v / total) * 100.0
        }
    }
}

#[derive(Debug, Clone)]
pub struct SpartanBrakedownPipelineResult {
    pub proof: SpartanBrakedownProof,
    pub public: SpartanBrakedownPublic,
    pub timings: KernelTimingMs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    // Full replay against case inputs (including z); debug/invariant mode.
    StrictReplay,
    // Proof/public-only path: no witness-like tensors on public boundary.
    // This remains research/demo-level succinct verification.
    Succinct,
}

#[derive(Debug, Clone, Copy)]
pub struct SpartanBrakedownProver {
    pub profile: BrakedownFieldProfile,
}

impl SpartanBrakedownProver {
    pub fn new(profile: BrakedownFieldProfile) -> Self {
        Self { profile }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SpartanBrakedownVerifier {
    pub mode: VerifyMode,
}

impl SpartanBrakedownVerifier {
    pub fn new(mode: VerifyMode) -> Self {
        Self { mode }
    }
}
