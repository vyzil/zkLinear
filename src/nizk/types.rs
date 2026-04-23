use crate::{
    core::field::Fp,
    pcs::brakedown::types::{BrakedownEvalProof, BrakedownFieldProfile, BrakedownVerifierCommitment},
    protocol::reference::ReferenceProfile,
    sumcheck::{inner::SumcheckTrace, outer::OuterSumcheckTrace},
};

#[derive(Debug, Clone)]
pub struct SpartanBrakedownProof {
    pub outer_trace: OuterSumcheckTrace,
    pub inner_trace: SumcheckTrace,
    pub gamma: Fp,
    pub claimed_value: Fp,
    pub blind_eval_1: Fp,
    pub blind_eval_2: Fp,
    pub blind_mix_alpha: Fp,
    pub reference_profile: ReferenceProfile,
    pub verifier_commitment: BrakedownVerifierCommitment,
    pub pcs_proof_main: BrakedownEvalProof,
    pub pcs_proof_blind_1: BrakedownEvalProof,
    pub pcs_proof_blind_2: BrakedownEvalProof,
}

#[derive(Debug, Clone)]
pub struct SpartanBrakedownPublic {
    pub rows: usize,
    pub cols: usize,
    pub case_digest: [u8; 32],
    pub outer_tensor_main: Vec<Fp>,
    pub outer_tensor_blind_1: Vec<Fp>,
    pub outer_tensor_blind_2: Vec<Fp>,
    pub inner_tensor: Vec<Fp>,
    pub claimed_value_unblinded: Fp,
    pub claimed_value_masked: Fp,
    pub reference_profile: ReferenceProfile,
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
    // Full replay against case inputs; strongest debug/invariant checks.
    StrictReplay,
    // Proof/public-only verification path.
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
