use super::meta::{SpartanBrakedownProofMeta, SpartanBrakedownPublicMeta};
use crate::{
    core::field::Fp,
    pcs::brakedown::types::{
        BrakedownEvalProof, BrakedownFieldProfile, BrakedownVerifierCommitment,
    },
};

pub const NIZK_BLINDED_LAYOUT_ROWS: usize = 1;

#[derive(Debug, Clone)]
pub struct NizkOuterRound {
    pub round: usize,
    pub g_at_0: Fp,
    pub g_at_2: Fp,
    pub g_at_3: Fp,
    pub challenge_r: Fp,
}

#[derive(Debug, Clone)]
pub struct NizkOuterTrace {
    pub claim_initial: Fp,
    pub rounds: Vec<NizkOuterRound>,
    pub final_value: Fp,
    pub final_claim: Fp,
}

#[derive(Debug, Clone)]
pub struct NizkInnerRound {
    pub round: usize,
    pub h_at_0: Fp,
    pub h_at_1: Fp,
    pub h_at_2: Fp,
    pub challenge_r: Fp,
}

#[derive(Debug, Clone)]
pub struct NizkInnerTrace {
    pub claim_initial: Fp,
    pub rounds: Vec<NizkInnerRound>,
    pub final_f: Fp,
    pub final_g: Fp,
    pub final_claim: Fp,
}

#[derive(Debug, Clone)]
pub struct SpartanBrakedownProof {
    // Canonical sumcheck transcript messages only (no folded/intermediate vectors).
    pub outer_trace: NizkOuterTrace,
    pub inner_trace: NizkInnerTrace,
    pub gamma: Fp,
    pub verifier_commitment: BrakedownVerifierCommitment,
    pub pcs_proof_joint_eval_at_r: BrakedownEvalProof,
}

#[derive(Debug, Clone)]
pub struct SpartanBrakedownPublic {
    pub rows: usize,
    pub cols: usize,
    pub case_digest: [u8; 32],
    pub field_profile: BrakedownFieldProfile,
}

#[derive(Debug, Clone)]
pub struct SpartanBrakedownCompiledCircuit {
    pub rows: usize,
    pub cols: usize,
    pub case_digest: [u8; 32],
    pub field_profile: BrakedownFieldProfile,
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
    pub proof_meta: SpartanBrakedownProofMeta,
    pub public_meta: SpartanBrakedownPublicMeta,
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
