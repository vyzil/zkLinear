use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    core::field::{Fp, ModulusScope},
    nizk::spartan_brakedown::{
        NizkInnerRound, NizkInnerTrace, NizkJointChallenges, NizkOuterRound, NizkOuterTrace,
        SpartanBrakedownProof, SpartanBrakedownPublic,
    },
    pcs::brakedown::{
        types::BrakedownFieldProfile,
        wire::{
            deserialize_eval_proof, deserialize_verifier_commitment, serialize_eval_proof,
            serialize_verifier_commitment,
        },
    },
};

pub const REFERENCE_COMPAT_FORMAT: &str = "reference_compat_v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceCompatOuterRound {
    pub round: usize,
    pub g_at_0: u64,
    pub g_at_2: u64,
    pub g_at_3: u64,
    pub challenge_r: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceCompatOuterTrace {
    pub claim_initial: u64,
    pub rounds: Vec<ReferenceCompatOuterRound>,
    pub final_value: u64,
    pub final_claim: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceCompatInnerRound {
    pub round: usize,
    pub h_at_0: u64,
    pub h_at_1: u64,
    pub h_at_2: u64,
    pub challenge_r: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceCompatInnerTrace {
    pub claim_initial: u64,
    pub rounds: Vec<ReferenceCompatInnerRound>,
    pub final_f: u64,
    pub final_g: u64,
    pub final_claim: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceCompatJointChallenges {
    pub r_a: u64,
    pub r_b: u64,
    pub r_c: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceCompatProof {
    pub format: String,
    pub outer_trace: ReferenceCompatOuterTrace,
    pub inner_trace: ReferenceCompatInnerTrace,
    pub joint_challenges: ReferenceCompatJointChallenges,
    pub verifier_commitment_hex: String,
    pub pcs_proof_joint_eval_at_r_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceCompatPublic {
    pub format: String,
    pub rows: usize,
    pub cols: usize,
    pub instance_digest_hex: String,
    pub field_profile: String,
}

fn fp_to_u64(v: Fp) -> u64 {
    v.0
}

fn u64_to_fp(v: u64) -> Fp {
    Fp(v)
}

fn digest_to_hex(d: [u8; 32]) -> String {
    hex::encode(d)
}

fn digest_from_hex(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).context("invalid hex digest")?;
    if bytes.len() != 32 {
        bail!("digest must be 32 bytes, got {}", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn encode_reference_compat_proof(p: &SpartanBrakedownProof) -> ReferenceCompatProof {
    ReferenceCompatProof {
        format: REFERENCE_COMPAT_FORMAT.to_string(),
        outer_trace: ReferenceCompatOuterTrace {
            claim_initial: fp_to_u64(p.outer_trace.claim_initial),
            rounds: p
                .outer_trace
                .rounds
                .iter()
                .map(|r| ReferenceCompatOuterRound {
                    round: r.round,
                    g_at_0: fp_to_u64(r.g_at_0),
                    g_at_2: fp_to_u64(r.g_at_2),
                    g_at_3: fp_to_u64(r.g_at_3),
                    challenge_r: fp_to_u64(r.challenge_r),
                })
                .collect(),
            final_value: fp_to_u64(p.outer_trace.final_value),
            final_claim: fp_to_u64(p.outer_trace.final_claim),
        },
        inner_trace: ReferenceCompatInnerTrace {
            claim_initial: fp_to_u64(p.inner_trace.claim_initial),
            rounds: p
                .inner_trace
                .rounds
                .iter()
                .map(|r| ReferenceCompatInnerRound {
                    round: r.round,
                    h_at_0: fp_to_u64(r.h_at_0),
                    h_at_1: fp_to_u64(r.h_at_1),
                    h_at_2: fp_to_u64(r.h_at_2),
                    challenge_r: fp_to_u64(r.challenge_r),
                })
                .collect(),
            final_f: fp_to_u64(p.inner_trace.final_f),
            final_g: fp_to_u64(p.inner_trace.final_g),
            final_claim: fp_to_u64(p.inner_trace.final_claim),
        },
        joint_challenges: ReferenceCompatJointChallenges {
            r_a: fp_to_u64(p.joint_challenges.r_a),
            r_b: fp_to_u64(p.joint_challenges.r_b),
            r_c: fp_to_u64(p.joint_challenges.r_c),
        },
        verifier_commitment_hex: hex::encode(serialize_verifier_commitment(&p.verifier_commitment)),
        pcs_proof_joint_eval_at_r_hex: hex::encode(serialize_eval_proof(
            &p.pcs_proof_joint_eval_at_r,
        )),
    }
}

pub fn decode_reference_compat_proof(p: &ReferenceCompatProof) -> Result<SpartanBrakedownProof> {
    if p.format != REFERENCE_COMPAT_FORMAT {
        return Err(anyhow!(
            "reference_compat proof format mismatch: expected {}, got {}",
            REFERENCE_COMPAT_FORMAT,
            p.format
        ));
    }
    let verifier_commitment = deserialize_verifier_commitment(
        &hex::decode(&p.verifier_commitment_hex).context("bad verifier commitment hex")?,
    )?;
    let _mod_scope = ModulusScope::enter(verifier_commitment.field_profile.base_modulus());
    let pcs_proof_joint_eval_at_r = deserialize_eval_proof(
        &hex::decode(&p.pcs_proof_joint_eval_at_r_hex).context("bad pcs proof hex")?,
    )?;

    Ok(SpartanBrakedownProof {
        outer_trace: NizkOuterTrace {
            claim_initial: u64_to_fp(p.outer_trace.claim_initial),
            rounds: p
                .outer_trace
                .rounds
                .iter()
                .map(|r| NizkOuterRound {
                    round: r.round,
                    g_at_0: u64_to_fp(r.g_at_0),
                    g_at_2: u64_to_fp(r.g_at_2),
                    g_at_3: u64_to_fp(r.g_at_3),
                    challenge_r: u64_to_fp(r.challenge_r),
                })
                .collect(),
            final_value: u64_to_fp(p.outer_trace.final_value),
            final_claim: u64_to_fp(p.outer_trace.final_claim),
        },
        inner_trace: NizkInnerTrace {
            claim_initial: u64_to_fp(p.inner_trace.claim_initial),
            rounds: p
                .inner_trace
                .rounds
                .iter()
                .map(|r| NizkInnerRound {
                    round: r.round,
                    h_at_0: u64_to_fp(r.h_at_0),
                    h_at_1: u64_to_fp(r.h_at_1),
                    h_at_2: u64_to_fp(r.h_at_2),
                    challenge_r: u64_to_fp(r.challenge_r),
                })
                .collect(),
            final_f: u64_to_fp(p.inner_trace.final_f),
            final_g: u64_to_fp(p.inner_trace.final_g),
            final_claim: u64_to_fp(p.inner_trace.final_claim),
        },
        joint_challenges: NizkJointChallenges {
            r_a: u64_to_fp(p.joint_challenges.r_a),
            r_b: u64_to_fp(p.joint_challenges.r_b),
            r_c: u64_to_fp(p.joint_challenges.r_c),
        },
        verifier_commitment,
        pcs_proof_joint_eval_at_r,
    })
}

pub fn encode_reference_compat_public(p: &SpartanBrakedownPublic) -> ReferenceCompatPublic {
    ReferenceCompatPublic {
        format: REFERENCE_COMPAT_FORMAT.to_string(),
        rows: p.rows,
        cols: p.cols,
        instance_digest_hex: digest_to_hex(p.instance_digest),
        field_profile: format!("{:?}", p.field_profile),
    }
}

pub fn decode_reference_compat_public(p: &ReferenceCompatPublic) -> Result<SpartanBrakedownPublic> {
    if p.format != REFERENCE_COMPAT_FORMAT {
        return Err(anyhow!(
            "reference_compat public format mismatch: expected {}, got {}",
            REFERENCE_COMPAT_FORMAT,
            p.format
        ));
    }
    let field_profile = BrakedownFieldProfile::parse(&p.field_profile)
        .ok_or_else(|| anyhow!("bad field profile in reference_compat public"))?;
    Ok(SpartanBrakedownPublic {
        rows: p.rows,
        cols: p.cols,
        instance_digest: digest_from_hex(&p.instance_digest_hex)?,
        field_profile,
    })
}
