use std::{path::Path, time::Instant};

use anyhow::{anyhow, Result};
use merlin::Transcript;

use crate::{
    api::spartan_like::{build_spartan_like_report_data_from_dir, SpartanLikeReportData},
    core::field::Fp,
    pcs::{
        brakedown::{
            types::{BrakedownEvalProof, BrakedownParams, BrakedownVerifierCommitment},
            BrakedownPcs,
        },
        traits::PolynomialCommitmentScheme,
    },
    protocol::{
        reference::{
            append_reference_profile_to_transcript, ReferenceProfile, DUAL_REFERENCE_PROFILE,
        },
        spec_v1::{append_fp_le, append_spec_domain, append_u64_le},
        shared::{compute_case_digest, flatten_rows},
    },
    sumcheck::{
        inner::{verify_inner_sumcheck_trace, VerifyTrace},
        outer::{verify_outer_sumcheck_trace, OuterVerifyTrace},
    },
};

pub const BRIDGE_TRANSCRIPT_LABEL: &[u8] = crate::protocol::spec_v1::BRIDGE_TRANSCRIPT_LABEL;

#[derive(Debug, Clone)]
pub struct BridgeProofBundle {
    pub outer_trace: crate::sumcheck::outer::OuterSumcheckTrace,
    pub inner_trace: crate::sumcheck::inner::SumcheckTrace,
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

fn append_bridge_public_metadata(tr: &mut Transcript, query: &BridgeVerifierQuery) {
    tr.append_message(b"case_digest", &query.public_case_digest);
    append_fp_le(tr, b"gamma", query.gamma);
    append_fp_le(tr, b"claimed", query.claimed_value);
}

pub fn prove_bridge_from_dir(case_dir: &Path) -> Result<BridgeBuildResult> {
    let t0 = Instant::now();
    let data = build_spartan_like_report_data_from_dir(case_dir)?;
    let k0 = t0.elapsed().as_secs_f64() * 1000.0;

    let t1 = Instant::now();
    let claimed = data.joint_trace.claim_initial;
    let outer_tensor = vec![Fp::new(1), data.gamma, data.gamma_sq];
    let inner_tensor = data.case.z.clone();
    let case_digest = compute_case_digest(&data.case);
    let query = BridgeVerifierQuery {
        outer_tensor,
        inner_tensor,
        claimed_value: claimed,
        gamma: data.gamma,
        public_case_digest: case_digest,
        reference_profile: DUAL_REFERENCE_PROFILE,
    };
    let k1 = t1.elapsed().as_secs_f64() * 1000.0;

    let t2 = Instant::now();
    let params = BrakedownParams::new(data.a_bound.len());
    let pcs = BrakedownPcs::new(params.clone());
    let coeffs = flatten_rows(&[
        data.a_bound.clone(),
        data.b_bound.clone(),
        data.c_bound.clone(),
    ]);
    let prover_commitment = pcs.commit(&coeffs)?;
    let verifier_commitment = pcs.verifier_commitment(&prover_commitment);

    let mut tr_p = Transcript::new(BRIDGE_TRANSCRIPT_LABEL);
    append_spec_domain(&mut tr_p);
    append_reference_profile_to_transcript(&mut tr_p, &query.reference_profile);
    append_bridge_public_metadata(&mut tr_p, &query);
    tr_p.append_message(b"bridge_opening_label", b"bridge_main_opening");
    tr_p.append_message(b"polycommit", &verifier_commitment.root);
    append_u64_le(&mut tr_p, b"ncols", pcs.encoding.n_cols as u64);
    let pcs_opening_proof = pcs.open(&prover_commitment, &query.outer_tensor, &mut tr_p)?;
    let k2 = t2.elapsed().as_secs_f64() * 1000.0;

    let bundle = BridgeProofBundle {
        outer_trace: data.outer_trace.clone(),
        inner_trace: data.joint_trace.clone(),
        verifier_commitment,
        pcs_opening_proof,
        claimed_evaluation: claimed,
        gamma: data.gamma,
        public_case_digest: case_digest,
        reference_profile: DUAL_REFERENCE_PROFILE,
        pcs_params: params,
    };

    Ok(BridgeBuildResult {
        bundle,
        verifier_query: query,
        spartan_data: data,
        timings: BridgeTimingMs {
            k0_input_parse_ms: k0,
            k1_spartan_ms: k1,
            k2_pcs_ms: k2,
        },
    })
}

pub fn verify_bridge_bundle(
    bundle: &BridgeProofBundle,
    query: &BridgeVerifierQuery,
    tr: &mut Transcript,
) -> Result<BridgeVerifyReport> {
    if query.claimed_value != bundle.claimed_evaluation {
        return Err(anyhow!(
            "claimed value mismatch between query and proof bundle"
        ));
    }
    if query.gamma != bundle.gamma {
        return Err(anyhow!("gamma mismatch between query and proof bundle"));
    }
    if query.public_case_digest != bundle.public_case_digest {
        return Err(anyhow!(
            "public case digest mismatch between query and proof bundle"
        ));
    }
    if query.reference_profile != bundle.reference_profile {
        return Err(anyhow!(
            "reference profile mismatch between query and proof bundle"
        ));
    }
    if bundle.inner_trace.claim_initial != query.claimed_value {
        return Err(anyhow!(
            "inner-sumcheck claim and verifier claimed value mismatch"
        ));
    }
    if query.outer_tensor.len() != 3 {
        return Err(anyhow!(
            "bridge outer tensor must have exactly 3 elements [1,gamma,gamma^2]"
        ));
    }
    if query.outer_tensor[0] != Fp::new(1)
        || query.outer_tensor[1] != query.gamma
        || query.outer_tensor[2] != query.gamma.mul(query.gamma)
    {
        return Err(anyhow!(
            "outer tensor must be protocol-formed as [1, gamma, gamma^2]"
        ));
    }

    let outer_v = verify_outer_sumcheck_trace(&bundle.outer_trace);
    if !outer_v.final_consistent {
        return Err(anyhow!("outer sumcheck verification failed"));
    }

    let inner_v = verify_inner_sumcheck_trace(&bundle.inner_trace);
    if !inner_v.final_consistent {
        return Err(anyhow!("inner sumcheck verification failed"));
    }

    append_spec_domain(tr);
    append_reference_profile_to_transcript(tr, &query.reference_profile);
    append_bridge_public_metadata(tr, query);
    tr.append_message(b"bridge_opening_label", b"bridge_main_opening");
    tr.append_message(b"polycommit", &bundle.verifier_commitment.root);
    append_u64_le(tr, b"ncols", bundle.verifier_commitment.n_cols as u64);

    let pcs = BrakedownPcs::new(bundle.pcs_params.clone());
    pcs.verify(
        &bundle.verifier_commitment,
        &bundle.pcs_opening_proof,
        &query.outer_tensor,
        &query.inner_tensor,
        query.claimed_value,
        tr,
    )?;

    Ok(BridgeVerifyReport {
        outer_verify: outer_v,
        inner_verify: inner_v,
    })
}
