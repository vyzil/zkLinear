use std::{path::Path, time::Instant};

use anyhow::Result;
use merlin::Transcript;

use crate::{
    api::spartan_like::build_spartan_like_report_data_from_dir_with_modulus,
    core::{field::{Fp, ModulusScope}},
    pcs::{
        brakedown::{profiles::params_for_field_profile, types::BrakedownFieldProfile, BrakedownPcs},
        traits::PolynomialCommitmentScheme,
    },
    protocol::{
        reference::{append_reference_profile_to_transcript, DUAL_REFERENCE_PROFILE},
        shared::{compute_case_digest, flatten_rows},
        spec_v1::{append_spec_domain, append_u64_le},
    },
};

use super::{
    transcript::append_bridge_public_metadata,
    types::{
        BridgeBuildResult, BridgeProofBundle, BridgeTimingMs, BridgeVerifierQuery,
        BRIDGE_TRANSCRIPT_LABEL,
    },
};

pub fn prove_bridge_from_dir(case_dir: &Path) -> Result<BridgeBuildResult> {
    prove_bridge_from_dir_with_profile(case_dir, BrakedownFieldProfile::Mersenne61Ext2)
}

pub fn prove_bridge_from_dir_with_profile(
    case_dir: &Path,
    profile: BrakedownFieldProfile,
) -> Result<BridgeBuildResult> {
    let _mod_scope = ModulusScope::enter(profile.base_modulus());
    let t0 = Instant::now();
    let data = build_spartan_like_report_data_from_dir_with_modulus(case_dir, profile.base_modulus())?;
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
    let params = params_for_field_profile(data.a_bound.len(), profile);
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
