use anyhow::{anyhow, Result};
use merlin::Transcript;

use crate::{
    core::field::{Fp, ModulusScope},
    core::transcript::derive_round_challenge_t,
    pcs::{
        brakedown::{profiles::params_for_field_profile, BrakedownPcs},
    },
    protocol::{
        reference::{append_reference_profile_to_transcript, DUAL_REFERENCE_PROFILE},
        spec_v1::{INNER_SUMCHECK_JOINT_LABEL, OUTER_SUMCHECK_LABEL},
        shared::append_field_profile_to_transcript,
        spec_v1::{append_spec_domain, append_u64_le},
    },
    sumcheck::{
        inner::verify_inner_sumcheck_trace,
        outer::verify_outer_sumcheck_trace,
    },
};

use super::{
    transcript::append_bridge_public_metadata,
    types::{BridgeProofBundle, BridgeVerifierQuery, BridgeVerifyReport},
};

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
    if query.field_profile != bundle.verifier_commitment.field_profile {
        return Err(anyhow!(
            "field profile mismatch between query and proof bundle"
        ));
    }
    if query.rows == 0 || query.cols == 0 || !query.rows.is_power_of_two() || !query.cols.is_power_of_two() {
        return Err(anyhow!(
            "bridge public shape must be non-zero powers of two"
        ));
    }
    if bundle.verifier_commitment.n_per_row != query.cols {
        return Err(anyhow!(
            "bridge verifier commitment width mismatch vs public query"
        ));
    }
    if bundle.verifier_commitment.n_rows != 3 {
        return Err(anyhow!(
            "bridge verifier commitment row count mismatch (expected 3)"
        ));
    }
    if bundle.reference_profile != DUAL_REFERENCE_PROFILE {
        return Err(anyhow!("unsupported reference profile for this bridge flow"));
    }
    let _mod_scope = ModulusScope::enter(query.field_profile.base_modulus());
    if bundle.inner_trace.claim_initial != query.claimed_value {
        return Err(anyhow!(
            "inner-sumcheck claim and verifier claimed value mismatch"
        ));
    }
    if bundle.verifier_commitment.n_per_row == 0 || !bundle.verifier_commitment.n_per_row.is_power_of_two() {
        return Err(anyhow!(
            "bridge verifier commitment n_per_row must be a non-zero power of two"
        ));
    }
    if bundle.inner_trace.rounds.len() != query.cols.trailing_zeros() as usize {
        return Err(anyhow!(
            "bridge inner rounds do not match verifier commitment width"
        ));
    }
    let outer_rounds = bundle.outer_trace.rounds.len();
    if outer_rounds != query.rows.trailing_zeros() as usize {
        return Err(anyhow!(
            "bridge outer rounds do not match public row count"
        ));
    }
    let max_rounds = usize::BITS as usize - 1;
    if outer_rounds > max_rounds {
        return Err(anyhow!(
            "bridge outer round count exceeds machine word capacity"
        ));
    }
    for (i, r) in bundle.outer_trace.rounds.iter().enumerate() {
        if r.round != i {
            return Err(anyhow!("bridge outer round index mismatch at position {}", i));
        }
        let expected_r = derive_round_challenge_t(
            OUTER_SUMCHECK_LABEL,
            r.round,
            r.g_at_0,
            r.g_at_2,
            r.g_at_3,
        );
        if expected_r != r.challenge_r {
            return Err(anyhow!("bridge outer challenge mismatch at round {}", i));
        }
        let expected_fold_len = query
            .rows
            .checked_shr((i + 1) as u32)
            .ok_or_else(|| anyhow!("bridge outer folded-length shift overflow"))?;
        if r.folded_values.len() != expected_fold_len {
            return Err(anyhow!(
                "bridge outer folded vector length mismatch at round {}",
                i
            ));
        }
    }
    for (i, r) in bundle.inner_trace.rounds.iter().enumerate() {
        if r.round != i {
            return Err(anyhow!("bridge inner round index mismatch at position {}", i));
        }
        let expected_r = derive_round_challenge_t(
            INNER_SUMCHECK_JOINT_LABEL,
            r.round,
            r.h_at_0,
            r.h_at_1,
            r.h_at_2,
        );
        if expected_r != r.challenge_r {
            return Err(anyhow!("bridge inner challenge mismatch at round {}", i));
        }
        let expected_fold_len = query.cols >> (i + 1);
        if r.folded_f.len() != expected_fold_len
            || r.folded_g.len() != expected_fold_len
            || r.folded_f.len() != r.folded_g.len()
        {
            return Err(anyhow!(
                "bridge inner folded vector length mismatch at round {}",
                i
            ));
        }
    }
    let outer_v = verify_outer_sumcheck_trace(&bundle.outer_trace);
    if !outer_v.final_consistent {
        return Err(anyhow!("outer sumcheck verification failed"));
    }
    if bundle.outer_trace.final_value != bundle.outer_trace.final_claim {
        return Err(anyhow!("bridge outer final value/claim mismatch"));
    }

    let inner_v = verify_inner_sumcheck_trace(&bundle.inner_trace);
    if !inner_v.final_consistent {
        return Err(anyhow!("inner sumcheck verification failed"));
    }
    if bundle.inner_trace.final_claim
        != bundle.inner_trace.final_f.mul(bundle.inner_trace.final_g)
    {
        return Err(anyhow!("bridge inner final claim mismatch vs final_f*final_g"));
    }

    append_spec_domain(tr);
    append_reference_profile_to_transcript(tr, &query.reference_profile);
    append_field_profile_to_transcript(tr, bundle.verifier_commitment.field_profile);
    append_bridge_public_metadata(tr, query);
    tr.append_message(b"bridge_opening_label", b"bridge_main_opening");
    tr.append_message(b"polycommit", &bundle.verifier_commitment.root);
    append_u64_le(tr, b"ncols", bundle.verifier_commitment.n_cols as u64);

    let expected_params = params_for_field_profile(
        bundle.verifier_commitment.n_per_row,
        bundle.verifier_commitment.field_profile,
    );
    if bundle.verifier_commitment.field_profile != bundle.pcs_params.field_profile {
        return Err(anyhow!("bridge commitment/params field profile mismatch"));
    }
    if bundle.pcs_params.n_per_row != expected_params.n_per_row
        || bundle.pcs_params.n_degree_tests != expected_params.n_degree_tests
        || bundle.pcs_params.n_col_opens != expected_params.n_col_opens
        || bundle.pcs_params.security_bits != expected_params.security_bits
        || bundle.pcs_params.field_profile != expected_params.field_profile
        || bundle.pcs_params.auto_tune_security != expected_params.auto_tune_security
        || bundle.pcs_params.encoder_kind != expected_params.encoder_kind
        || bundle.pcs_params.encoder_seed != expected_params.encoder_seed
        || bundle.pcs_params.spel_layers != expected_params.spel_layers
        || bundle.pcs_params.spel_pre_density != expected_params.spel_pre_density
        || bundle.pcs_params.spel_post_density != expected_params.spel_post_density
        || bundle.pcs_params.spel_base_rs_parity != expected_params.spel_base_rs_parity
    {
        return Err(anyhow!("bridge PCS parameter contract mismatch"));
    }
    let pcs = BrakedownPcs::new(bundle.pcs_params.clone());
    let outer_tensor = vec![Fp::new(1), query.gamma, query.gamma.mul(query.gamma)];
    // Research-succinct boundary: verifier avoids witness-like inner tensor input
    // and checks transcript/PCS opening structure at this bridge layer.
    pcs.verify_structure_generic(
        &bundle.verifier_commitment,
        &bundle.pcs_opening_proof,
        &outer_tensor,
        tr,
    )?;

    Ok(BridgeVerifyReport {
        outer_verify: outer_v,
        inner_verify: inner_v,
    })
}
