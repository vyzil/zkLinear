use anyhow::{anyhow, Result};
use merlin::Transcript;

use crate::{
    core::field::{Fp, ModulusScope},
    pcs::{
        brakedown::{profiles::params_for_field_profile, BrakedownPcs},
    },
    protocol::{
        reference::{append_reference_profile_to_transcript, DUAL_REFERENCE_PROFILE},
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
    let _mod_scope = ModulusScope::enter(bundle.verifier_commitment.field_profile.base_modulus());
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
    if bundle.reference_profile != DUAL_REFERENCE_PROFILE {
        return Err(anyhow!("unsupported reference profile for this bridge flow"));
    }
    if bundle.inner_trace.claim_initial != query.claimed_value {
        return Err(anyhow!(
            "inner-sumcheck claim and verifier claimed value mismatch"
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

    let expected_params = params_for_field_profile(
        bundle.verifier_commitment.n_per_row,
        bundle.verifier_commitment.field_profile,
    );
    if expected_params.field_profile != bundle.pcs_params.field_profile {
        return Err(anyhow!("bridge params/profile mismatch"));
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
