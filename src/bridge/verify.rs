use anyhow::{anyhow, Result};
use merlin::Transcript;

use crate::{
    core::field::{Fp, ModulusScope},
    pcs::{
        brakedown::{profiles::params_for_field_profile, BrakedownPcs},
        traits::PolynomialCommitmentScheme,
    },
    protocol::{
        reference::append_reference_profile_to_transcript,
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

    let expected_params = params_for_field_profile(
        bundle.verifier_commitment.n_per_row,
        bundle.verifier_commitment.field_profile,
    );
    if expected_params.field_profile != bundle.pcs_params.field_profile {
        return Err(anyhow!("bridge params/profile mismatch"));
    }
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
