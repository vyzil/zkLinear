use merlin::Transcript;
use sha2::{Digest, Sha256};

use crate::pcs::brakedown::{
    profiles::params_for_field_profile,
    types::{BrakedownFieldProfile, BrakedownParams},
};
use crate::protocol::reference::ReferenceProfile;
use crate::protocol::spec_v1::{append_fp_le, append_u64_le};

use super::types::BridgeVerifierQuery;

pub(crate) fn append_bridge_public_metadata(tr: &mut Transcript, query: &BridgeVerifierQuery) {
    append_u64_le(tr, b"rows", query.rows as u64);
    append_u64_le(tr, b"cols", query.cols as u64);
    append_u64_le(tr, b"field_profile", query.field_profile as u64);
    tr.append_message(b"case_digest", &query.public_case_digest);
    tr.append_message(b"context_fingerprint", &query.context_fingerprint);
    append_fp_le(tr, b"gamma", query.gamma);
    append_fp_le(tr, b"claimed", query.claimed_value);
}

pub(crate) fn bridge_context_fingerprint(
    rows: usize,
    cols: usize,
    case_digest: [u8; 32],
    field_profile: BrakedownFieldProfile,
    reference_profile: ReferenceProfile,
) -> [u8; 32] {
    let params = bridge_public_params(cols, field_profile);
    let mut h = Sha256::new();
    h.update(b"zklinear/bridge/context-fingerprint/v1");
    h.update((rows as u64).to_le_bytes());
    h.update((cols as u64).to_le_bytes());
    h.update(case_digest);
    h.update((field_profile as u8).to_le_bytes());
    h.update((reference_profile.protocol as u8).to_le_bytes());
    h.update((reference_profile.pcs as u8).to_le_bytes());
    h.update((params.n_degree_tests as u64).to_le_bytes());
    h.update((params.n_col_opens as u64).to_le_bytes());
    h.update((params.col_open_start as u64).to_le_bytes());
    h.update((params.security_bits as u64).to_le_bytes());
    h.update((params.auto_tune_security as u8).to_le_bytes());
    h.update((params.encoder_kind as u8).to_le_bytes());
    h.update(params.encoder_seed.to_le_bytes());
    h.update((params.spel_layers as u64).to_le_bytes());
    h.update((params.spel_pre_density as u64).to_le_bytes());
    h.update((params.spel_post_density as u64).to_le_bytes());
    h.update((params.spel_base_rs_parity as u64).to_le_bytes());
    h.finalize().into()
}

pub(crate) fn bridge_public_params(
    cols: usize,
    profile: BrakedownFieldProfile,
) -> BrakedownParams {
    params_for_field_profile(cols, profile)
}
