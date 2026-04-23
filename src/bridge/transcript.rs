use merlin::Transcript;

use crate::protocol::spec_v1::{append_fp_le, append_u64_le};

use super::types::BridgeVerifierQuery;

pub(crate) fn append_bridge_public_metadata(tr: &mut Transcript, query: &BridgeVerifierQuery) {
    append_u64_le(tr, b"field_profile", query.field_profile as u64);
    tr.append_message(b"case_digest", &query.public_case_digest);
    append_fp_le(tr, b"gamma", query.gamma);
    append_fp_le(tr, b"claimed", query.claimed_value);
}
