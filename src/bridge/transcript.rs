use merlin::Transcript;

use crate::protocol::spec_v1::append_fp_le;

use super::types::BridgeVerifierQuery;

pub(crate) fn append_bridge_public_metadata(tr: &mut Transcript, query: &BridgeVerifierQuery) {
    tr.append_message(b"case_digest", &query.public_case_digest);
    append_fp_le(tr, b"gamma", query.gamma);
    append_fp_le(tr, b"claimed", query.claimed_value);
}
