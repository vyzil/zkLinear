use merlin::Transcript;

use crate::core::field::Fp;

pub const TRANSCRIPT_DOMAIN: &[u8] = b"zklinear/v1/spartan-brakedown";
pub const NIZK_TRANSCRIPT_LABEL: &[u8] = b"SpartanSNARK";
pub const PCS_DEMO_TRANSCRIPT_LABEL: &[u8] = b"zklinear/v1/spartan-brakedown/pcs-demo";

pub const OUTER_SUMCHECK_LABEL: &[u8] = b"spartan-outer-sumcheck";
pub const INNER_SUMCHECK_LABEL: &[u8] = b"spartan-inner-sumcheck";
pub const INNER_SUMCHECK_JOINT_LABEL: &[u8] = b"spartan-inner-joint";

pub const BLIND_MIX_LABEL: &[u8] = b"spartan_nizk_blind_mix_alpha";
pub const JOINT_CHALLENGE_DOMAIN: &[u8] = b"spartan-like-joint-challenge";
pub const JOINT_CHALLENGE_R_LABEL: &[u8] = b"r";
pub const JOINT_CHALLENGE_RA_LABEL: &[u8] = b"r_a";
pub const JOINT_CHALLENGE_RB_LABEL: &[u8] = b"r_b";
pub const JOINT_CHALLENGE_RC_LABEL: &[u8] = b"r_c";
pub const OUTER_TAU_LABEL: &[u8] = b"spartan-outer-tau";
pub const LCPC_DEG_TEST_LABEL: &[u8] = b"lcpc_deg_test";
pub const LCPC_COL_OPEN_LABEL: &[u8] = b"lcpc_col_open";

pub fn append_spec_domain(tr: &mut Transcript) {
    tr.append_message(b"zklinear_spec", TRANSCRIPT_DOMAIN);
}

pub fn append_u64_le(tr: &mut Transcript, label: &'static [u8], v: u64) {
    tr.append_message(label, &v.to_le_bytes());
}

pub fn append_fp_le(tr: &mut Transcript, label: &'static [u8], v: Fp) {
    tr.append_message(label, &v.0.to_le_bytes());
}
