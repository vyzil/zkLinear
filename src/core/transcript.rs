use merlin::Transcript;
use sha2::{Digest, Sha256};

use crate::{
    core::{field::Fp, field_element::FieldElement},
    protocol::spec_v1::append_u64_le,
};

pub fn derive_round_challenge(label: &[u8], round: usize, h0: Fp, h1: Fp, h2: Fp) -> Fp {
    derive_round_challenge_t::<Fp>(label, round, h0, h1, h2)
}

pub fn derive_round_challenge_t<F: FieldElement>(
    label: &[u8],
    round: usize,
    h0: F,
    h1: F,
    h2: F,
) -> F {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update((round as u64).to_le_bytes());
    let mut buf = Vec::new();
    h0.append_le_bytes(&mut buf);
    h1.append_le_bytes(&mut buf);
    h2.append_le_bytes(&mut buf);
    hasher.update(buf);
    let out = hasher.finalize();
    F::from_challenge(out.into())
}

pub fn derive_round_challenge_merlin(
    tr: &mut Transcript,
    label: &[u8],
    round: usize,
    h0: Fp,
    h1: Fp,
    h2: Fp,
) -> Fp {
    derive_round_challenge_merlin_t::<Fp>(tr, label, round, h0, h1, h2)
}

pub fn derive_round_challenge_merlin_t<F: FieldElement>(
    tr: &mut Transcript,
    label: &[u8],
    round: usize,
    h0: F,
    h1: F,
    h2: F,
) -> F {
    tr.append_message(b"round_label", label);
    append_u64_le(tr, b"round_idx", round as u64);
    let mut b0 = Vec::new();
    let mut b1 = Vec::new();
    let mut b2 = Vec::new();
    h0.append_le_bytes(&mut b0);
    h1.append_le_bytes(&mut b1);
    h2.append_le_bytes(&mut b2);
    tr.append_message(b"msg_0", &b0);
    tr.append_message(b"msg_1", &b1);
    tr.append_message(b"msg_2", &b2);
    let mut out = [0u8; 32];
    tr.challenge_bytes(b"round_challenge", &mut out);
    F::from_challenge(out)
}
