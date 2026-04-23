use merlin::Transcript;
use sha2::{Digest, Sha256};

use crate::core::field::Fp;

pub fn derive_round_challenge(label: &[u8], round: usize, h0: Fp, h1: Fp, h2: Fp) -> Fp {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update((round as u64).to_be_bytes());
    hasher.update(h0.0.to_be_bytes());
    hasher.update(h1.0.to_be_bytes());
    hasher.update(h2.0.to_be_bytes());
    let out = hasher.finalize();
    Fp::from_challenge(out.into())
}

pub fn derive_round_challenge_merlin(
    tr: &mut Transcript,
    label: &[u8],
    round: usize,
    h0: Fp,
    h1: Fp,
    h2: Fp,
) -> Fp {
    tr.append_message(b"round_label", label);
    tr.append_message(b"round_idx", &(round as u64).to_be_bytes());
    tr.append_message(b"msg_0", &h0.0.to_be_bytes());
    tr.append_message(b"msg_1", &h1.0.to_be_bytes());
    tr.append_message(b"msg_2", &h2.0.to_be_bytes());
    let mut out = [0u8; 32];
    tr.challenge_bytes(b"round_challenge", &mut out);
    Fp::from_challenge(out)
}
