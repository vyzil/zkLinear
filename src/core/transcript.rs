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
