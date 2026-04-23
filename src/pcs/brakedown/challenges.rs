use anyhow::{Result, anyhow};
use merlin::Transcript;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::core::field::Fp;

pub fn sample_field_vec(tr: &mut Transcript, label: &'static [u8], n: usize) -> Vec<Fp> {
  let mut seed = [0u8; 32];
  tr.challenge_bytes(label, &mut seed);
  let mut rng = ChaCha20Rng::from_seed(seed);
  (0..n).map(|_| Fp::new(rng.r#gen::<u64>())).collect()
}

pub fn sample_unique_cols(
  tr: &mut Transcript,
  n_cols: usize,
  n_open: usize,
) -> Result<Vec<usize>> {
  if n_open > n_cols {
    return Err(anyhow!("cannot open more columns than available"));
  }

  let mut seed = [0u8; 32];
  tr.challenge_bytes(b"lcpc_col_open", &mut seed);
  let mut rng = ChaCha20Rng::from_seed(seed);

  let mut all: Vec<usize> = (0..n_cols).collect();
  for i in 0..n_open {
    let j = i + rng.gen_range(0..(n_cols - i));
    all.swap(i, j);
  }

  Ok(all[..n_open].to_vec())
}
