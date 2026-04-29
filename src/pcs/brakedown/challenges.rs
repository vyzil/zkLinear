use anyhow::{anyhow, Result};
use merlin::Transcript;
use rand::distributions::{Distribution, Uniform};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::iter::repeat_with;

use super::scalar::BrakedownField;
use crate::core::field::Fp;
use crate::protocol::spec_v1::LCPC_COL_OPEN_LABEL;

pub fn sample_field_vec(tr: &mut Transcript, label: &'static [u8], n: usize) -> Vec<Fp> {
    sample_field_vec_t(tr, label, n)
}

fn sample_field_from_transcript<F: BrakedownField>(tr: &mut Transcript, label: &'static [u8]) -> F {
    let mut out = [0u8; 32];
    tr.challenge_bytes(label, &mut out);
    F::from_challenge(out)
}

pub fn sample_field_vec_t<F: BrakedownField>(
    tr: &mut Transcript,
    label: &'static [u8],
    n: usize,
) -> Vec<F> {
    (0..n)
        .map(|_| sample_field_from_transcript::<F>(tr, label))
        .collect()
}

pub fn sample_field_vec_round_t<F: BrakedownField>(
    tr: &mut Transcript,
    label: &'static [u8],
    _round: u64,
    n: usize,
) -> Vec<F> {
    sample_field_vec_t(tr, label, n)
}

pub fn sample_unique_cols(tr: &mut Transcript, n_cols: usize, n_open: usize) -> Result<Vec<usize>> {
    sample_cols(tr, n_cols, n_open)
}

pub fn sample_cols(tr: &mut Transcript, n_cols: usize, n_open: usize) -> Result<Vec<usize>> {
    if n_cols == 0 {
        return Err(anyhow!("cannot sample columns when n_cols is zero"));
    }
    tr.append_message(b"lcpc_col_ncols", &(n_cols as u64).to_le_bytes());
    tr.append_message(b"lcpc_col_nopen", &(n_open as u64).to_le_bytes());

    let mut key: <ChaCha20Rng as SeedableRng>::Seed = Default::default();
    tr.challenge_bytes(LCPC_COL_OPEN_LABEL, &mut key);
    let mut rng = ChaCha20Rng::from_seed(key);
    let col_range = Uniform::new(0usize, n_cols);
    let out = repeat_with(|| col_range.sample(&mut rng))
        .take(n_open)
        .collect::<Vec<_>>();
    Ok(out)
}
