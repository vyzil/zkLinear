use anyhow::{anyhow, Result};
use merlin::Transcript;

use crate::core::field::Fp;
use super::scalar::BrakedownField;
use crate::protocol::spec_v1::LCPC_COL_OPEN_LABEL;

pub fn sample_field_vec(tr: &mut Transcript, label: &'static [u8], n: usize) -> Vec<Fp> {
    sample_field_vec_t(tr, label, n)
}

fn next_u64(tr: &mut Transcript, label: &'static [u8]) -> u64 {
    let mut b = [0u8; 8];
    tr.challenge_bytes(label, &mut b);
    u64::from_le_bytes(b)
}

fn sample_u64_below_unbiased(
    tr: &mut Transcript,
    label: &'static [u8],
    upper_exclusive: u64,
) -> u64 {
    assert!(upper_exclusive > 0, "upper bound must be positive");
    let zone = u64::MAX - (u64::MAX % upper_exclusive);
    loop {
        let x = next_u64(tr, label);
        if x < zone {
            return x % upper_exclusive;
        }
    }
}

fn sample_field_unbiased<F: BrakedownField>(tr: &mut Transcript, label: &'static [u8]) -> F {
    let p = F::modulus();
    let x = sample_u64_below_unbiased(tr, label, p);
    F::new(x)
}

pub fn sample_field_vec_t<F: BrakedownField>(
    tr: &mut Transcript,
    label: &'static [u8],
    n: usize,
) -> Vec<F> {
    (0..n).map(|_| sample_field_unbiased::<F>(tr, label)).collect()
}

pub fn sample_unique_cols(tr: &mut Transcript, n_cols: usize, n_open: usize) -> Result<Vec<usize>> {
    if n_open > n_cols {
        return Err(anyhow!("cannot open more columns than available"));
    }

    let mut all: Vec<usize> = (0..n_cols).collect();
    for i in 0..n_open {
        let off = sample_u64_below_unbiased(
            tr,
            LCPC_COL_OPEN_LABEL,
            (n_cols - i) as u64,
        ) as usize;
        let j = i + off;
        all.swap(i, j);
    }

    Ok(all[..n_open].to_vec())
}
