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
) -> Result<u64> {
    if upper_exclusive == 0 {
        return Err(anyhow!("upper bound must be positive"));
    }
    let zone = u64::MAX - (u64::MAX % upper_exclusive);
    loop {
        let x = next_u64(tr, label);
        if x < zone {
            return Ok(x % upper_exclusive);
        }
    }
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
    round: u64,
    n: usize,
) -> Vec<F> {
    tr.append_message(b"lcpc_deg_round", &round.to_le_bytes());
    sample_field_vec_t(tr, label, n)
}

pub fn sample_unique_cols(tr: &mut Transcript, n_cols: usize, n_open: usize) -> Result<Vec<usize>> {
    sample_unique_cols_from_start(tr, n_cols, n_open, 0)
}

pub fn sample_unique_cols_from_start(
    tr: &mut Transcript,
    n_cols: usize,
    n_open: usize,
    start_col: usize,
) -> Result<Vec<usize>> {
    if start_col > n_cols {
        return Err(anyhow!("column sampling start must be <= n_cols"));
    }
    if start_col == n_cols {
        if n_open == 0 {
            tr.append_message(b"lcpc_col_ncols", &(n_cols as u64).to_le_bytes());
            tr.append_message(b"lcpc_col_nopen", &(n_open as u64).to_le_bytes());
            tr.append_message(b"lcpc_col_start", &(start_col as u64).to_le_bytes());
            return Ok(Vec::new());
        }
        return Err(anyhow!(
            "cannot open columns when sampling range is empty"
        ));
    }
    let avail = n_cols - start_col;
    if n_open > avail {
        return Err(anyhow!(
            "cannot open more columns than available in the requested range"
        ));
    }
    tr.append_message(b"lcpc_col_ncols", &(n_cols as u64).to_le_bytes());
    tr.append_message(b"lcpc_col_nopen", &(n_open as u64).to_le_bytes());
    tr.append_message(b"lcpc_col_start", &(start_col as u64).to_le_bytes());

    let mut all: Vec<usize> = (start_col..n_cols).collect();
    for i in 0..n_open {
        let off = sample_u64_below_unbiased(
            tr,
            LCPC_COL_OPEN_LABEL,
            (avail - i) as u64,
        )? as usize;
        let j = i + off;
        all.swap(i, j);
    }

    Ok(all[..n_open].to_vec())
}
