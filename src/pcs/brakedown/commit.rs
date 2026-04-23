use anyhow::{Result, anyhow};

use crate::core::field::Fp;

use super::{
  merkle::{digest_fp_list, merkle_tree},
  types::{BrakedownProverCommitment, ColumnOpening, MiniEncoding},
};

pub fn commit(coeffs_in: &[Fp], enc: &MiniEncoding) -> Result<BrakedownProverCommitment> {
  if coeffs_in.len() % enc.n_per_row != 0 {
    return Err(anyhow!("coeff length must be multiple of n_per_row"));
  }

  let n_rows = coeffs_in.len() / enc.n_per_row;
  let mut encoded = vec![Fp::zero(); n_rows * enc.n_cols];

  for r in 0..n_rows {
    let row = &coeffs_in[r * enc.n_per_row..(r + 1) * enc.n_per_row];
    let enc_row = enc.encode_row(row);
    encoded[r * enc.n_cols..(r + 1) * enc.n_cols].copy_from_slice(&enc_row);
  }

  let mut leaf_hashes = Vec::with_capacity(enc.n_cols);
  for c in 0..enc.n_cols {
    let mut col = Vec::with_capacity(n_rows);
    for r in 0..n_rows {
      col.push(encoded[r * enc.n_cols + c]);
    }
    leaf_hashes.push(digest_fp_list(&col));
  }

  let merkle_nodes = merkle_tree(&leaf_hashes);

  Ok(BrakedownProverCommitment {
    coeffs: coeffs_in.to_vec(),
    encoded,
    n_rows,
    n_per_row: enc.n_per_row,
    n_cols: enc.n_cols,
    leaf_hashes,
    merkle_nodes,
  })
}

pub fn open_column(comm: &BrakedownProverCommitment, col_idx: usize) -> Result<ColumnOpening> {
  if col_idx >= comm.n_cols {
    return Err(anyhow!("opened column out of range"));
  }

  let mut values = Vec::with_capacity(comm.n_rows);
  for r in 0..comm.n_rows {
    values.push(comm.encoded[r * comm.n_cols + col_idx]);
  }

  let n = comm.n_cols.next_power_of_two();
  let mut path = Vec::new();
  let mut idx = col_idx;
  let mut layer_start = 0usize;
  let mut width = n;
  while width > 1 {
    let sib = idx ^ 1;
    let sib_hash = comm.merkle_nodes[layer_start + sib];
    path.push(sib_hash);
    idx >>= 1;
    layer_start += width;
    width >>= 1;
  }

  Ok(ColumnOpening {
    col_idx,
    values,
    merkle_path: path,
  })
}
