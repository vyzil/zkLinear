use anyhow::{anyhow, Result};
use merlin::Transcript;

use crate::core::field::Fp;
use crate::protocol::spec_v1::LCPC_DEG_TEST_LABEL;

use super::{
    challenges::{sample_field_vec, sample_unique_cols},
    commit::open_column,
    types::{BrakedownEncoding, BrakedownEvalProof, BrakedownParams, BrakedownProverCommitment},
};

fn collapse_rows(coeffs: &[Fp], tensor: &[Fp], n_rows: usize, n_per_row: usize) -> Vec<Fp> {
    assert_eq!(tensor.len(), n_rows);
    let mut out = vec![Fp::zero(); n_per_row];
    for r in 0..n_rows {
        for c in 0..n_per_row {
            out[c] = out[c].add(coeffs[r * n_per_row + c].mul(tensor[r]));
        }
    }
    out
}

pub fn prove_eval(
    comm: &BrakedownProverCommitment,
    outer_tensor: &[Fp],
    enc: &BrakedownEncoding,
    params: &BrakedownParams,
    tr: &mut Transcript,
) -> Result<BrakedownEvalProof> {
    if outer_tensor.len() != comm.n_rows {
        return Err(anyhow!("outer tensor size mismatch"));
    }

    let mut p_random_vec = Vec::new();
    for _ in 0..params.n_degree_tests {
        let rand_tensor = sample_field_vec(tr, LCPC_DEG_TEST_LABEL, comm.n_rows);
        let p_rand = collapse_rows(&comm.coeffs, &rand_tensor, comm.n_rows, comm.n_per_row);
        for v in &p_rand {
            tr.append_message(b"p_random", &v.0.to_le_bytes());
        }
        p_random_vec.push(p_rand);
    }

    let p_eval = collapse_rows(&comm.coeffs, outer_tensor, comm.n_rows, comm.n_per_row);
    for v in &p_eval {
        tr.append_message(b"p_eval", &v.0.to_le_bytes());
    }

    let cols = sample_unique_cols(tr, comm.n_cols, params.n_col_opens)?;
    let mut openings = Vec::with_capacity(cols.len());
    for c in cols {
        openings.push(open_column(comm, c)?);
    }

    let _ = enc;
    Ok(BrakedownEvalProof {
        p_eval,
        p_random_vec,
        columns: openings,
    })
}
