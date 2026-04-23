use anyhow::{anyhow, Result};
use merlin::Transcript;

use crate::protocol::spec_v1::LCPC_DEG_TEST_LABEL;

use super::{
    challenges::{sample_field_vec_round_t, sample_unique_cols},
    merkle::verify_column_path_t,
    scalar::BrakedownField,
    types::{
        BrakedownEncoding, BrakedownEvalProofT, BrakedownParams, BrakedownVerifierCommitment,
    },
};

pub fn verify_eval_t<F: BrakedownField>(
    commitment: &BrakedownVerifierCommitment,
    proof: &BrakedownEvalProofT<F>,
    outer_tensor: &[F],
    inner_tensor: &[F],
    claimed_value: F,
    enc: &BrakedownEncoding,
    params: &BrakedownParams,
    tr: &mut Transcript,
) -> Result<()> {
    if commitment.n_per_row != enc.n_per_row || commitment.n_cols != enc.n_cols {
        return Err(anyhow!("commitment dimension/encoding mismatch"));
    }
    if commitment.field_profile != params.field_profile {
        return Err(anyhow!("commitment field profile mismatch"));
    }
    if commitment.encoder_kind != enc.kind
        || commitment.encoder_seed != enc.seed
        || commitment.spel_layers != enc.spel_layers
        || commitment.spel_pre_density != enc.spel_pre_density
        || commitment.spel_post_density != enc.spel_post_density
        || commitment.spel_base_rs_parity != enc.spel_base_rs_parity
    {
        return Err(anyhow!("commitment encoder profile mismatch"));
    }

    if outer_tensor.len() != commitment.n_rows {
        return Err(anyhow!("outer tensor size mismatch"));
    }
    if inner_tensor.len() != enc.n_per_row {
        return Err(anyhow!("inner tensor size mismatch"));
    }
    if proof.columns.len() != params.n_col_opens {
        return Err(anyhow!("num openings mismatch"));
    }
    if proof.p_eval.len() != enc.n_per_row {
        return Err(anyhow!("p_eval length mismatch"));
    }
    if proof.p_random_vec.len() != params.n_degree_tests {
        return Err(anyhow!("degree-test vector count mismatch"));
    }

    let mut rand_tensors = Vec::new();
    for (round, p_rand) in proof.p_random_vec.iter().enumerate() {
        if p_rand.len() != enc.n_per_row {
            return Err(anyhow!("degree-test vector length mismatch"));
        }

        let t: Vec<F> = sample_field_vec_round_t(
            tr,
            LCPC_DEG_TEST_LABEL,
            round as u64,
            commitment.n_rows,
        );
        rand_tensors.push(t);
        for v in p_rand {
            let mut b = Vec::new();
            v.append_le_bytes(&mut b);
            tr.append_message(b"p_random", &b);
        }
    }

    for v in &proof.p_eval {
        let mut b = Vec::new();
        v.append_le_bytes(&mut b);
        tr.append_message(b"p_eval", &b);
    }

    let cols_expected = sample_unique_cols(tr, enc.n_cols, params.n_col_opens)?;

    let p_eval_enc = enc.encode_row_t(&proof.p_eval);
    let p_rand_enc: Vec<Vec<F>> = proof
        .p_random_vec
        .iter()
        .map(|v| enc.encode_row_t(v))
        .collect();

    let expected_path_len = enc.n_cols.next_power_of_two().trailing_zeros() as usize;

    for (i, op) in proof.columns.iter().enumerate() {
        if op.col_idx != cols_expected[i] {
            return Err(anyhow!("opened column index mismatch"));
        }
        if op.values.len() != commitment.n_rows {
            return Err(anyhow!("opened column value length mismatch"));
        }
        if op.merkle_path.len() != expected_path_len {
            return Err(anyhow!("opened column merkle path length mismatch"));
        }

        for j in 0..proof.p_random_vec.len() {
            let dot = rand_tensors[j]
                .iter()
                .zip(op.values.iter())
                .fold(F::zero(), |acc, (a, b)| acc.add((*a).mul(*b)));
            if dot != p_rand_enc[j][op.col_idx] {
                return Err(anyhow!("degree-test column check failed"));
            }
        }

        let dot_eval = outer_tensor
            .iter()
            .zip(op.values.iter())
            .fold(F::zero(), |acc, (a, b)| acc.add((*a).mul(*b)));
        if dot_eval != p_eval_enc[op.col_idx] {
            return Err(anyhow!("eval column check failed"));
        }

        if !verify_column_path_t(commitment.root, op) {
            return Err(anyhow!("merkle path failed"));
        }
    }

    let eval = inner_tensor
        .iter()
        .zip(proof.p_eval.iter())
        .fold(F::zero(), |acc, (a, b)| acc.add((*a).mul(*b)));
    if eval != claimed_value {
        return Err(anyhow!("claimed evaluation mismatch"));
    }
    Ok(())
}
