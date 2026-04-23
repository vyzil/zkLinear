use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::nizk::spartan_brakedown::prove_from_dir;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LcpcLikeParitySnapshot {
    pub field_profile: String,
    pub n_rows: usize,
    pub n_per_row: usize,
    pub n_cols: usize,
    pub n_degree_tests: usize,
    pub n_col_opens: usize,
    pub opened_cols: usize,
    pub p_eval_len: usize,
    pub p_random_count: usize,
    pub merkle_root_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LcpcLikeMustMatchView {
    pub n_rows: usize,
    pub n_per_row: usize,
    pub n_cols: usize,
    pub n_degree_tests: usize,
    pub n_col_opens: usize,
    pub opened_cols: usize,
    pub p_eval_len: usize,
    pub p_random_count: usize,
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn build_local_lcpc_like_snapshot(case_dir: &Path) -> Result<LcpcLikeParitySnapshot> {
    let pipeline = prove_from_dir(case_dir)?;
    let vc = &pipeline.proof.verifier_commitment;
    let pf = &pipeline.proof.pcs_proof_main;

    Ok(LcpcLikeParitySnapshot {
        field_profile: format!("{:?}", vc.field_profile),
        n_rows: vc.n_rows,
        n_per_row: vc.n_per_row,
        n_cols: vc.n_cols,
        n_degree_tests: pf.p_random_vec.len(),
        n_col_opens: pf.columns.len(),
        opened_cols: pf.columns.len(),
        p_eval_len: pf.p_eval.len(),
        p_random_count: pf.p_random_vec.len(),
        merkle_root_hex: to_hex(&vc.root),
    })
}

impl LcpcLikeParitySnapshot {
    pub fn must_match_view(&self) -> LcpcLikeMustMatchView {
        LcpcLikeMustMatchView {
            n_rows: self.n_rows,
            n_per_row: self.n_per_row,
            n_cols: self.n_cols,
            n_degree_tests: self.n_degree_tests,
            n_col_opens: self.n_col_opens,
            opened_cols: self.opened_cols,
            p_eval_len: self.p_eval_len,
            p_random_count: self.p_random_count,
        }
    }
}
