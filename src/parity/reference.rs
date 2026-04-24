use std::path::Path;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use crate::{
    api::spartan_like::build_spartan_like_report_data_from_dir, core::field::Fp,
    nizk::spartan_brakedown::prove_from_dir,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParitySnapshot {
    pub rows: usize,
    pub cols: usize,
    pub z_len: usize,
    pub az: Vec<u64>,
    pub bz: Vec<u64>,
    pub cz: Vec<u64>,
    pub residual: Vec<u64>,
    pub outer_claim_initial: u64,
    pub outer_rounds: usize,
    pub inner_rounds: usize,
    pub spartan_gamma: u64,
    pub nizk_gamma: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MustMatchParityView {
    pub rows: usize,
    pub cols: usize,
    pub z_len: usize,
    pub az: Vec<u64>,
    pub bz: Vec<u64>,
    pub cz: Vec<u64>,
    pub residual: Vec<u64>,
    pub outer_claim_initial: u64,
    pub outer_rounds: usize,
    pub inner_rounds: usize,
}

fn fp_vec_to_u64(v: &[Fp]) -> Vec<u64> {
    v.iter().map(|x| x.0).collect()
}

pub fn build_local_parity_snapshot(case_dir: &Path) -> Result<ParitySnapshot> {
    let sp = build_spartan_like_report_data_from_dir(case_dir)?;
    let nz = prove_from_dir(case_dir)?;

    if sp.outer_trace.claim_initial != nz.proof.outer_trace.claim_initial {
        return Err(anyhow!(
            "local parity invariant failed: outer claim mismatch between spartan-like and nizk paths"
        ));
    }

    Ok(ParitySnapshot {
        rows: sp.case.a.len(),
        cols: sp.case.a[0].len(),
        z_len: sp.case.z.len(),
        az: fp_vec_to_u64(&sp.az),
        bz: fp_vec_to_u64(&sp.bz),
        cz: fp_vec_to_u64(&sp.cz),
        residual: fp_vec_to_u64(&sp.residual),
        outer_claim_initial: sp.outer_trace.claim_initial.0,
        outer_rounds: sp.outer_trace.rounds.len(),
        inner_rounds: sp.joint_trace.rounds.len(),
        spartan_gamma: sp.gamma.0,
        nizk_gamma: nz.proof.gamma.0,
    })
}

impl ParitySnapshot {
    pub fn must_match_view(&self) -> MustMatchParityView {
        MustMatchParityView {
            rows: self.rows,
            cols: self.cols,
            z_len: self.z_len,
            az: self.az.clone(),
            bz: self.bz.clone(),
            cz: self.cz.clone(),
            residual: self.residual.clone(),
            outer_claim_initial: self.outer_claim_initial,
            outer_rounds: self.outer_rounds,
            inner_rounds: self.inner_rounds,
        }
    }
}
