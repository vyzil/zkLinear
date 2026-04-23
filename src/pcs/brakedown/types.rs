use crate::core::field::Fp;

pub const DEFAULT_N_DEGREE_TESTS: usize = 2;
pub const DEFAULT_N_COL_OPENS: usize = 3;

#[derive(Clone, Debug)]
pub struct BrakedownParams {
  pub n_per_row: usize,
  pub n_degree_tests: usize,
  pub n_col_opens: usize,
}

impl BrakedownParams {
  pub fn new(n_per_row: usize) -> Self {
    Self {
      n_per_row,
      n_degree_tests: DEFAULT_N_DEGREE_TESTS,
      n_col_opens: DEFAULT_N_COL_OPENS,
    }
  }
}

#[derive(Clone, Debug)]
pub struct MiniEncoding {
  pub n_per_row: usize,
  pub n_cols: usize,
}

#[derive(Clone, Debug)]
pub struct BrakedownProverCommitment {
  pub coeffs: Vec<Fp>,
  pub encoded: Vec<Fp>,
  pub n_rows: usize,
  pub n_per_row: usize,
  pub n_cols: usize,
  pub leaf_hashes: Vec<[u8; 32]>,
  pub merkle_nodes: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct BrakedownVerifierCommitment {
  pub root: [u8; 32],
  pub n_rows: usize,
  pub n_per_row: usize,
  pub n_cols: usize,
}

impl BrakedownProverCommitment {
  pub fn verifier_view(&self) -> BrakedownVerifierCommitment {
    BrakedownVerifierCommitment {
      root: *self.merkle_nodes.last().unwrap_or(&[0u8; 32]),
      n_rows: self.n_rows,
      n_per_row: self.n_per_row,
      n_cols: self.n_cols,
    }
  }
}

#[derive(Clone, Debug)]
pub struct ColumnOpening {
  pub col_idx: usize,
  pub values: Vec<Fp>,
  pub merkle_path: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct BrakedownEvalProof {
  pub p_eval: Vec<Fp>,
  pub p_random_vec: Vec<Vec<Fp>>,
  pub columns: Vec<ColumnOpening>,
}
