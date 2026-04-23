use anyhow::Result;
use merlin::Transcript;

use crate::{
  core::field::{Fp, MODULUS},
  pcs::traits::PolynomialCommitmentScheme,
};

use super::{BrakedownPcs, merkle::merkle_root, types::BrakedownParams};

pub fn build_brakedown_demo_report() -> Result<String> {
  let params = BrakedownParams::new(8);
  let pcs = BrakedownPcs::new(params.clone());

  let n_rows = 4;
  let coeffs: Vec<Fp> = (0..(n_rows * params.n_per_row))
    .map(|i| Fp::new(((i as u64) * 13 + 5) % MODULUS))
    .collect();

  let prover_commitment = pcs.commit(&coeffs)?;
  let verifier_commitment = pcs.verifier_commitment(&prover_commitment);
  let root = merkle_root(&prover_commitment.merkle_nodes);

  let x = Fp::new(7);
  let mut inner = Vec::with_capacity(params.n_per_row);
  let mut p = Fp::new(1);
  for _ in 0..params.n_per_row {
    inner.push(p);
    p = p.mul(x);
  }

  let xr = x.mul(*inner.last().unwrap());
  let mut outer = Vec::with_capacity(n_rows);
  let mut q = Fp::new(1);
  for _ in 0..n_rows {
    outer.push(q);
    q = q.mul(xr);
  }

  let mut tr_p = Transcript::new(b"mini-brakedown-demo");
  tr_p.append_message(b"polycommit", &root);
  tr_p.append_message(b"ncols", &(pcs.encoding.n_cols as u64).to_be_bytes());
  let proof = pcs.open(&prover_commitment, &outer, &mut tr_p)?;

  let mut tr_v = Transcript::new(b"mini-brakedown-demo");
  tr_v.append_message(b"polycommit", &root);
  tr_v.append_message(b"ncols", &(pcs.encoding.n_cols as u64).to_be_bytes());
  let claimed_eval = inner
    .iter()
    .zip(proof.p_eval.iter())
    .fold(Fp::zero(), |acc, (a, b)| acc.add((*a).mul(*b)));
  pcs.verify(
    &verifier_commitment,
    &proof,
    &outer,
    &inner,
    claimed_eval,
    &mut tr_v,
  )?;

  let mut out = String::new();
  out.push_str("=== Independent Mini Brakedown-style Trace ===\n");
  out.push_str("\n[Input]\n");
  out.push_str(&format!("field: F_{}\n", MODULUS));
  out.push_str(&format!(
    "coeffs len={} (rows={} x per_row={})\n",
    coeffs.len(),
    n_rows,
    params.n_per_row
  ));
  out.push_str(&format!(
    "coeffs (first 16): {:?}\n",
    coeffs.iter().take(16).map(|x| x.0).collect::<Vec<_>>()
  ));
  out.push_str(&format!(
    "inner tensor (len={}): {:?}\n",
    inner.len(),
    inner.iter().map(|x| x.0).collect::<Vec<_>>()
  ));
  out.push_str(&format!(
    "outer tensor (len={}): {:?}\n",
    outer.len(),
    outer.iter().map(|x| x.0).collect::<Vec<_>>()
  ));

  out.push_str("\n[Commit]\n");
  out.push_str(&format!(
    "dims: n_rows={}, n_per_row={}, n_cols={}\n",
    prover_commitment.n_rows, prover_commitment.n_per_row, prover_commitment.n_cols
  ));
  out.push_str(&format!(
    "security params (demo): n_col_opens={}, n_degree_tests={}\n",
    params.n_col_opens, params.n_degree_tests
  ));
  out.push_str(&format!("Merkle root(hex): {}\n", hex::encode(root)));
  out.push_str(&format!("leaf count: {}\n", prover_commitment.leaf_hashes.len()));

  out.push_str("\n[Prove]\n");
  out.push_str(&format!(
    "proof payload: p_eval_len={}, p_random_count={}, opened_cols={}\n",
    proof.p_eval.len(),
    proof.p_random_vec.len(),
    proof.columns.len()
  ));
  out.push_str(&format!(
    "p_eval: {:?}\n",
    proof.p_eval.iter().map(|x| x.0).collect::<Vec<_>>()
  ));
  out.push_str(&format!(
    "opened col indices: {:?}\n",
    proof.columns.iter().map(|c| c.col_idx).collect::<Vec<_>>()
  ));
  for (i, col) in proof.columns.iter().enumerate() {
    out.push_str(&format!(
      "  opening[{}]: col={}, values(first 4)={:?}, path_len={}\n",
      i,
      col.col_idx,
      col.values.iter().take(4).map(|x| x.0).collect::<Vec<_>>(),
      col.merkle_path.len()
    ));
  }

  out.push_str("\n[Verify]\n");
  out.push_str(&format!("claimed eval: {}\n", claimed_eval.0));
  out.push_str("verify: success (claimed evaluation accepted)\n");
  out.push_str(
    "meaning: opened columns are Merkle-authenticated and consistent with collapsed checks\n",
  );
  out.push_str("\n[format]\n");
  out.push_str("- leaf hash input: H(zero_digest || column values serialized as LE u64)\n");
  out.push_str("- internal hash input: H(left_hash || right_hash)\n");
  out.push_str("- opening payload: (column index, column values, merkle sibling path)\n");

  Ok(out)
}

pub fn run_brakedown_trace() -> Result<()> {
  let report = build_brakedown_demo_report()?;
  println!("\n{}", report);
  Ok(())
}
