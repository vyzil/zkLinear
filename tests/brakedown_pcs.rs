use merlin::Transcript;
use zk_linear::{
  core::{
    field::{Fp, MODULUS},
  },
  pcs::{
    brakedown::{
      BrakedownPcs,
      merkle::merkle_root,
      types::BrakedownParams,
    },
    traits::PolynomialCommitmentScheme,
  },
};

fn build_tensors(n_rows: usize, n_per_row: usize) -> (Vec<Fp>, Vec<Fp>) {
  let x = Fp::new(7);

  let mut inner = Vec::with_capacity(n_per_row);
  let mut p = Fp::new(1);
  for _ in 0..n_per_row {
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

  (outer, inner)
}

fn fixture() -> (BrakedownPcs, Vec<Fp>) {
  let params = BrakedownParams::new(8);
  let pcs = BrakedownPcs::new(params.clone());
  let n_rows = 4;
  let coeffs: Vec<Fp> = (0..(n_rows * params.n_per_row))
    .map(|i| Fp::new(((i as u64) * 13 + 5) % MODULUS))
    .collect();
  (pcs, coeffs)
}

#[test]
fn brakedown_end_to_end_succeeds() {
  let (pcs, coeffs) = fixture();
  let prover_commitment = pcs.commit(&coeffs).expect("commit should succeed");
  let verifier_commitment = pcs.verifier_commitment(&prover_commitment);

  let (outer, inner) = build_tensors(prover_commitment.n_rows, prover_commitment.n_per_row);

  let root = merkle_root(&prover_commitment.merkle_nodes);
  let mut tr_p = Transcript::new(b"mini-brakedown-demo");
  tr_p.append_message(b"polycommit", &root);
  tr_p.append_message(b"ncols", &(pcs.encoding.n_cols as u64).to_be_bytes());

  let proof = pcs
    .open(&prover_commitment, &outer, &mut tr_p)
    .expect("open should succeed");

  let mut tr_v = Transcript::new(b"mini-brakedown-demo");
  tr_v.append_message(b"polycommit", &root);
  tr_v.append_message(b"ncols", &(pcs.encoding.n_cols as u64).to_be_bytes());

  let eval = pcs
    .verify(&verifier_commitment, &proof, &outer, &inner, &mut tr_v)
    .expect("verify should succeed");

  assert_ne!(eval, Fp::zero());
  assert_eq!(proof.columns.len(), pcs.params.n_col_opens);
  let mut uniq = proof.columns.iter().map(|c| c.col_idx).collect::<Vec<_>>();
  uniq.sort_unstable();
  uniq.dedup();
  assert_eq!(uniq.len(), pcs.params.n_col_opens);
}

#[test]
fn brakedown_verify_fails_on_tampered_column_value() {
  let (pcs, coeffs) = fixture();
  let prover_commitment = pcs.commit(&coeffs).expect("commit should succeed");
  let verifier_commitment = pcs.verifier_commitment(&prover_commitment);
  let (outer, inner) = build_tensors(prover_commitment.n_rows, prover_commitment.n_per_row);

  let root = merkle_root(&prover_commitment.merkle_nodes);
  let mut tr_p = Transcript::new(b"mini-brakedown-demo");
  tr_p.append_message(b"polycommit", &root);
  tr_p.append_message(b"ncols", &(pcs.encoding.n_cols as u64).to_be_bytes());
  let mut proof = pcs
    .open(&prover_commitment, &outer, &mut tr_p)
    .expect("open should succeed");

  proof.columns[0].values[0] = proof.columns[0].values[0].add(Fp::new(1));

  let mut tr_v = Transcript::new(b"mini-brakedown-demo");
  tr_v.append_message(b"polycommit", &root);
  tr_v.append_message(b"ncols", &(pcs.encoding.n_cols as u64).to_be_bytes());

  let err = pcs
    .verify(&verifier_commitment, &proof, &outer, &inner, &mut tr_v)
    .expect_err("verify should fail for tampered column value");

  assert!(
    err.to_string().contains("degree-test")
      || err.to_string().contains("eval column")
      || err.to_string().contains("merkle path")
  );
}

#[test]
fn brakedown_verify_fails_on_tampered_merkle_path() {
  let (pcs, coeffs) = fixture();
  let prover_commitment = pcs.commit(&coeffs).expect("commit should succeed");
  let verifier_commitment = pcs.verifier_commitment(&prover_commitment);
  let (outer, inner) = build_tensors(prover_commitment.n_rows, prover_commitment.n_per_row);

  let root = merkle_root(&prover_commitment.merkle_nodes);
  let mut tr_p = Transcript::new(b"mini-brakedown-demo");
  tr_p.append_message(b"polycommit", &root);
  tr_p.append_message(b"ncols", &(pcs.encoding.n_cols as u64).to_be_bytes());
  let mut proof = pcs
    .open(&prover_commitment, &outer, &mut tr_p)
    .expect("open should succeed");

  proof.columns[0].merkle_path[0][0] ^= 1;

  let mut tr_v = Transcript::new(b"mini-brakedown-demo");
  tr_v.append_message(b"polycommit", &root);
  tr_v.append_message(b"ncols", &(pcs.encoding.n_cols as u64).to_be_bytes());

  let err = pcs
    .verify(&verifier_commitment, &proof, &outer, &inner, &mut tr_v)
    .expect_err("verify should fail for tampered merkle path");

  assert!(err.to_string().contains("merkle path"));
}
