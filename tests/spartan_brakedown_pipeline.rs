use std::{path::PathBuf, time::Instant};

use merlin::Transcript;
use zk_linear::{
  api::spartan_like::build_spartan_like_report_data_from_dir,
  core::field::Fp,
  pcs::{
    brakedown::{
      BrakedownPcs,
      types::BrakedownParams,
    },
    traits::PolynomialCommitmentScheme,
  },
  sumcheck::{
    inner::verify_inner_sumcheck_trace,
    outer::verify_outer_sumcheck_trace,
  },
};

fn case_dir() -> PathBuf {
  PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/inner_sumcheck_spartan")
}

#[test]
fn spartan_brakedown_style_pipeline_main_like() {
  println!("=== Spartan + Brakedown Style Pipeline (Research Bridge) ===");
  println!("\n[Scope]");
  println!("- This is NOT full Spartan2 NIZK integration.");
  println!("- It is a staged software bridge: Spartan-like prove outputs -> Brakedown-style PCS commit/open/verify.");

  // ---------------- K0: Input ----------------
  let t0 = Instant::now();
  let dir = case_dir();
  let data = build_spartan_like_report_data_from_dir(&dir).expect("spartan-like data build should succeed");
  let k0_ms = t0.elapsed().as_secs_f64() * 1000.0;

  println!("\n[Kernel K0: Input Parse]");
  println!("input source: tests/inner_sumcheck_spartan/_A.data, _B.data, _C.data, _z.data");
  println!("rows={}, cols={}, z_len={}", data.case.a.len(), data.case.a[0].len(), data.case.z.len());
  println!(
    "A={:?}",
    data.case
      .a
      .iter()
      .map(|r| r.iter().map(|x| x.0).collect::<Vec<_>>())
      .collect::<Vec<_>>()
  );
  println!(
    "B={:?}",
    data.case
      .b
      .iter()
      .map(|r| r.iter().map(|x| x.0).collect::<Vec<_>>())
      .collect::<Vec<_>>()
  );
  println!(
    "C={:?}",
    data.case
      .c
      .iter()
      .map(|r| r.iter().map(|x| x.0).collect::<Vec<_>>())
      .collect::<Vec<_>>()
  );
  println!("z={:?}", data.case.z.iter().map(|x| x.0).collect::<Vec<_>>());
  println!("time: {:.3} ms", k0_ms);
  println!("payload -> K1: {{A, B, C, z}} [source=parsed input files]");

  // ---------------- K1: Spartan Prove ----------------
  let t1 = Instant::now();
  let outer_rounds = data.outer_trace.rounds.len();
  let inner_rounds = data.joint_trace.rounds.len();
  let claim_outer = data.outer_trace.claim_initial;
  let claim_inner = data.joint_trace.claim_initial;
  let r_x = data.r_x.clone();
  let row_weights = data.row_weights.clone();
  let gamma = data.gamma;
  let gamma_sq = data.gamma_sq;
  let a_bound = data.a_bound.clone();
  let b_bound = data.b_bound.clone();
  let c_bound = data.c_bound.clone();
  let joint_bound = data.joint_bound.clone();
  let k1_ms = t1.elapsed().as_secs_f64() * 1000.0;

  println!("\n[Kernel K1: Spartan-like Prove Core]");
  println!("input source: payload from K0");
  println!("outer claim C0=sum(eq(tau)*residual)={}", claim_outer.0);
  println!("outer rounds={}, r_x={:?}", outer_rounds, r_x.iter().map(|x| x.0).collect::<Vec<_>>());
  println!(
    "row weights eq(r_x)={:?}",
    row_weights.iter().map(|x| x.0).collect::<Vec<_>>()
  );
  println!("gamma={} (gamma^2={})", gamma.0, gamma_sq.0);
  println!("A_bound={:?}", a_bound.iter().map(|x| x.0).collect::<Vec<_>>());
  println!("B_bound={:?}", b_bound.iter().map(|x| x.0).collect::<Vec<_>>());
  println!("C_bound={:?}", c_bound.iter().map(|x| x.0).collect::<Vec<_>>());
  println!("joint_bound={:?}", joint_bound.iter().map(|x| x.0).collect::<Vec<_>>());
  println!("joint inner claim C0=<joint_bound,z>={}", claim_inner.0);
  println!("inner rounds={}", inner_rounds);
  println!("time: {:.3} ms", k1_ms);

  println!("payload -> K2 (PCS commit/open):");
  println!("  coeff rows=[A_bound, B_bound, C_bound] [source=K1 row binding]");
  println!("  outer tensor=[1, gamma, gamma^2] [source=K1 challenge]");
  println!("  inner tensor=z [source=K0 input]");
  println!("  claimed value=<joint_bound,z>={} [source=K1 inner claim]", claim_inner.0);

  // ---------------- K2: Brakedown PCS Prove ----------------
  let t2 = Instant::now();
  let n_per_row = a_bound.len();
  let params = BrakedownParams::new(n_per_row);
  let pcs = BrakedownPcs::new(params.clone());

  let mut coeffs = Vec::with_capacity(3 * n_per_row);
  coeffs.extend_from_slice(&a_bound);
  coeffs.extend_from_slice(&b_bound);
  coeffs.extend_from_slice(&c_bound);

  let prover_commitment = pcs.commit(&coeffs).expect("pcs commit should succeed");
  let verifier_commitment = pcs.verifier_commitment(&prover_commitment);

  let outer_tensor = vec![Fp::new(1), gamma, gamma_sq];
  let inner_tensor = data.case.z.clone();

  let mut tr_p = Transcript::new(b"spartan-brakedown-bridge");
  tr_p.append_message(b"polycommit", &verifier_commitment.root);
  tr_p.append_message(b"ncols", &(pcs.encoding.n_cols as u64).to_be_bytes());
  let proof = pcs
    .open(&prover_commitment, &outer_tensor, &mut tr_p)
    .expect("pcs open should succeed");

  let k2_ms = t2.elapsed().as_secs_f64() * 1000.0;

  println!("\n[Kernel K2: Brakedown-style Commit/Open Prove]");
  println!("input source: payload from K1");
  println!(
    "coeff matrix dims: rows={}, per_row={}, encoded_cols={}",
    prover_commitment.n_rows, prover_commitment.n_per_row, prover_commitment.n_cols
  );
  println!(
    "commitment(root)={}",
    hex::encode(verifier_commitment.root)
  );
  println!(
    "proof payload: p_eval_len={}, p_random_count={}, opened_cols={}",
    proof.p_eval.len(),
    proof.p_random_vec.len(),
    proof.columns.len()
  );
  println!(
    "opened col indices={:?}",
    proof.columns.iter().map(|c| c.col_idx).collect::<Vec<_>>()
  );
  println!("time: {:.3} ms", k2_ms);

  println!("payload -> K3 (Verifier):");
  println!("  from K2 generated: verifier_commitment(root,dims), opening proof");
  println!("  from K1 generated: outer_tensor=[1,gamma,gamma^2], claimed_value={}", claim_inner.0);
  println!("  from K0 input: inner_tensor=z");

  // ---------------- K3: Verify ----------------
  let t3 = Instant::now();

  let outer_v = verify_outer_sumcheck_trace(&data.outer_trace);
  let inner_v = verify_inner_sumcheck_trace(&data.joint_trace);

  let mut tr_v = Transcript::new(b"spartan-brakedown-bridge");
  tr_v.append_message(b"polycommit", &verifier_commitment.root);
  tr_v.append_message(b"ncols", &(pcs.encoding.n_cols as u64).to_be_bytes());
  pcs.verify(
    &verifier_commitment,
    &proof,
    &outer_tensor,
    &inner_tensor,
    claim_inner,
    &mut tr_v,
  )
  .expect("pcs verify should succeed");

  let k3_ms = t3.elapsed().as_secs_f64() * 1000.0;

  println!("\n[Kernel K3: Verify]");
  println!("input source: payload from K2 + tensors/claim from K1/K0");
  println!(
    "Spartan outer verify: final_ok={}, verifier_claim={}, trace_claim={}",
    outer_v.final_consistent,
    outer_v.final_claim_from_verifier.0,
    outer_v.final_claim_from_trace.0
  );
  println!(
    "Spartan inner verify: final_ok={}, verifier_claim={}, trace_claim={}",
    inner_v.final_consistent,
    inner_v.final_claim_from_verifier.0,
    inner_v.final_claim_from_trace.0
  );
  println!(
    "PCS verify: success for claimed_value={} with Merkle openings + encoded checks",
    claim_inner.0
  );
  println!("time: {:.3} ms", k3_ms);

  let total_ms = k0_ms + k1_ms + k2_ms + k3_ms;
  println!("\n[Summary]");
  println!("K0 Input Parse: {:.3} ms", k0_ms);
  println!("K1 Spartan Prove Core: {:.3} ms", k1_ms);
  println!("K2 Brakedown Commit/Open Prove: {:.3} ms", k2_ms);
  println!("K3 Verify: {:.3} ms", k3_ms);
  println!("TOTAL: {:.3} ms", total_ms);

  assert!(outer_v.final_consistent, "outer sumcheck verify should pass");
  assert!(inner_v.final_consistent, "inner sumcheck verify should pass");
}
