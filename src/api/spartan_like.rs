use std::path::Path;

use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::{
  core::field::{Fp, MODULUS},
  io::case_format::load_spartan_like_case_from_dir,
  sumcheck::{
    inner::{inner_product, prove_inner_sumcheck_with_label, verify_inner_sumcheck_trace},
    outer::prove_outer_sumcheck,
  },
};

fn matrix_vec_mul(m: &[Vec<Fp>], z: &[Fp]) -> Vec<Fp> {
  m.iter().map(|row| inner_product(row, z)).collect()
}

fn derive_joint_challenge(az: &[Fp], bz: &[Fp], cz: &[Fp]) -> Fp {
  let mut h = Sha256::new();
  h.update(b"spartan-like-joint-challenge");
  for v in az.iter().chain(bz.iter()).chain(cz.iter()) {
    h.update(v.0.to_be_bytes());
  }
  let out: [u8; 32] = h.finalize().into();
  Fp::from_challenge(out)
}

fn build_eq_weights_from_challenges(chals: &[Fp]) -> Vec<Fp> {
  // weights = EqPolynomial::evals_from_points(chals) equivalent:
  // start [1], for each r: [w*(1-r), w*r]
  let mut w = vec![Fp::new(1)];
  for r in chals {
    let one_minus_r = Fp::new(1).sub(*r);
    let mut nxt = Vec::with_capacity(w.len() * 2);
    for wi in &w {
      nxt.push(wi.mul(one_minus_r));
      nxt.push(wi.mul(*r));
    }
    w = nxt;
  }
  w
}

fn build_eq_weights_trace(chals: &[Fp]) -> Vec<Vec<Fp>> {
  let mut states = Vec::new();
  let mut w = vec![Fp::new(1)];
  states.push(w.clone());
  for r in chals {
    let one_minus_r = Fp::new(1).sub(*r);
    let mut nxt = Vec::with_capacity(w.len() * 2);
    for wi in &w {
      nxt.push(wi.mul(one_minus_r));
      nxt.push(wi.mul(*r));
    }
    w = nxt;
    states.push(w.clone());
  }
  states
}

fn bind_rows(matrix: &[Vec<Fp>], weights: &[Fp]) -> Vec<Fp> {
  let cols = matrix[0].len();
  let mut out = vec![Fp::zero(); cols];
  for (row, w) in matrix.iter().zip(weights.iter()) {
    for j in 0..cols {
      out[j] = out[j].add(row[j].mul(*w));
    }
  }
  out
}

fn explain_bound(name: &str, matrix: &[Vec<Fp>], weights: &[Fp], bound: &[Fp]) -> String {
  let mut s = String::new();
  s.push_str(&format!("{}[j] = sum_i eq_i * {}[i][j]\n", name, name));
  for j in 0..bound.len() {
    let mut terms = Vec::new();
    for i in 0..matrix.len() {
      if matrix[i][j] != Fp::zero() {
        terms.push(format!("{}*{}", weights[i].0, matrix[i][j].0));
      }
    }
    if terms.is_empty() {
      terms.push("0".to_string());
    }
    s.push_str(&format!(
      "  {}[{}] = ({}) mod {} = {}\n",
      name,
      j,
      terms.join(" + "),
      MODULUS,
      bound[j].0
    ));
  }
  s
}

fn fmt_vec(v: &[Fp]) -> String {
  format!("{:?}", v.iter().map(|x| x.0).collect::<Vec<_>>())
}

fn fmt_matrix(m: &[Vec<Fp>]) -> String {
  let rows: Vec<String> = m.iter().map(|row| fmt_vec(row)).collect();
  format!("[\n  {}\n]", rows.join(",\n  "))
}

pub fn build_spartan_like_report_from_dir(case_dir: &Path) -> Result<String> {
  let case = load_spartan_like_case_from_dir(case_dir)?;

  let az = matrix_vec_mul(&case.a, &case.z);
  let bz = matrix_vec_mul(&case.b, &case.z);
  let cz = matrix_vec_mul(&case.c, &case.z);

  let residual: Vec<Fp> = az
    .iter()
    .zip(bz.iter())
    .zip(cz.iter())
    .map(|((a, b), c)| a.mul(*b).sub(*c))
    .collect();

  let outer_trace = prove_outer_sumcheck(&residual);

  let gamma = derive_joint_challenge(&az, &bz, &cz);
  let gamma_sq = gamma.mul(gamma);

  let mut out = String::new();
  out.push_str("=== Spartan-like R1CS Sumcheck Report ===\n");
  out.push_str("--------------------------------------------------\n");
  out.push_str("\n[Info]\n");
  out.push_str(&format!("field: F_{}\n", MODULUS));
  out.push_str("hash/transcript: SHA-256 Fiat-Shamir\n");
  out.push_str(&format!(
    "outer challenge format: r = H(\"spartan-outer-sumcheck\", round, sum_low, sum_high, 0) mod {}\n",
    MODULUS
  ));
  out.push_str(&format!(
    "inner challenge format: r = H(label, round, h0, h1, h2) mod {}\n",
    MODULUS
  ));
  out.push_str(&format!("shape: rows={}, cols={}\n", case.a.len(), case.a[0].len()));
  out.push_str(&format!("z: {}\n", fmt_vec(&case.z)));
  out.push_str(&format!("A:\n{}\n", fmt_matrix(&case.a)));
  out.push_str(&format!("B:\n{}\n", fmt_matrix(&case.b)));
  out.push_str(&format!("C:\n{}\n", fmt_matrix(&case.c)));

  out.push_str("\n[Claim]\n");
  out.push_str(&format!("Az = A*z = {}\n", fmt_vec(&az)));
  out.push_str(&format!("Bz = B*z = {}\n", fmt_vec(&bz)));
  out.push_str(&format!("Cz = C*z = {}\n", fmt_vec(&cz)));
  out.push_str(&format!("residual = Az*Bz-Cz = {}\n", fmt_vec(&residual)));
  out.push_str("--------------------------------------------------\n");

  out.push_str("\n[Outer Prove]\n");
  out.push_str(&format!(
    "initial claim C0 = sum(residual) = {}\n",
    outer_trace.claim_initial.0
  ));
  for r in &outer_trace.rounds {
    let folded_sum = r.folded_values.iter().fold(Fp::zero(), |acc, v| acc.add(*v));
    out.push_str(&format!(
      "  round {} -> low_sum={}, high_sum={}, challenge_r=hash({}, {}, {}, 0)={}\n",
      r.round,
      r.sum_low.0,
      r.sum_high.0,
      r.round,
      r.sum_low.0,
      r.sum_high.0,
      r.challenge_r.0
    ));
    out.push_str(&format!(
      "    folded residual = {:?}\n",
      r.folded_values.iter().map(|x| x.0).collect::<Vec<_>>()
    ));
    out.push_str(&format!(
      "    next claim (from folded residual sum) = {}\n",
      folded_sum.0
    ));
  }
  out.push_str(&format!(
    "outer prove end: final_value={} | final_claim={}\n",
    outer_trace.final_value.0, outer_trace.final_claim.0
  ));
  out.push_str("--------------------------------------------------\n");

  // Spartan-like dependency: inner phase uses row-binding challenges from outer phase.
  let r_x: Vec<Fp> = outer_trace.rounds.iter().map(|rr| rr.challenge_r).collect();
  let row_weights = build_eq_weights_from_challenges(&r_x);
  let eq_states = build_eq_weights_trace(&r_x);
  out.push_str("\n[Dependency]\n");
  out.push_str("Inner phase depends on outer challenges r_x.\n");
  out.push_str("r_x is NOT newly sampled; it reuses outer-round Fiat-Shamir challenges.\n");
  for rr in &outer_trace.rounds {
    out.push_str(&format!(
      "  r_x[{}] = H(\"spartan-outer-sumcheck\", {}, {}, {}, 0) mod {} = {}\n",
      rr.round,
      rr.round,
      rr.sum_low.0,
      rr.sum_high.0,
      MODULUS,
      rr.challenge_r.0
    ));
  }
  out.push_str(&format!("r_x = {}\n", fmt_vec(&r_x)));
  out.push_str("eq(r_x) weights are built by iterative split with w.\n");
  out.push_str("  start: w^(0) = [1]\n");
  for (i, r) in r_x.iter().enumerate() {
    let one_minus_r = Fp::new(1).sub(*r);
    out.push_str(&format!(
      "  step {} with r_x[{}]={}: each w -> [w*(1-r), w*r], where (1-r)={}\n",
      i, i, r.0, one_minus_r.0
    ));
    out.push_str(&format!("    w^({}) = {}\n", i + 1, fmt_vec(&eq_states[i + 1])));
  }
  out.push_str(&format!("eq(r_x) row weights = {}\n", fmt_vec(&row_weights)));
  out.push_str("--------------------------------------------------\n");

  let a_bound = bind_rows(&case.a, &row_weights);
  let b_bound = bind_rows(&case.b, &row_weights);
  let c_bound = bind_rows(&case.c, &row_weights);

  out.push_str("\n[Inner Prove: Spartan-like JOINT path]\n");
  out.push_str("joint challenge is Fiat-Shamir sampled from (Az || Bz || Cz).\n");
  out.push_str(&format!(
    "gamma = H(\"spartan-like-joint-challenge\", Az, Bz, Cz) mod {} = {}\n",
    MODULUS, gamma.0
  ));
  out.push_str(&format!(
    "  Az input = {}\n  Bz input = {}\n  Cz input = {}\n",
    fmt_vec(&az),
    fmt_vec(&bz),
    fmt_vec(&cz)
  ));
  out.push_str(&format!("gamma^2 mod {} = {}\n", MODULUS, gamma_sq.0));
  out.push_str(&explain_bound("A", &case.a, &row_weights, &a_bound));
  out.push_str(&explain_bound("B", &case.b, &row_weights, &b_bound));
  out.push_str(&explain_bound("C", &case.c, &row_weights, &c_bound));
  out.push_str(&format!("A_bound = {}\n", fmt_vec(&a_bound)));
  out.push_str(&format!("B_bound = {}\n", fmt_vec(&b_bound)));
  out.push_str(&format!("C_bound = {}\n", fmt_vec(&c_bound)));

  let joint_bound: Vec<Fp> = a_bound
    .iter()
    .zip(b_bound.iter())
    .zip(c_bound.iter())
    .map(|((a, b), c)| a.add(gamma.mul(*b)).add(gamma_sq.mul(*c)))
    .collect();
  out.push_str(&format!(
    "joint_bound = A_bound + gamma*B_bound + gamma^2*C_bound = {}\n",
    fmt_vec(&joint_bound)
  ));

  let joint_trace = prove_inner_sumcheck_with_label(&joint_bound, &case.z, b"spartan-inner-joint");
  let joint_verify = verify_inner_sumcheck_trace(&joint_trace);
  out.push_str(&format!("joint initial claim = {}\n", joint_trace.claim_initial.0));
  for rr in &joint_trace.rounds {
    out.push_str(&format!(
      "  round {} -> h0={}, h1={}, h2={}, challenge_r=hash({}, {}, {}, {})={}\n",
      rr.round,
      rr.h_at_0.0,
      rr.h_at_1.0,
      rr.h_at_2.0,
      rr.round,
      rr.h_at_0.0,
      rr.h_at_1.0,
      rr.h_at_2.0,
      rr.challenge_r.0
    ));
    out.push_str(&format!(
      "    folded f={} | folded g={}\n",
      fmt_vec(&rr.folded_f),
      fmt_vec(&rr.folded_g)
    ));
  }
  out.push_str("--------------------------------------------------\n");

  out.push_str("\n[Proof Payload]\n");
  out.push_str("Values verifier needs (recomputing Fiat-Shamir challenges locally):\n");
  out.push_str(&format!("  outer initial claim: {}\n", outer_trace.claim_initial.0));
  out.push_str("  outer rounds: [(low_sum, high_sum)]\n");
  out.push_str("  outer-derived point: r_x (from outer transcript)\n");
  out.push_str("  eq(r_x) row weights (recomputed from r_x)\n");
  out.push_str(&format!("  inner initial claim: {}\n", joint_trace.claim_initial.0));
  out.push_str("  inner rounds: [(h0, h1, h2)]\n");
  out.push_str(&format!(
    "  final opening values: final_f={}, final_g={}, final_claim={}\n",
    joint_trace.final_f.0, joint_trace.final_g.0, joint_trace.final_claim.0
  ));
  out.push_str("--------------------------------------------------\n");

  out.push_str("\n[Verify]\n");
  let mut outer_verify_claim = outer_trace.claim_initial;
  out.push_str("outer verify checks:\n");
  for r in &outer_trace.rounds {
    let h01 = r.sum_low.add(r.sum_high);
    let folded_sum = r.folded_values.iter().fold(Fp::zero(), |acc, v| acc.add(*v));
    let expected_next_claim = if let Some(next_round) = outer_trace.rounds.get(r.round + 1) {
      next_round.sum_low.add(next_round.sum_high)
    } else {
      outer_trace.final_claim
    };
    let transition_ok = folded_sum == expected_next_claim;
    out.push_str(&format!(
      "  round {}: claim_in={} | low+high={} | claim_ok={}\n",
      r.round,
      outer_verify_claim.0,
      h01.0,
      outer_verify_claim == h01
    ));
    out.push_str(&format!(
      "           r={} -> next_claim_from_fold={} | transition_ok={}\n",
      r.challenge_r.0,
      folded_sum.0,
      transition_ok
    ));
    outer_verify_claim = folded_sum;
  }
  out.push_str(&format!(
    "  outer final: verifier_claim={} | trace_final_claim={} | ok={}\n",
    outer_verify_claim.0,
    outer_trace.final_claim.0,
    outer_verify_claim == outer_trace.final_claim
  ));

  out.push_str("inner verify checks:\n");
  for vr in &joint_verify.rounds {
    out.push_str(&format!(
      "  round {}: claim_in={} | h0+h1={} | claim_ok={}\n",
      vr.round, vr.claim_in.0, vr.expected_claim_from_h01.0, vr.claim_consistent
    ));
    out.push_str(&format!(
      "           r={} -> h(r)={} | folded_claim={} | transition_ok={}\n",
      vr.challenge_r.0, vr.hr_from_interpolation.0, vr.folded_claim_from_vectors.0, vr.transition_consistent
    ));
  }
  out.push_str(&format!(
    "  final check: final_f*final_g={}*{}={} | trace_final_claim={}\n",
    joint_trace.final_f.0,
    joint_trace.final_g.0,
    joint_trace.final_f.mul(joint_trace.final_g).0,
    joint_trace.final_claim.0
  ));
  out.push_str(&format!(
    "  verifier final claim={} | trace final claim={} | ok={}\n",
    joint_verify.final_claim_from_verifier.0,
    joint_trace.final_claim.0,
    joint_verify.final_consistent
  ));
  out.push_str("--------------------------------------------------\n");

  out.push_str("\n[Compare: Separate A/B/C Inner Paths]\n");
  let a_trace = prove_inner_sumcheck_with_label(&a_bound, &case.z, b"spartan-inner-A");
  let b_trace = prove_inner_sumcheck_with_label(&b_bound, &case.z, b"spartan-inner-B");
  let c_trace = prove_inner_sumcheck_with_label(&c_bound, &case.z, b"spartan-inner-C");
  out.push_str(&format!(
    "A path initial/final: {}/{}\n",
    a_trace.claim_initial.0, a_trace.final_claim.0
  ));
  out.push_str(&format!(
    "B path initial/final: {}/{}\n",
    b_trace.claim_initial.0, b_trace.final_claim.0
  ));
  out.push_str(&format!(
    "C path initial/final: {}/{}\n",
    c_trace.claim_initial.0, c_trace.final_claim.0
  ));
  out.push_str("Note: Spartan proof path uses the JOINT inner sumcheck, not three separate proofs.\n");

  Ok(out)
}
