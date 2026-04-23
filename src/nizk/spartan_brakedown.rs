use std::{path::Path, time::Instant};

use anyhow::{Result, anyhow};
use merlin::Transcript;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

use crate::{
  core::{
    field::{Fp, MODULUS},
    transcript::derive_round_challenge_merlin,
  },
  io::case_format::{SpartanLikeCase, load_spartan_like_case_from_dir},
  pcs::{
    brakedown::{
      BrakedownPcs,
      types::{BrakedownEvalProof, BrakedownParams, BrakedownVerifierCommitment},
    },
    traits::PolynomialCommitmentScheme,
  },
  sumcheck::{
    inner::{
      SumcheckTrace,
      inner_product,
      prove_inner_sumcheck_with_label_and_transcript,
      verify_inner_sumcheck_trace,
    },
    outer::{
      OuterSumcheckTrace,
      prove_outer_sumcheck_with_transcript,
      verify_outer_sumcheck_trace,
    },
  },
};

const NIZK_TRANSCRIPT_LABEL: &[u8] = b"zklinear-spartan-brakedown-nizk";
const JOINT_INNER_LABEL: &[u8] = b"spartan-inner-joint";

#[derive(Debug, Clone)]
pub struct SpartanBrakedownProof {
  pub outer_trace: OuterSumcheckTrace,
  pub inner_trace: SumcheckTrace,
  pub gamma: Fp,
  pub claimed_value: Fp,
  pub blind_eval: Fp,
  pub verifier_commitment: BrakedownVerifierCommitment,
  pub pcs_proof_main: BrakedownEvalProof,
  pub pcs_proof_blind: BrakedownEvalProof,
}

#[derive(Debug, Clone)]
pub struct SpartanBrakedownPublic {
  pub outer_tensor_main: Vec<Fp>,
  pub outer_tensor_blind: Vec<Fp>,
  pub inner_tensor: Vec<Fp>,
  pub claimed_value_unblinded: Fp,
  pub claimed_value_masked: Fp,
}

#[derive(Debug, Clone)]
pub struct KernelTimingMs {
  pub k0_input_parse_ms: f64,
  pub k1_spartan_prove_ms: f64,
  pub k2_pcs_prove_ms: f64,
  pub k3_verify_ms: f64,
}

#[derive(Debug, Clone)]
pub struct SpartanBrakedownPipelineResult {
  pub proof: SpartanBrakedownProof,
  pub public: SpartanBrakedownPublic,
  pub timings: KernelTimingMs,
}

fn append_public_input_to_transcript(tr: &mut Transcript, case: &SpartanLikeCase) {
  tr.append_message(b"rows", &(case.a.len() as u64).to_be_bytes());
  tr.append_message(b"cols", &(case.a[0].len() as u64).to_be_bytes());

  for row in &case.a {
    for v in row {
      tr.append_message(b"A", &v.0.to_be_bytes());
    }
  }
  for row in &case.b {
    for v in row {
      tr.append_message(b"B", &v.0.to_be_bytes());
    }
  }
  for row in &case.c {
    for v in row {
      tr.append_message(b"C", &v.0.to_be_bytes());
    }
  }
  for v in &case.z {
    tr.append_message(b"z", &v.0.to_be_bytes());
  }
}

fn sample_gamma_from_transcript(tr: &mut Transcript, az: &[Fp], bz: &[Fp], cz: &[Fp]) -> Fp {
  tr.append_message(b"gamma_domain", b"spartan-like-joint-challenge");
  for v in az {
    tr.append_message(b"Az", &v.0.to_be_bytes());
  }
  for v in bz {
    tr.append_message(b"Bz", &v.0.to_be_bytes());
  }
  for v in cz {
    tr.append_message(b"Cz", &v.0.to_be_bytes());
  }
  let mut out = [0u8; 32];
  tr.challenge_bytes(b"gamma", &mut out);
  Fp::from_challenge(out)
}

fn derive_outer_tau(num_vars: usize, az: &[Fp], bz: &[Fp], cz: &[Fp], z: &[Fp]) -> Vec<Fp> {
  let mut tau = Vec::with_capacity(num_vars);
  for i in 0..num_vars {
    let mut h = Sha256::new();
    h.update(b"spartan-outer-tau");
    h.update((i as u64).to_be_bytes());
    for v in az.iter().chain(bz.iter()).chain(cz.iter()).chain(z.iter()) {
      h.update(v.0.to_be_bytes());
    }
    let out: [u8; 32] = h.finalize().into();
    tau.push(Fp::from_challenge(out));
  }
  tau
}

fn build_eq_weights_from_challenges(chals: &[Fp]) -> Vec<Fp> {
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

fn flatten_rows(rows: &[Vec<Fp>]) -> Vec<Fp> {
  let total = rows.iter().map(Vec::len).sum();
  let mut out = Vec::with_capacity(total);
  for row in rows {
    out.extend_from_slice(row);
  }
  out
}

fn matrix_vec_mul(m: &[Vec<Fp>], z: &[Fp]) -> Vec<Fp> {
  m.iter().map(|row| inner_product(row, z)).collect()
}

fn sample_blind_vec(len: usize) -> Vec<Fp> {
  let mut rng = ChaCha20Rng::from_entropy();
  (0..len)
    .map(|_| {
      use rand::RngCore;
      Fp::new(rng.next_u64() % MODULUS)
    })
    .collect()
}

pub fn prove_from_dir(case_dir: &Path) -> Result<SpartanBrakedownPipelineResult> {
  let t0 = Instant::now();
  let case = load_spartan_like_case_from_dir(case_dir)?;
  let k0_ms = t0.elapsed().as_secs_f64() * 1000.0;

  let t1 = Instant::now();
  let az = matrix_vec_mul(&case.a, &case.z);
  let bz = matrix_vec_mul(&case.b, &case.z);
  let cz = matrix_vec_mul(&case.c, &case.z);

  let residual: Vec<Fp> = az
    .iter()
    .zip(bz.iter())
    .zip(cz.iter())
    .map(|((a, b), c)| a.mul(*b).sub(*c))
    .collect();

  let row_vars = case.a.len().trailing_zeros() as usize;
  let tau = derive_outer_tau(row_vars, &az, &bz, &cz, &case.z);
  let eq_tau = build_eq_weights_from_challenges(&tau);
  let weighted_residual: Vec<Fp> = residual
    .iter()
    .zip(eq_tau.iter())
    .map(|(r, w)| r.mul(*w))
    .collect();

  let mut tr_p = Transcript::new(NIZK_TRANSCRIPT_LABEL);
  append_public_input_to_transcript(&mut tr_p, &case);

  let outer_trace = prove_outer_sumcheck_with_transcript(&weighted_residual, &mut tr_p);
  let r_x = outer_trace
    .rounds
    .iter()
    .map(|rr| rr.challenge_r)
    .collect::<Vec<_>>();
  let row_weights = build_eq_weights_from_challenges(&r_x);

  let gamma = sample_gamma_from_transcript(&mut tr_p, &az, &bz, &cz);
  let gamma_sq = gamma.mul(gamma);

  let a_bound = bind_rows(&case.a, &row_weights);
  let b_bound = bind_rows(&case.b, &row_weights);
  let c_bound = bind_rows(&case.c, &row_weights);

  let joint_bound: Vec<Fp> = a_bound
    .iter()
    .zip(b_bound.iter())
    .zip(c_bound.iter())
    .map(|((a, b), c)| a.add(gamma.mul(*b)).add(gamma_sq.mul(*c)))
    .collect();

  let inner_trace =
    prove_inner_sumcheck_with_label_and_transcript(&joint_bound, &case.z, JOINT_INNER_LABEL, &mut tr_p);

  let claimed_value_unblinded = inner_product(&joint_bound, &case.z);
  let blind_vec = sample_blind_vec(case.z.len());
  let blind_eval = inner_product(&blind_vec, &case.z);
  let claimed_value_masked = claimed_value_unblinded.add(blind_eval);

  tr_p.append_message(b"claimed_value_unblinded", &claimed_value_unblinded.0.to_be_bytes());
  tr_p.append_message(b"blind_eval", &blind_eval.0.to_be_bytes());
  tr_p.append_message(b"claimed_value_masked", &claimed_value_masked.0.to_be_bytes());

  let k1_ms = t1.elapsed().as_secs_f64() * 1000.0;

  let t2 = Instant::now();
  let coeff_rows = vec![a_bound, b_bound, c_bound, blind_vec];
  let coeffs = flatten_rows(&coeff_rows);

  let params = BrakedownParams::new(case.a[0].len());
  let pcs = BrakedownPcs::new(params);
  let prover_commitment = pcs.commit(&coeffs)?;
  let verifier_commitment = pcs.verifier_commitment(&prover_commitment);

  tr_p.append_message(b"polycommit", &verifier_commitment.root);
  tr_p.append_message(b"ncols", &(pcs.encoding.n_cols as u64).to_be_bytes());

  let outer_tensor_main = vec![Fp::new(1), gamma, gamma_sq, Fp::new(1)];
  let outer_tensor_blind = vec![Fp::zero(), Fp::zero(), Fp::zero(), Fp::new(1)];

  let pcs_proof_main = pcs.open(&prover_commitment, &outer_tensor_main, &mut tr_p)?;
  let pcs_proof_blind = pcs.open(&prover_commitment, &outer_tensor_blind, &mut tr_p)?;
  let k2_ms = t2.elapsed().as_secs_f64() * 1000.0;

  let proof = SpartanBrakedownProof {
    outer_trace,
    inner_trace,
    gamma,
    claimed_value: claimed_value_masked,
    blind_eval,
    verifier_commitment,
    pcs_proof_main,
    pcs_proof_blind,
  };

  let public = SpartanBrakedownPublic {
    outer_tensor_main,
    outer_tensor_blind,
    inner_tensor: case.z,
    claimed_value_unblinded,
    claimed_value_masked,
  };

  let t3 = Instant::now();
  verify_from_dir(case_dir, &proof)?;
  let k3_ms = t3.elapsed().as_secs_f64() * 1000.0;

  Ok(SpartanBrakedownPipelineResult {
    proof,
    public,
    timings: KernelTimingMs {
      k0_input_parse_ms: k0_ms,
      k1_spartan_prove_ms: k1_ms,
      k2_pcs_prove_ms: k2_ms,
      k3_verify_ms: k3_ms,
    },
  })
}

pub fn verify_from_dir(case_dir: &Path, proof: &SpartanBrakedownProof) -> Result<()> {
  let case = load_spartan_like_case_from_dir(case_dir)?;
  let rows = case.a.len();
  let cols = case.a[0].len();

  if proof.outer_trace.rounds.len() != rows.trailing_zeros() as usize {
    return Err(anyhow!("outer rounds do not match row count"));
  }
  if proof.inner_trace.rounds.len() != cols.trailing_zeros() as usize {
    return Err(anyhow!("inner rounds do not match column count"));
  }

  if proof.verifier_commitment.n_rows != 4 || proof.verifier_commitment.n_per_row != cols {
    return Err(anyhow!("verifier commitment dimensions mismatch for blinded layout"));
  }

  let az = matrix_vec_mul(&case.a, &case.z);
  let bz = matrix_vec_mul(&case.b, &case.z);
  let cz = matrix_vec_mul(&case.c, &case.z);
  let residual = az
    .iter()
    .zip(bz.iter())
    .zip(cz.iter())
    .map(|((a, b), c)| a.mul(*b).sub(*c))
    .collect::<Vec<_>>();

  let tau = derive_outer_tau(rows.trailing_zeros() as usize, &az, &bz, &cz, &case.z);
  let eq_tau = build_eq_weights_from_challenges(&tau);
  let weighted_residual = residual
    .iter()
    .zip(eq_tau.iter())
    .map(|(r, w)| r.mul(*w))
    .collect::<Vec<_>>();
  let expected_outer_claim = weighted_residual
    .iter()
    .fold(Fp::zero(), |acc, v| acc.add(*v));
  if expected_outer_claim != proof.outer_trace.claim_initial {
    return Err(anyhow!("outer claim does not match A/B/C/z-derived claim"));
  }

  let mut tr_v = Transcript::new(NIZK_TRANSCRIPT_LABEL);
  append_public_input_to_transcript(&mut tr_v, &case);

  for r in &proof.outer_trace.rounds {
    let expected_r = derive_round_challenge_merlin(
      &mut tr_v,
      b"spartan-outer-sumcheck",
      r.round,
      r.g_at_0,
      r.g_at_2,
      r.g_at_3,
    );
    if expected_r != r.challenge_r {
      return Err(anyhow!("outer challenge mismatch at round {}", r.round));
    }
  }

  let outer_v = verify_outer_sumcheck_trace(&proof.outer_trace);
  if !outer_v.final_consistent {
    return Err(anyhow!("outer sumcheck verification failed"));
  }

  let expected_gamma = sample_gamma_from_transcript(&mut tr_v, &az, &bz, &cz);
  if expected_gamma != proof.gamma {
    return Err(anyhow!("gamma mismatch vs transcript-derived challenge"));
  }

  for r in &proof.inner_trace.rounds {
    let expected_r = derive_round_challenge_merlin(
      &mut tr_v,
      JOINT_INNER_LABEL,
      r.round,
      r.h_at_0,
      r.h_at_1,
      r.h_at_2,
    );
    if expected_r != r.challenge_r {
      return Err(anyhow!("inner challenge mismatch at round {}", r.round));
    }
  }

  let inner_v = verify_inner_sumcheck_trace(&proof.inner_trace);
  if !inner_v.final_consistent {
    return Err(anyhow!("inner sumcheck verification failed"));
  }

  let r_x = proof
    .outer_trace
    .rounds
    .iter()
    .map(|r| r.challenge_r)
    .collect::<Vec<_>>();
  let row_weights = build_eq_weights_from_challenges(&r_x);
  let a_bound = bind_rows(&case.a, &row_weights);
  let b_bound = bind_rows(&case.b, &row_weights);
  let c_bound = bind_rows(&case.c, &row_weights);

  let gamma_sq = proof.gamma.mul(proof.gamma);
  let joint_bound = a_bound
    .iter()
    .zip(b_bound.iter())
    .zip(c_bound.iter())
    .map(|((a, b), c)| a.add(proof.gamma.mul(*b)).add(gamma_sq.mul(*c)))
    .collect::<Vec<_>>();

  let expected_claimed_unblinded = inner_product(&joint_bound, &case.z);
  if proof.inner_trace.claim_initial != expected_claimed_unblinded {
    return Err(anyhow!("inner initial claim mismatch vs bound/input"));
  }

  let expected_masked = expected_claimed_unblinded.add(proof.blind_eval);
  if proof.claimed_value != expected_masked {
    return Err(anyhow!("masked claimed value mismatch"));
  }

  tr_v.append_message(b"claimed_value_unblinded", &expected_claimed_unblinded.0.to_be_bytes());
  tr_v.append_message(b"blind_eval", &proof.blind_eval.0.to_be_bytes());
  tr_v.append_message(b"claimed_value_masked", &proof.claimed_value.0.to_be_bytes());
  tr_v.append_message(b"polycommit", &proof.verifier_commitment.root);
  tr_v.append_message(b"ncols", &(proof.verifier_commitment.n_cols as u64).to_be_bytes());

  let params = BrakedownParams::new(cols);
  let pcs = BrakedownPcs::new(params);
  let inner_tensor = case.z;
  let outer_tensor_main = vec![Fp::new(1), proof.gamma, gamma_sq, Fp::new(1)];
  let outer_tensor_blind = vec![Fp::zero(), Fp::zero(), Fp::zero(), Fp::new(1)];

  pcs.verify(
    &proof.verifier_commitment,
    &proof.pcs_proof_main,
    &outer_tensor_main,
    &inner_tensor,
    proof.claimed_value,
    &mut tr_v,
  )?;

  pcs.verify(
    &proof.verifier_commitment,
    &proof.pcs_proof_blind,
    &outer_tensor_blind,
    &inner_tensor,
    proof.blind_eval,
    &mut tr_v,
  )?;

  Ok(())
}

pub fn build_pipeline_report_from_dir(case_dir: &Path) -> Result<String> {
  let result = prove_from_dir(case_dir)?;
  let proof = &result.proof;
  let public = &result.public;
  let t = &result.timings;

  let mut out = String::new();
  out.push_str("=== Spartan + Brakedown Full-Style NIZK Report (Research) ===\n");
  out.push_str("\n[Scope]\n");
  out.push_str("- modular/unit tests keep SHA path for local arithmetic isolation\n");
  out.push_str("- integrated NIZK path uses single merlin transcript across outer/inner/pcs\n");
  out.push_str("- includes toy ZK blinding layer at PCS evaluation boundary\n");
  out.push_str("- NOTE: this is research/demo code, not production-hardened NIZK\n");

  out.push_str("\n[Prove/Kernels]\n");
  out.push_str("K0 Input Parse:\n");
  out.push_str(&format!("  source: {}\n", case_dir.display()));
  out.push_str(&format!("  time_ms: {:.3}\n", t.k0_input_parse_ms));

  out.push_str("K1 Spartan Prove Core:\n");
  out.push_str(&format!(
    "  output: outer_rounds={}, inner_rounds={}, gamma={}\n",
    proof.outer_trace.rounds.len(),
    proof.inner_trace.rounds.len(),
    proof.gamma.0
  ));
  out.push_str(&format!(
    "  unblinded_claim(inner sumcheck)={}\n",
    public.claimed_value_unblinded.0
  ));
  out.push_str(&format!("  blind_eval={}\n", proof.blind_eval.0));
  out.push_str(&format!("  masked_claim={}\n", proof.claimed_value.0));
  out.push_str(&format!("  time_ms: {:.3}\n", t.k1_spartan_prove_ms));

  out.push_str("K2 Brakedown PCS Commit/Open:\n");
  out.push_str(&format!(
    "  output: root={}\n",
    hex::encode(proof.verifier_commitment.root)
  ));
  out.push_str(&format!(
    "  main payload: p_eval_len={}, p_random_count={}, opening_count={}\n",
    proof.pcs_proof_main.p_eval.len(),
    proof.pcs_proof_main.p_random_vec.len(),
    proof.pcs_proof_main.columns.len()
  ));
  out.push_str(&format!(
    "  blind payload: p_eval_len={}, p_random_count={}, opening_count={}\n",
    proof.pcs_proof_blind.p_eval.len(),
    proof.pcs_proof_blind.p_random_vec.len(),
    proof.pcs_proof_blind.columns.len()
  ));
  out.push_str(&format!("  time_ms: {:.3}\n", t.k2_pcs_prove_ms));

  out.push_str("\n[Payload Prove -> Verify]\n");
  out.push_str("from K1:\n");
  out.push_str("  - outer_trace messages (g0,g2,g3 per round)\n");
  out.push_str("  - inner_trace messages (h0,h1,h2 per round)\n");
  out.push_str(&format!("  - gamma={}\n", proof.gamma.0));
  out.push_str(&format!("  - unblinded_claim={}\n", public.claimed_value_unblinded.0));
  out.push_str(&format!("  - blind_eval={}\n", proof.blind_eval.0));
  out.push_str(&format!("  - masked_claim={}\n", proof.claimed_value.0));
  out.push_str("from K2:\n");
  out.push_str(&format!("  - verifier commitment root={}\n", hex::encode(proof.verifier_commitment.root)));
  out.push_str("  - pcs main opening proof (masked claim)\n");
  out.push_str("  - pcs blind opening proof (blind component)\n");
  out.push_str("public verifier input:\n");
  out.push_str("  - (A,B,C,z) loaded from case_dir\n");
  out.push_str(&format!(
    "  - outer_tensor_main=[1,gamma,gamma^2,1]=[1,{},{},1]\n",
    proof.gamma.0,
    proof.gamma.mul(proof.gamma).0
  ));
  out.push_str("  - outer_tensor_blind=[0,0,0,1]\n");
  out.push_str(&format!(
    "  - inner_tensor(z) len={} (from input)\n",
    public.inner_tensor.len()
  ));

  out.push_str("\n[Verify]\n");
  out.push_str("step 1: replay transcript on (A,B,C,z) + outer rounds and check r_x\n");
  out.push_str("step 2: derive gamma from same transcript and check equality\n");
  out.push_str("step 3: replay transcript on inner rounds and check inner challenges\n");
  out.push_str("step 4: check masked_claim = unblinded_claim + blind_eval\n");
  out.push_str("step 5: verify PCS main opening for masked_claim\n");
  out.push_str("step 6: verify PCS blind opening for blind_eval\n");
  out.push_str(&format!("verify_result: success, masked_claim={}\n", public.claimed_value_masked.0));
  out.push_str(&format!("K3 verify time_ms: {:.3}\n", t.k3_verify_ms));

  out.push_str("\n[Timing Summary]\n");
  out.push_str(&format!("K0: {:.3} ms\n", t.k0_input_parse_ms));
  out.push_str(&format!("K1: {:.3} ms\n", t.k1_spartan_prove_ms));
  out.push_str(&format!("K2: {:.3} ms\n", t.k2_pcs_prove_ms));
  out.push_str(&format!("K3: {:.3} ms\n", t.k3_verify_ms));
  out.push_str(&format!(
    "TOTAL: {:.3} ms\n",
    t.k0_input_parse_ms + t.k1_spartan_prove_ms + t.k2_pcs_prove_ms + t.k3_verify_ms
  ));
  out.push_str(&format!("\nfield: F_{}\n", MODULUS));

  Ok(out)
}
