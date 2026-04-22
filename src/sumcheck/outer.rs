use crate::core::{field::Fp, transcript::derive_round_challenge};

#[derive(Debug, Clone)]
pub struct OuterRoundTranscript {
  pub round: usize,
  pub g_at_0: Fp,
  pub g_at_2: Fp,
  pub g_at_3: Fp,
  pub challenge_r: Fp,
  pub folded_values: Vec<Fp>,
}

#[derive(Debug, Clone)]
pub struct OuterSumcheckTrace {
  pub claim_initial: Fp,
  pub rounds: Vec<OuterRoundTranscript>,
  pub final_value: Fp,
  pub final_claim: Fp,
}

#[derive(Debug, Clone)]
pub struct OuterVerifyRoundTrace {
  pub round: usize,
  pub claim_in: Fp,
  pub g0: Fp,
  pub g1_derived: Fp,
  pub g2: Fp,
  pub g3: Fp,
  pub challenge_r: Fp,
  pub gr_from_interpolation: Fp,
  pub folded_claim_from_vectors: Fp,
  pub claim_consistent: bool,
  pub transition_consistent: bool,
}

#[derive(Debug, Clone)]
pub struct OuterVerifyTrace {
  pub rounds: Vec<OuterVerifyRoundTrace>,
  pub final_claim_from_verifier: Fp,
  pub final_claim_from_trace: Fp,
  pub final_consistent: bool,
}

fn eval_cubic_from_0_1_2_3(g0: Fp, g1: Fp, g2: Fp, g3: Fp, r: Fp) -> Fp {
  // Lagrange interpolation on points 0,1,2,3 over F_97.
  // L0 = -(r-1)(r-2)(r-3)/6
  // L1 =  r(r-2)(r-3)/2
  // L2 = -r(r-1)(r-3)/2
  // L3 =  r(r-1)(r-2)/6
  let one = Fp::new(1);
  let two = Fp::new(2);
  let three = Fp::new(3);
  let six_inv = Fp::new(81); // inverse of 6 mod 97
  let two_inv = Fp::new(49); // inverse of 2 mod 97

  let l0 = Fp::zero()
    .sub(r.sub(one).mul(r.sub(two)).mul(r.sub(three)).mul(six_inv));
  let l1 = r.mul(r.sub(two)).mul(r.sub(three)).mul(two_inv);
  let l2 = Fp::zero().sub(r.mul(r.sub(one)).mul(r.sub(three)).mul(two_inv));
  let l3 = r.mul(r.sub(one)).mul(r.sub(two)).mul(six_inv);

  g0.mul(l0).add(g1.mul(l1)).add(g2.mul(l2)).add(g3.mul(l3))
}

pub fn prove_outer_sumcheck(values: &[Fp]) -> OuterSumcheckTrace {
  assert!(!values.is_empty());
  assert!(values.len().is_power_of_two());

  let mut cur = values.to_vec();
  let mut claim = cur.iter().fold(Fp::zero(), |acc, v| acc.add(*v));
  let claim_initial = claim;
  let mut rounds = Vec::new();
  let mut round = 0usize;

  while cur.len() > 1 {
    let half = cur.len() / 2;
    let (low, high) = cur.split_at(half);
    let g0 = low.iter().fold(Fp::zero(), |acc, v| acc.add(*v));
    let g1 = high.iter().fold(Fp::zero(), |acc, v| acc.add(*v));
    assert_eq!(claim, g0.add(g1));

    // In this simplified setting, g(t) is linear; we still publish g(0), g(2), g(3)
    // to match Spartan-style message shape where verifier derives g(1) from claim.
    let delta = g1.sub(g0);
    let g2 = g0.add(delta.mul(Fp::new(2)));
    let g3 = g0.add(delta.mul(Fp::new(3)));

    let r = derive_round_challenge(
      b"spartan-outer-sumcheck",
      round,
      g0,
      g2,
      g3,
    );

    let folded_values: Vec<Fp> = low
      .iter()
      .zip(high.iter())
      .map(|(l, h)| l.add(r.mul(h.sub(*l))))
      .collect();

    claim = folded_values.iter().fold(Fp::zero(), |acc, v| acc.add(*v));

    rounds.push(OuterRoundTranscript {
      round,
      g_at_0: g0,
      g_at_2: g2,
      g_at_3: g3,
      challenge_r: r,
      folded_values: folded_values.clone(),
    });

    cur = folded_values;
    round += 1;
  }

  OuterSumcheckTrace {
    claim_initial,
    rounds,
    final_value: cur[0],
    final_claim: claim,
  }
}

pub fn verify_outer_sumcheck_trace(trace: &OuterSumcheckTrace) -> OuterVerifyTrace {
  let mut claim = trace.claim_initial;
  let mut rounds = Vec::new();

  for r in &trace.rounds {
    let g1_derived = claim.sub(r.g_at_0);
    let claim_consistent = claim == r.g_at_0.add(g1_derived);
    let gr = eval_cubic_from_0_1_2_3(r.g_at_0, g1_derived, r.g_at_2, r.g_at_3, r.challenge_r);
    let folded_claim_from_vectors = r
      .folded_values
      .iter()
      .fold(Fp::zero(), |acc, v| acc.add(*v));
    let transition_consistent = gr == folded_claim_from_vectors;

    rounds.push(OuterVerifyRoundTrace {
      round: r.round,
      claim_in: claim,
      g0: r.g_at_0,
      g1_derived,
      g2: r.g_at_2,
      g3: r.g_at_3,
      challenge_r: r.challenge_r,
      gr_from_interpolation: gr,
      folded_claim_from_vectors,
      claim_consistent,
      transition_consistent,
    });

    claim = gr;
  }

  OuterVerifyTrace {
    rounds,
    final_claim_from_verifier: claim,
    final_claim_from_trace: trace.final_claim,
    final_consistent: claim == trace.final_claim,
  }
}
