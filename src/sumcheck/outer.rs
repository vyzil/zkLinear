use crate::core::{field::Fp, transcript::derive_round_challenge};

#[derive(Debug, Clone)]
pub struct OuterRoundTranscript {
  pub round: usize,
  pub sum_low: Fp,
  pub sum_high: Fp,
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
    let sum_low = low.iter().fold(Fp::zero(), |acc, v| acc.add(*v));
    let sum_high = high.iter().fold(Fp::zero(), |acc, v| acc.add(*v));
    assert_eq!(claim, sum_low.add(sum_high));

    let r = derive_round_challenge(
      b"spartan-outer-sumcheck",
      round,
      sum_low,
      sum_high,
      Fp::zero(),
    );

    let folded_values: Vec<Fp> = low
      .iter()
      .zip(high.iter())
      .map(|(l, h)| l.add(r.mul(h.sub(*l))))
      .collect();

    claim = folded_values.iter().fold(Fp::zero(), |acc, v| acc.add(*v));

    rounds.push(OuterRoundTranscript {
      round,
      sum_low,
      sum_high,
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
