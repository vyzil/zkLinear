use merlin::Transcript;

use crate::core::{
    field::Fp,
    field_element::FieldElement,
    transcript::{derive_round_challenge_merlin_t, derive_round_challenge_t},
};
use crate::protocol::spec_v1::INNER_SUMCHECK_LABEL;

#[derive(Debug, Clone)]
pub struct RoundTranscript<F = Fp> {
    pub round: usize,
    pub h_at_0: F,
    pub h_at_1: F,
    pub h_at_2: F,
    pub challenge_r: F,
    pub folded_f: Vec<F>,
    pub folded_g: Vec<F>,
}

#[derive(Debug, Clone)]
pub struct SumcheckTrace<F = Fp> {
    pub claim_initial: F,
    pub rounds: Vec<RoundTranscript<F>>,
    pub final_f: F,
    pub final_g: F,
    pub final_claim: F,
}

#[derive(Debug, Clone)]
pub struct VerifyRoundTrace {
    pub round: usize,
    pub h0: Fp,
    pub h1: Fp,
    pub h2: Fp,
    pub claim_in: Fp,
    pub expected_claim_from_h01: Fp,
    pub claim_consistent: bool,
    pub challenge_r: Fp,
    pub hr_from_interpolation: Fp,
    pub folded_claim_from_vectors: Fp,
    pub transition_consistent: bool,
}

#[derive(Debug, Clone)]
pub struct VerifyTrace {
    pub rounds: Vec<VerifyRoundTrace>,
    pub final_claim_from_verifier: Fp,
    pub final_claim_from_trace: Fp,
    pub final_consistent: bool,
}

#[derive(Debug, Clone)]
pub struct VerifyRoundTraceT<F = Fp> {
    pub round: usize,
    pub h0: F,
    pub h1: F,
    pub h2: F,
    pub claim_in: F,
    pub expected_claim_from_h01: F,
    pub claim_consistent: bool,
    pub challenge_r: F,
    pub hr_from_interpolation: F,
    pub folded_claim_from_vectors: F,
    pub transition_consistent: bool,
}

#[derive(Debug, Clone)]
pub struct VerifyTraceT<F = Fp> {
    pub rounds: Vec<VerifyRoundTraceT<F>>,
    pub final_claim_from_verifier: F,
    pub final_claim_from_trace: F,
    pub final_consistent: bool,
}

pub const CHALLENGE_LABEL: &[u8] = INNER_SUMCHECK_LABEL;
pub const CHALLENGE_HASH_NAME: &str = "SHA-256";

pub fn inner_product_t<F: FieldElement>(a: &[F], b: &[F]) -> F {
    a.iter()
        .zip(b.iter())
        .fold(F::zero(), |acc, (x, y)| acc.add(x.mul(*y)))
}

pub fn inner_product(a: &[Fp], b: &[Fp]) -> Fp {
    inner_product_t(a, b)
}

pub fn prove_inner_sumcheck_with_label_t<F: FieldElement>(
    f: &[F],
    g: &[F],
    label: &[u8],
) -> SumcheckTrace<F> {
    assert_eq!(f.len(), g.len());
    assert!(f.len().is_power_of_two());

    let mut f_cur = f.to_vec();
    let mut g_cur = g.to_vec();

    let claim_initial = inner_product_t(&f_cur, &g_cur);
    let mut claim = claim_initial;
    let mut rounds = Vec::new();

    let mut round = 0usize;
    while f_cur.len() > 1 {
        let half = f_cur.len() / 2;
        let (f0, f1) = f_cur.split_at(half);
        let (g0, g1) = g_cur.split_at(half);

        let h0 = inner_product_t(f0, g0);
        let h1 = inner_product_t(f1, g1);

        let f2: Vec<F> = f0
            .iter()
            .zip(f1.iter())
            .map(|(l, h)| h.mul(F::from_u64(2)).sub(*l))
            .collect();
        let g2: Vec<F> = g0
            .iter()
            .zip(g1.iter())
            .map(|(l, h)| h.mul(F::from_u64(2)).sub(*l))
            .collect();
        let h2 = inner_product_t(&f2, &g2);

        assert_eq!(claim, h0.add(h1));

        let r = derive_round_challenge_t(label, round, h0, h1, h2);

        let folded_f: Vec<F> = f0
            .iter()
            .zip(f1.iter())
            .map(|(l, h)| l.add(r.mul(h.sub(*l))))
            .collect();
        let folded_g: Vec<F> = g0
            .iter()
            .zip(g1.iter())
            .map(|(l, h)| l.add(r.mul(h.sub(*l))))
            .collect();

        claim = inner_product_t(&folded_f, &folded_g);

        rounds.push(RoundTranscript {
            round,
            h_at_0: h0,
            h_at_1: h1,
            h_at_2: h2,
            challenge_r: r,
            folded_f: folded_f.clone(),
            folded_g: folded_g.clone(),
        });

        f_cur = folded_f;
        g_cur = folded_g;
        round += 1;
    }

    SumcheckTrace {
        claim_initial,
        rounds,
        final_f: f_cur[0],
        final_g: g_cur[0],
        final_claim: claim,
    }
}

pub fn prove_inner_sumcheck_with_label(f: &[Fp], g: &[Fp], label: &[u8]) -> SumcheckTrace {
    prove_inner_sumcheck_with_label_t(f, g, label)
}

pub fn prove_inner_sumcheck(f: &[Fp], g: &[Fp]) -> SumcheckTrace {
    prove_inner_sumcheck_with_label(f, g, CHALLENGE_LABEL)
}

pub fn prove_inner_sumcheck_with_label_and_transcript_t<F: FieldElement>(
    f: &[F],
    g: &[F],
    label: &[u8],
    tr: &mut Transcript,
) -> SumcheckTrace<F> {
    assert_eq!(f.len(), g.len());
    assert!(f.len().is_power_of_two());

    let mut f_cur = f.to_vec();
    let mut g_cur = g.to_vec();

    let claim_initial = inner_product_t(&f_cur, &g_cur);
    let mut claim = claim_initial;
    let mut rounds = Vec::new();

    let mut round = 0usize;
    while f_cur.len() > 1 {
        let half = f_cur.len() / 2;
        let (f0, f1) = f_cur.split_at(half);
        let (g0, g1) = g_cur.split_at(half);

        let h0 = inner_product_t(f0, g0);
        let h1 = inner_product_t(f1, g1);

        let f2: Vec<F> = f0
            .iter()
            .zip(f1.iter())
            .map(|(l, h)| h.mul(F::from_u64(2)).sub(*l))
            .collect();
        let g2: Vec<F> = g0
            .iter()
            .zip(g1.iter())
            .map(|(l, h)| h.mul(F::from_u64(2)).sub(*l))
            .collect();
        let h2 = inner_product_t(&f2, &g2);

        assert_eq!(claim, h0.add(h1));

        let r = derive_round_challenge_merlin_t(tr, label, round, h0, h1, h2);

        let folded_f: Vec<F> = f0
            .iter()
            .zip(f1.iter())
            .map(|(l, h)| l.add(r.mul(h.sub(*l))))
            .collect();
        let folded_g: Vec<F> = g0
            .iter()
            .zip(g1.iter())
            .map(|(l, h)| l.add(r.mul(h.sub(*l))))
            .collect();

        claim = inner_product_t(&folded_f, &folded_g);

        rounds.push(RoundTranscript {
            round,
            h_at_0: h0,
            h_at_1: h1,
            h_at_2: h2,
            challenge_r: r,
            folded_f: folded_f.clone(),
            folded_g: folded_g.clone(),
        });

        f_cur = folded_f;
        g_cur = folded_g;
        round += 1;
    }

    SumcheckTrace {
        claim_initial,
        rounds,
        final_f: f_cur[0],
        final_g: g_cur[0],
        final_claim: claim,
    }
}

pub fn prove_inner_sumcheck_with_label_and_transcript(
    f: &[Fp],
    g: &[Fp],
    label: &[u8],
    tr: &mut Transcript,
) -> SumcheckTrace {
    prove_inner_sumcheck_with_label_and_transcript_t(f, g, label, tr)
}

pub fn prove_matrix_vector_inner_sumcheck(a: &[Vec<Fp>], y: &[Fp]) -> Vec<SumcheckTrace<Fp>> {
    assert!(!a.is_empty());
    for row in a {
        assert_eq!(row.len(), y.len());
        assert!(row.len().is_power_of_two());
    }
    a.iter().map(|row| prove_inner_sumcheck(row, y)).collect()
}

fn eval_quadratic_from_0_1_2(h0: Fp, h1: Fp, h2: Fp, r: Fp) -> Fp {
    // Lagrange interpolation at points 0,1,2 over current field modulus:
    // h(r) = h0*L0(r) + h1*L1(r) + h2*L2(r)
    // L0(r) = (r-1)(r-2)/2
    // L1(r) = -r(r-2)
    // L2(r) = r(r-1)/2
    let two_inv = Fp::new(2).inv().expect("2 must be invertible in field");
    let one = Fp::new(1);
    let two = Fp::new(2);

    let l0 = r.sub(one).mul(r.sub(two)).mul(two_inv);
    let l1 = Fp::zero().sub(r.mul(r.sub(two)));
    let l2 = r.mul(r.sub(one)).mul(two_inv);

    h0.mul(l0).add(h1.mul(l1)).add(h2.mul(l2))
}

fn eval_quadratic_from_0_1_2_t<F: FieldElement>(h0: F, h1: F, h2: F, r: F) -> F {
    let two_inv = F::from_u64(2).inv().expect("2 must be invertible in field");
    let one = F::from_u64(1);
    let two = F::from_u64(2);

    let l0 = r.sub(one).mul(r.sub(two)).mul(two_inv);
    let l1 = F::zero().sub(r.mul(r.sub(two)));
    let l2 = r.mul(r.sub(one)).mul(two_inv);

    h0.mul(l0).add(h1.mul(l1)).add(h2.mul(l2))
}

pub fn verify_inner_sumcheck_trace(trace: &SumcheckTrace) -> VerifyTrace {
    let mut claim = trace.claim_initial;
    let mut rounds = Vec::new();
    let mut all_rounds_consistent = true;

    for r in &trace.rounds {
        let expected_claim_from_h01 = r.h_at_0.add(r.h_at_1);
        let claim_consistent = claim == expected_claim_from_h01;

        let hr = eval_quadratic_from_0_1_2(r.h_at_0, r.h_at_1, r.h_at_2, r.challenge_r);
        let folded_claim_from_vectors = inner_product(&r.folded_f, &r.folded_g);
        let transition_consistent = hr == folded_claim_from_vectors;
        all_rounds_consistent &= claim_consistent && transition_consistent;

        rounds.push(VerifyRoundTrace {
            round: r.round,
            h0: r.h_at_0,
            h1: r.h_at_1,
            h2: r.h_at_2,
            claim_in: claim,
            expected_claim_from_h01,
            claim_consistent,
            challenge_r: r.challenge_r,
            hr_from_interpolation: hr,
            folded_claim_from_vectors,
            transition_consistent,
        });

        claim = hr;
    }

    VerifyTrace {
        rounds,
        final_claim_from_verifier: claim,
        final_claim_from_trace: trace.final_claim,
        final_consistent: all_rounds_consistent && claim == trace.final_claim,
    }
}

pub fn verify_inner_sumcheck_trace_t<F: FieldElement>(trace: &SumcheckTrace<F>) -> VerifyTraceT<F> {
    let mut claim = trace.claim_initial;
    let mut rounds = Vec::new();
    let mut all_rounds_consistent = true;

    for r in &trace.rounds {
        let expected_claim_from_h01 = r.h_at_0.add(r.h_at_1);
        let claim_consistent = claim == expected_claim_from_h01;

        let hr = eval_quadratic_from_0_1_2_t(r.h_at_0, r.h_at_1, r.h_at_2, r.challenge_r);
        let folded_claim_from_vectors = inner_product_t(&r.folded_f, &r.folded_g);
        let transition_consistent = hr == folded_claim_from_vectors;
        all_rounds_consistent &= claim_consistent && transition_consistent;

        rounds.push(VerifyRoundTraceT {
            round: r.round,
            h0: r.h_at_0,
            h1: r.h_at_1,
            h2: r.h_at_2,
            claim_in: claim,
            expected_claim_from_h01,
            claim_consistent,
            challenge_r: r.challenge_r,
            hr_from_interpolation: hr,
            folded_claim_from_vectors,
            transition_consistent,
        });

        claim = hr;
    }

    VerifyTraceT {
        rounds,
        final_claim_from_verifier: claim,
        final_claim_from_trace: trace.final_claim,
        final_consistent: all_rounds_consistent && claim == trace.final_claim,
    }
}
