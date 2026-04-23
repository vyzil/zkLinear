use merlin::Transcript;

use crate::core::{
    field::Fp,
    transcript::{derive_round_challenge, derive_round_challenge_merlin},
};

#[derive(Debug, Clone)]
pub struct RoundTranscript {
    pub round: usize,
    pub h_at_0: Fp,
    pub h_at_1: Fp,
    pub h_at_2: Fp,
    pub challenge_r: Fp,
    pub folded_f: Vec<Fp>,
    pub folded_g: Vec<Fp>,
}

#[derive(Debug, Clone)]
pub struct SumcheckTrace {
    pub claim_initial: Fp,
    pub rounds: Vec<RoundTranscript>,
    pub final_f: Fp,
    pub final_g: Fp,
    pub final_claim: Fp,
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

pub const CHALLENGE_LABEL: &[u8] = b"spartan-inner-sumcheck";
pub const CHALLENGE_HASH_NAME: &str = "SHA-256";

pub fn inner_product(a: &[Fp], b: &[Fp]) -> Fp {
    a.iter()
        .zip(b.iter())
        .fold(Fp::zero(), |acc, (x, y)| acc.add(x.mul(*y)))
}

pub fn prove_inner_sumcheck_with_label(f: &[Fp], g: &[Fp], label: &[u8]) -> SumcheckTrace {
    assert_eq!(f.len(), g.len());
    assert!(f.len().is_power_of_two());

    let mut f_cur = f.to_vec();
    let mut g_cur = g.to_vec();

    let claim_initial = inner_product(&f_cur, &g_cur);
    let mut claim = claim_initial;
    let mut rounds = Vec::new();

    let mut round = 0usize;
    while f_cur.len() > 1 {
        let half = f_cur.len() / 2;
        let (f0, f1) = f_cur.split_at(half);
        let (g0, g1) = g_cur.split_at(half);

        let h0 = inner_product(f0, g0);
        let h1 = inner_product(f1, g1);

        let f2: Vec<Fp> = f0
            .iter()
            .zip(f1.iter())
            .map(|(l, h)| h.mul(Fp::new(2)).sub(*l))
            .collect();
        let g2: Vec<Fp> = g0
            .iter()
            .zip(g1.iter())
            .map(|(l, h)| h.mul(Fp::new(2)).sub(*l))
            .collect();
        let h2 = inner_product(&f2, &g2);

        assert_eq!(claim, h0.add(h1));

        let r = derive_round_challenge(label, round, h0, h1, h2);

        let folded_f: Vec<Fp> = f0
            .iter()
            .zip(f1.iter())
            .map(|(l, h)| l.add(r.mul(h.sub(*l))))
            .collect();
        let folded_g: Vec<Fp> = g0
            .iter()
            .zip(g1.iter())
            .map(|(l, h)| l.add(r.mul(h.sub(*l))))
            .collect();

        claim = inner_product(&folded_f, &folded_g);

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

pub fn prove_inner_sumcheck(f: &[Fp], g: &[Fp]) -> SumcheckTrace {
    prove_inner_sumcheck_with_label(f, g, CHALLENGE_LABEL)
}

pub fn prove_inner_sumcheck_with_label_and_transcript(
    f: &[Fp],
    g: &[Fp],
    label: &[u8],
    tr: &mut Transcript,
) -> SumcheckTrace {
    assert_eq!(f.len(), g.len());
    assert!(f.len().is_power_of_two());

    let mut f_cur = f.to_vec();
    let mut g_cur = g.to_vec();

    let claim_initial = inner_product(&f_cur, &g_cur);
    let mut claim = claim_initial;
    let mut rounds = Vec::new();

    let mut round = 0usize;
    while f_cur.len() > 1 {
        let half = f_cur.len() / 2;
        let (f0, f1) = f_cur.split_at(half);
        let (g0, g1) = g_cur.split_at(half);

        let h0 = inner_product(f0, g0);
        let h1 = inner_product(f1, g1);

        let f2: Vec<Fp> = f0
            .iter()
            .zip(f1.iter())
            .map(|(l, h)| h.mul(Fp::new(2)).sub(*l))
            .collect();
        let g2: Vec<Fp> = g0
            .iter()
            .zip(g1.iter())
            .map(|(l, h)| h.mul(Fp::new(2)).sub(*l))
            .collect();
        let h2 = inner_product(&f2, &g2);

        assert_eq!(claim, h0.add(h1));

        let r = derive_round_challenge_merlin(tr, label, round, h0, h1, h2);

        let folded_f: Vec<Fp> = f0
            .iter()
            .zip(f1.iter())
            .map(|(l, h)| l.add(r.mul(h.sub(*l))))
            .collect();
        let folded_g: Vec<Fp> = g0
            .iter()
            .zip(g1.iter())
            .map(|(l, h)| l.add(r.mul(h.sub(*l))))
            .collect();

        claim = inner_product(&folded_f, &folded_g);

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

pub fn prove_matrix_vector_inner_sumcheck(a: &[Vec<Fp>], y: &[Fp]) -> Vec<SumcheckTrace> {
    assert!(!a.is_empty());
    for row in a {
        assert_eq!(row.len(), y.len());
        assert!(row.len().is_power_of_two());
    }
    a.iter().map(|row| prove_inner_sumcheck(row, y)).collect()
}

fn eval_quadratic_from_0_1_2(h0: Fp, h1: Fp, h2: Fp, r: Fp) -> Fp {
    // Lagrange interpolation at points 0,1,2 over F_97:
    // h(r) = h0*L0(r) + h1*L1(r) + h2*L2(r)
    // L0(r) = (r-1)(r-2)/2
    // L1(r) = -r(r-2)
    // L2(r) = r(r-1)/2
    let two_inv = Fp::new(49); // inverse of 2 mod 97
    let one = Fp::new(1);
    let two = Fp::new(2);

    let l0 = r.sub(one).mul(r.sub(two)).mul(two_inv);
    let l1 = Fp::zero().sub(r.mul(r.sub(two)));
    let l2 = r.mul(r.sub(one)).mul(two_inv);

    h0.mul(l0).add(h1.mul(l1)).add(h2.mul(l2))
}

pub fn verify_inner_sumcheck_trace(trace: &SumcheckTrace) -> VerifyTrace {
    let mut claim = trace.claim_initial;
    let mut rounds = Vec::new();

    for r in &trace.rounds {
        let expected_claim_from_h01 = r.h_at_0.add(r.h_at_1);
        let claim_consistent = claim == expected_claim_from_h01;

        let hr = eval_quadratic_from_0_1_2(r.h_at_0, r.h_at_1, r.h_at_2, r.challenge_r);
        let folded_claim_from_vectors = inner_product(&r.folded_f, &r.folded_g);
        let transition_consistent = hr == folded_claim_from_vectors;

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
        final_consistent: claim == trace.final_claim,
    }
}
