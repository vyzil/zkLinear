use std::path::Path;

use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::{
    core::field::{Fp, ModulusScope},
    io::case_format::{load_spartan_like_case_from_dir, SpartanLikeCase},
    protocol::spec_v1::{GAMMA_DOMAIN, INNER_SUMCHECK_JOINT_LABEL, OUTER_TAU_LABEL},
    sumcheck::{
        inner::{
            inner_product, prove_inner_sumcheck_with_label, verify_inner_sumcheck_trace,
            SumcheckTrace, VerifyTrace,
        },
        outer::{
            prove_outer_sumcheck, verify_outer_sumcheck_trace, OuterSumcheckTrace, OuterVerifyTrace,
        },
    },
};

fn default_spartan_modulus() -> u64 {
    (1u64 << 61) - 1
}

#[derive(Debug, Clone)]
pub struct SpartanLikeReportData {
    pub case: SpartanLikeCase,
    pub az: Vec<Fp>,
    pub bz: Vec<Fp>,
    pub cz: Vec<Fp>,
    pub residual: Vec<Fp>,
    pub tau: Vec<Fp>,
    pub eq_tau: Vec<Fp>,
    pub weighted_residual: Vec<Fp>,
    pub outer_trace: OuterSumcheckTrace,
    pub outer_verify: OuterVerifyTrace,
    pub r_x: Vec<Fp>,
    pub row_weights: Vec<Fp>,
    pub eq_states: Vec<Vec<Fp>>,
    pub gamma: Fp,
    pub gamma_sq: Fp,
    pub a_bound: Vec<Fp>,
    pub b_bound: Vec<Fp>,
    pub c_bound: Vec<Fp>,
    pub joint_bound: Vec<Fp>,
    pub joint_trace: SumcheckTrace,
    pub joint_verify: VerifyTrace,
    pub a_trace: SumcheckTrace,
    pub b_trace: SumcheckTrace,
    pub c_trace: SumcheckTrace,
}

fn matrix_vec_mul(m: &[Vec<Fp>], z: &[Fp]) -> Vec<Fp> {
    m.iter().map(|row| inner_product(row, z)).collect()
}

fn derive_joint_challenge(az: &[Fp], bz: &[Fp], cz: &[Fp]) -> Fp {
    let mut h = Sha256::new();
    h.update(GAMMA_DOMAIN);
    for v in az.iter().chain(bz.iter()).chain(cz.iter()) {
        h.update(v.0.to_le_bytes());
    }
    let out: [u8; 32] = h.finalize().into();
    Fp::from_challenge(out)
}

fn derive_outer_tau(num_vars: usize, az: &[Fp], bz: &[Fp], cz: &[Fp], z: &[Fp]) -> Vec<Fp> {
    let mut tau = Vec::with_capacity(num_vars);
    for i in 0..num_vars {
        let mut h = Sha256::new();
        h.update(OUTER_TAU_LABEL);
        h.update((i as u64).to_le_bytes());
        for v in az.iter().chain(bz.iter()).chain(cz.iter()).chain(z.iter()) {
            h.update(v.0.to_le_bytes());
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

pub fn build_spartan_like_report_data_from_dir(case_dir: &Path) -> Result<SpartanLikeReportData> {
    build_spartan_like_report_data_from_dir_with_modulus(case_dir, default_spartan_modulus())
}

pub fn build_spartan_like_report_data_from_dir_with_modulus(
    case_dir: &Path,
    modulus: u64,
) -> Result<SpartanLikeReportData> {
    let _mod_scope = ModulusScope::enter(modulus);
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

    let row_vars = case.a.len().trailing_zeros() as usize;
    let tau = derive_outer_tau(row_vars, &az, &bz, &cz, &case.z);
    let eq_tau = build_eq_weights_from_challenges(&tau);
    let weighted_residual: Vec<Fp> = residual
        .iter()
        .zip(eq_tau.iter())
        .map(|(r, w)| r.mul(*w))
        .collect();

    let outer_trace = prove_outer_sumcheck(&weighted_residual);
    let outer_verify = verify_outer_sumcheck_trace(&outer_trace);

    let r_x: Vec<Fp> = outer_trace.rounds.iter().map(|rr| rr.challenge_r).collect();
    let row_weights = build_eq_weights_from_challenges(&r_x);
    let eq_states = build_eq_weights_trace(&r_x);

    let gamma = derive_joint_challenge(&az, &bz, &cz);
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

    let joint_trace =
        prove_inner_sumcheck_with_label(&joint_bound, &case.z, INNER_SUMCHECK_JOINT_LABEL);
    let joint_verify = verify_inner_sumcheck_trace(&joint_trace);

    let a_trace = prove_inner_sumcheck_with_label(&a_bound, &case.z, b"spartan-inner-A");
    let b_trace = prove_inner_sumcheck_with_label(&b_bound, &case.z, b"spartan-inner-B");
    let c_trace = prove_inner_sumcheck_with_label(&c_bound, &case.z, b"spartan-inner-C");

    Ok(SpartanLikeReportData {
        case,
        az,
        bz,
        cz,
        residual,
        tau,
        eq_tau,
        weighted_residual,
        outer_trace,
        outer_verify,
        r_x,
        row_weights,
        eq_states,
        gamma,
        gamma_sq,
        a_bound,
        b_bound,
        c_bound,
        joint_bound,
        joint_trace,
        joint_verify,
        a_trace,
        b_trace,
        c_trace,
    })
}
