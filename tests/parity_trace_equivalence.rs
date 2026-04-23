use std::path::PathBuf;

use zk_linear::{
    api::spartan_like::build_spartan_like_report_data_from_dir,
    core::field::{Fp, ModulusScope},
    nizk::spartan_brakedown::prove_from_dir,
    protocol::shared::{build_eq_weights_from_challenges, derive_outer_tau_sha, matrix_vec_mul},
};

fn case_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/inner_sumcheck_spartan")
}

fn sum_vec(v: &[Fp]) -> Fp {
    v.iter().fold(Fp::zero(), |acc, x| acc.add(*x))
}

#[test]
fn parity_must_match_subset_between_spartan_like_and_nizk() {
    let _scope = ModulusScope::enter((1u64 << 61) - 1);
    let dir = case_dir();
    let sp = build_spartan_like_report_data_from_dir(&dir).expect("spartan-like data should build");
    let nz = prove_from_dir(&dir).expect("nizk prove should succeed");

    // 1) shape invariants
    let rows = sp.case.a.len();
    let cols = sp.case.a[0].len();
    assert_eq!(cols, sp.case.z.len());
    assert_eq!(sp.case.z.len(), nz.public.inner_tensor.len());
    assert_eq!(1usize << nz.proof.outer_trace.rounds.len(), rows);
    assert_eq!(1usize << nz.proof.inner_trace.rounds.len(), cols);
    assert_eq!(nz.proof.outer_trace.rounds.len(), rows.trailing_zeros() as usize);
    assert_eq!(nz.proof.inner_trace.rounds.len(), cols.trailing_zeros() as usize);
    assert_eq!(sp.outer_trace.rounds.len(), rows.trailing_zeros() as usize);
    assert_eq!(sp.joint_trace.rounds.len(), cols.trailing_zeros() as usize);

    // 2) A/B/C*z and residual invariants
    let az = matrix_vec_mul(&sp.case.a, &sp.case.z);
    let bz = matrix_vec_mul(&sp.case.b, &sp.case.z);
    let cz = matrix_vec_mul(&sp.case.c, &sp.case.z);
    assert_eq!(az, sp.az);
    assert_eq!(bz, sp.bz);
    assert_eq!(cz, sp.cz);

    let residual: Vec<Fp> = az
        .iter()
        .zip(bz.iter())
        .zip(cz.iter())
        .map(|((a, b), c)| a.mul(*b).sub(*c))
        .collect();
    assert_eq!(residual, sp.residual);

    // 3) outer-claim initial must match across both paths
    let tau = derive_outer_tau_sha(rows.trailing_zeros() as usize, &az, &bz, &cz, &sp.case.z);
    let eq_tau = build_eq_weights_from_challenges(&tau);
    let weighted_residual: Vec<Fp> = residual
        .iter()
        .zip(eq_tau.iter())
        .map(|(r, w)| r.mul(*w))
        .collect();
    let outer_claim_expected = sum_vec(&weighted_residual);

    assert_eq!(outer_claim_expected, sp.outer_trace.claim_initial);
    assert_eq!(outer_claim_expected, nz.proof.outer_trace.claim_initial);
}
