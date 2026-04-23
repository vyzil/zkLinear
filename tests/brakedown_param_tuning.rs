mod common;

use merlin::Transcript;
use zk_linear::pcs::BrakedownSecurityPreset;
use zk_linear::{
    core::field::Fp,
    field_profiles::{BaseField64, Mersenne61},
    pcs::{
        brakedown::profiles::auto_tuned_counts, traits::PolynomialCommitmentScheme, BrakedownPcs,
        BrakedownPcsT,
    },
    protocol::spec_v1::{append_spec_domain, append_u64_le, PCS_DEMO_TRANSCRIPT_LABEL},
};

#[test]
fn auto_tune_security_profiles_increase_degree_tests_vs_toy() {
    let base = common::pcs_from_preset(BrakedownSecurityPreset::DemoToy);
    let m61 = common::pcs_from_preset(BrakedownSecurityPreset::LcpcLikeMersenne61Ext2);
    let gold = common::pcs_from_preset(BrakedownSecurityPreset::LcpcLikeGoldilocks64Ext2);

    assert!(m61.params.n_degree_tests >= base.params.n_degree_tests);
    assert!(gold.params.n_degree_tests >= m61.params.n_degree_tests);
    assert!(m61.params.n_col_opens >= 1);
    assert!(gold.params.n_col_opens >= 1);
}

#[test]
fn auto_tune_security_produces_valid_open_count() {
    let pcs = common::pcs_from_preset(BrakedownSecurityPreset::LcpcLikeMersenne61Ext2);
    assert!(pcs.params.n_col_opens <= pcs.encoding.n_cols);
    assert!(pcs.params.n_degree_tests >= 1);
}

#[test]
fn generic_pcs_type_is_constructible_for_alt_field_profile() {
    let _pcs_generic: BrakedownPcsT<Mersenne61> =
        BrakedownPcsT::new(BrakedownSecurityPreset::LcpcLikeMersenne61Ext2.params(8));
}

#[test]
fn generic_pcs_mersenne61_end_to_end_succeeds() {
    let pcs: BrakedownPcsT<Mersenne61> =
        BrakedownPcsT::new(BrakedownSecurityPreset::LcpcLikeMersenne61Ext2.params(8));

    let n_rows = 4usize;
    let coeffs: Vec<Mersenne61> = (0..(n_rows * 8))
        .map(|i| Mersenne61::new(((i as u64) * 13 + 5) % Mersenne61::P))
        .collect();

    let comm = pcs.commit_generic(&coeffs).expect("generic commit");
    let vc = pcs.verifier_commitment_generic(&comm);

    let x = Mersenne61::new(7);
    let mut inner = Vec::with_capacity(8);
    let mut p = Mersenne61::one();
    for _ in 0..8 {
        inner.push(p);
        p = p.mul(x);
    }
    let xr = x.mul(*inner.last().unwrap());
    let mut outer = Vec::with_capacity(n_rows);
    let mut q = Mersenne61::one();
    for _ in 0..n_rows {
        outer.push(q);
        q = q.mul(xr);
    }

    let mut tr_p = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    append_spec_domain(&mut tr_p);
    tr_p.append_message(b"polycommit", &vc.root);
    append_u64_le(&mut tr_p, b"ncols", pcs.encoding.n_cols as u64);
    let pf = pcs
        .open_generic(&comm, &outer, &mut tr_p)
        .expect("generic open");

    let claim = inner
        .iter()
        .zip(pf.p_eval.iter())
        .fold(Mersenne61::zero(), |acc, (a, b)| acc.add((*a).mul(*b)));

    let mut tr_v = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    append_spec_domain(&mut tr_v);
    tr_v.append_message(b"polycommit", &vc.root);
    append_u64_le(&mut tr_v, b"ncols", pcs.encoding.n_cols as u64);

    pcs.verify_generic(&vc, &pf, &outer, &inner, claim, &mut tr_v)
        .expect("generic verify");
}

#[test]
fn production_preset_has_expected_fixed_encoder_knobs() {
    let p = BrakedownSecurityPreset::ProductionMersenne61Ext2.params(8);
    assert_eq!(p.spel_layers, 3);
    assert_eq!(p.spel_pre_density, 5);
    assert_eq!(p.spel_post_density, 4);
    assert_eq!(p.spel_base_rs_parity, 16);
    assert!(p.auto_tune_security);
    assert!(p.is_spec_v1_production_candidate());
}

#[test]
fn production_preset_mersenne61_end_to_end_succeeds() {
    let pcs: BrakedownPcsT<Mersenne61> =
        BrakedownPcsT::new(BrakedownSecurityPreset::ProductionMersenne61Ext2.params(8));

    let n_rows = 4usize;
    let coeffs: Vec<Mersenne61> = (0..(n_rows * 8))
        .map(|i| Mersenne61::new(((i as u64) * 17 + 3) % Mersenne61::P))
        .collect();

    let comm = pcs.commit_generic(&coeffs).expect("generic commit");
    let vc = pcs.verifier_commitment_generic(&comm);

    let x = Mersenne61::new(11);
    let mut inner = Vec::with_capacity(8);
    let mut p = Mersenne61::one();
    for _ in 0..8 {
        inner.push(p);
        p = p.mul(x);
    }
    let xr = x.mul(*inner.last().unwrap());
    let mut outer = Vec::with_capacity(n_rows);
    let mut q = Mersenne61::one();
    for _ in 0..n_rows {
        outer.push(q);
        q = q.mul(xr);
    }

    let mut tr_p = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    append_spec_domain(&mut tr_p);
    tr_p.append_message(b"polycommit", &vc.root);
    append_u64_le(&mut tr_p, b"ncols", pcs.encoding.n_cols as u64);
    let pf = pcs
        .open_generic(&comm, &outer, &mut tr_p)
        .expect("generic open");

    let claim = inner
        .iter()
        .zip(pf.p_eval.iter())
        .fold(Mersenne61::zero(), |acc, (a, b)| acc.add((*a).mul(*b)));

    let mut tr_v = Transcript::new(PCS_DEMO_TRANSCRIPT_LABEL);
    append_spec_domain(&mut tr_v);
    tr_v.append_message(b"polycommit", &vc.root);
    append_u64_le(&mut tr_v, b"ncols", pcs.encoding.n_cols as u64);
    pcs.verify_generic(&vc, &pf, &outer, &inner, claim, &mut tr_v)
        .expect("generic verify");
}

#[test]
fn fp_trait_path_rejects_non_toy_profiles() {
    let pcs = BrakedownPcs::new(BrakedownSecurityPreset::ProductionMersenne61Ext2.params(8));
    let coeffs = vec![Fp::new(1); 32];
    let err = pcs
        .commit(&coeffs)
        .expect_err("Fp path must reject non-toy field profile");
    assert!(err
        .to_string()
        .contains("Fp PCS path supports only ToyF97 profile"));
}

#[test]
fn lcpc_like_preset_is_not_spec_v1_production_candidate() {
    let p = BrakedownSecurityPreset::LcpcLikeMersenne61Ext2.params(8);
    assert!(
        !p.is_spec_v1_production_candidate(),
        "lcpc-like preset should stay distinct from pinned production-candidate profile"
    );
}

#[test]
fn auto_tune_counts_match_profile_formula() {
    let p = BrakedownSecurityPreset::ProductionMersenne61Ext2.params(8);
    let pcs: BrakedownPcsT<Mersenne61> = BrakedownPcsT::new(p.clone());
    let (deg, opens) = auto_tuned_counts(
        p.security_bits,
        pcs.encoding.n_cols,
        p.field_profile,
        p.encoder_kind,
    );
    assert_eq!(pcs.params.n_degree_tests, deg);
    assert_eq!(pcs.params.n_col_opens, opens);
}

#[test]
fn production_mersenne61_n_per_row8_has_expected_tuned_counts() {
    let p = BrakedownSecurityPreset::ProductionMersenne61Ext2.params(8);
    let pcs: BrakedownPcsT<Mersenne61> = BrakedownPcsT::new(p);
    assert_eq!(pcs.encoding.n_cols, 35);
    assert_eq!(pcs.params.n_degree_tests, 2);
    assert_eq!(pcs.params.n_col_opens, 35);
}
