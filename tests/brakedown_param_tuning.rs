mod common;

use merlin::Transcript;
use zk_linear::pcs::BrakedownSecurityPreset;
use zk_linear::{
    field_profiles::{BaseField64, Mersenne61},
    pcs::BrakedownPcsT,
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
