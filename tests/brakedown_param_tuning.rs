mod common;

use zk_linear::pcs::BrakedownSecurityPreset;

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
