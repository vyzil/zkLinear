use std::path::PathBuf;

use zk_linear::{
    bridge::{prove_bridge_from_dir_with_profile, verify_bridge_bundle, BRIDGE_TRANSCRIPT_LABEL},
    nizk::spartan_brakedown::{
        parse_field_profile, prove_from_dir, prove_from_dir_with_profile, verify_public,
    },
    pcs::brakedown::types::BrakedownFieldProfile,
};

use merlin::Transcript;

fn case_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/inner_sumcheck_spartan")
}

fn profiles() -> [BrakedownFieldProfile; 3] {
    [
        BrakedownFieldProfile::ToyF97,
        BrakedownFieldProfile::Mersenne61Ext2,
        BrakedownFieldProfile::Goldilocks64Ext2,
    ]
}

#[test]
fn nizk_e2e_runs_for_all_field_profiles() {
    for profile in profiles() {
        let res = prove_from_dir_with_profile(&case_dir(), profile)
            .expect("prove_from_dir_with_profile should succeed");
        assert_eq!(res.proof.verifier_commitment.field_profile, profile);
        verify_public(&res.proof, &res.public).expect("verify_public should succeed");
    }
}

#[test]
fn bridge_e2e_runs_for_all_field_profiles() {
    for profile in profiles() {
        let built = prove_bridge_from_dir_with_profile(&case_dir(), profile)
            .expect("prove_bridge_from_dir_with_profile should succeed");
        assert_eq!(built.bundle.verifier_commitment.field_profile, profile);

        let mut tr = Transcript::new(BRIDGE_TRANSCRIPT_LABEL);
        verify_bridge_bundle(&built.bundle, &built.verifier_query, &mut tr)
            .expect("verify_bridge_bundle should succeed");
    }
}

#[test]
fn default_nizk_profile_is_mersenne61ext2() {
    let r = prove_from_dir(&case_dir()).expect("default prove should succeed");
    assert_eq!(
        r.proof.verifier_commitment.field_profile,
        BrakedownFieldProfile::Mersenne61Ext2
    );
}

#[test]
fn parse_profile_aliases_work() {
    assert_eq!(
        parse_field_profile("toy"),
        Some(BrakedownFieldProfile::ToyF97)
    );
    assert_eq!(
        parse_field_profile("m61"),
        Some(BrakedownFieldProfile::Mersenne61Ext2)
    );
    assert_eq!(
        parse_field_profile("gold"),
        Some(BrakedownFieldProfile::Goldilocks64Ext2)
    );
    assert!(parse_field_profile("unknown").is_none());
}
