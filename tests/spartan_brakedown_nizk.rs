use std::path::PathBuf;

use zk_linear::{
    core::field::Fp,
    nizk::spartan_brakedown::{build_pipeline_report_from_dir, prove_from_dir, verify_from_dir},
    protocol::reference::{PcsReference, ProtocolReference},
};

fn case_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/inner_sumcheck_spartan")
}

#[test]
fn spartan_brakedown_full_style_report_main_like() {
    let report = build_pipeline_report_from_dir(&case_dir()).expect("pipeline report should build");
    println!("{}", report);

    assert!(report.contains("[Prove/Kernels]"));
    assert!(report.contains("[Payload Prove -> Verify]"));
    assert!(report.contains("[Verify]"));
    assert!(report.contains("verify_result: success"));
}

#[test]
fn spartan_brakedown_full_style_verify_succeeds() {
    let result = prove_from_dir(&case_dir()).expect("prove should succeed");
    verify_from_dir(&case_dir(), &result.proof).expect("verify should succeed");
}

#[test]
fn spartan_brakedown_full_style_fails_on_wrong_claimed_value() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.claimed_value = result.proof.claimed_value.add(Fp::new(1));

    let err = verify_from_dir(&case_dir(), &result.proof)
        .expect_err("verify should fail for wrong claimed value");
    assert!(
        err.to_string().contains("masked claimed value mismatch")
            || err.to_string().contains("claimed evaluation mismatch")
    );
}

#[test]
fn spartan_brakedown_full_style_fails_on_tampered_root() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.verifier_commitment.root[0] ^= 1;

    let err = verify_from_dir(&case_dir(), &result.proof)
        .expect_err("verify should fail for tampered root");
    assert!(
        err.to_string().contains("merkle path failed")
            || err.to_string().contains("opened column index mismatch")
    );
}

#[test]
fn spartan_brakedown_full_style_fails_on_tampered_blind_opening() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.pcs_proof_blind.columns[0].values[0] =
        result.proof.pcs_proof_blind.columns[0].values[0].add(Fp::new(1));

    let err = verify_from_dir(&case_dir(), &result.proof)
        .expect_err("verify should fail for tampered blind opening");
    assert!(
        err.to_string().contains("eval column check failed")
            || err.to_string().contains("degree-test column check failed")
            || err.to_string().contains("merkle path failed")
    );
}

#[test]
fn spartan_brakedown_full_style_fails_on_reference_profile_mismatch() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.reference_profile.protocol = ProtocolReference::ExperimentalAlt;
    result.proof.reference_profile.pcs = PcsReference::ExperimentalAlt;

    let err = verify_from_dir(&case_dir(), &result.proof)
        .expect_err("verify should fail for mismatched reference profile");
    assert!(err
        .to_string()
        .contains("unsupported reference profile for this NIZK flow"));
}

#[test]
fn spartan_brakedown_full_style_fails_on_tampered_outer_challenge() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.outer_trace.rounds[0].challenge_r =
        result.proof.outer_trace.rounds[0].challenge_r.add(Fp::new(1));

    let err = verify_from_dir(&case_dir(), &result.proof)
        .expect_err("verify should fail for tampered outer challenge");
    assert!(err.to_string().contains("outer challenge mismatch"));
}
