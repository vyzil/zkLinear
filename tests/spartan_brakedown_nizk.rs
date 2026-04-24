use std::path::PathBuf;

use zk_linear::{
    core::field::{Fp, ModulusScope},
    nizk::spartan_brakedown::{
        build_pipeline_report_from_dir, compile_from_dir, prove_from_dir,
        prove_with_compiled_from_dir, verify_from_dir_strict, verify_public, verify_with_compiled,
    },
    pcs::brakedown::profiles::params_for_field_profile,
    pcs::brakedown::wire::{deserialize_eval_proof, serialize_eval_proof},
    pcs::brakedown::types::BrakedownFieldProfile,
    protocol::reference::{PcsReference, ProtocolReference},
};

fn case_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/inner_sumcheck_spartan")
}

#[test]
fn spartan_brakedown_report_builds() {
    let report = build_pipeline_report_from_dir(&case_dir()).expect("pipeline report should build");
    println!("{}", report);

    assert!(report.contains("[Prove/Kernels]"));
    assert!(report.contains("[Payload]"));
    assert!(report.contains("[Verify]"));
    assert!(report.contains("verify_result: success"));
}

#[test]
fn spartan_brakedown_verify_succeeds() {
    let result = prove_from_dir(&case_dir()).expect("prove should succeed");
    verify_public(&result.proof, &result.public).expect("verify should succeed");
}

#[test]
fn spartan_brakedown_strict_replay_succeeds() {
    let result = prove_from_dir(&case_dir()).expect("prove should succeed");
    verify_from_dir_strict(&case_dir(), &result.proof).expect("strict replay verify should succeed");
}

#[test]
fn spartan_brakedown_fails_on_tampered_root() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.verifier_commitment.root[0] ^= 1;

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for tampered root");
    assert!(
        err.to_string().contains("merkle path failed")
            || err.to_string().contains("opened column index mismatch")
            || err.to_string().contains("commitment encoder profile mismatch")
    );
}

#[test]
fn spartan_brakedown_fails_on_tampered_joint_opening() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.pcs_proof_joint_eval_at_r.columns[0].values[0] =
        result.proof.pcs_proof_joint_eval_at_r.columns[0].values[0].add(Fp::new(1));

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for tampered joint opening");
    assert!(
        err.to_string().contains("eval column check failed")
            || err.to_string().contains("degree-test column check failed")
            || err.to_string().contains("merkle path failed")
            || err.to_string().contains("claimed evaluation mismatch")
    );
}

#[test]
fn spartan_brakedown_fails_on_reference_profile_mismatch() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.reference_profile.protocol = ProtocolReference::ExperimentalAlt;
    result.proof.reference_profile.pcs = PcsReference::ExperimentalAlt;

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for mismatched reference profile");
    assert!(err.to_string().contains("reference profile mismatch"));
}

#[test]
fn spartan_brakedown_fails_on_non_standard_reference_profile_even_if_matched() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.reference_profile.protocol = ProtocolReference::ExperimentalAlt;
    result.proof.reference_profile.pcs = PcsReference::ExperimentalAlt;
    result.public.reference_profile.protocol = ProtocolReference::ExperimentalAlt;
    result.public.reference_profile.pcs = PcsReference::ExperimentalAlt;

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for non-standard reference profile");
    assert!(err
        .to_string()
        .contains("unsupported reference profile for this NIZK flow"));
}

#[test]
fn spartan_brakedown_fails_on_tampered_outer_challenge() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.outer_trace.rounds[0].challenge_r =
        result.proof.outer_trace.rounds[0].challenge_r.add(Fp::new(1));

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for tampered outer challenge");
    assert!(err.to_string().contains("outer challenge mismatch"));
}

#[test]
fn spartan_brakedown_fails_on_outer_round_index_mismatch() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.outer_trace.rounds[0].round += 1;

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for outer round index mismatch");
    assert!(err
        .to_string()
        .contains("outer round index mismatch at position"));
}

#[test]
fn spartan_brakedown_fails_on_outer_final_value_mismatch() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.outer_trace.final_value = result.proof.outer_trace.final_value.add(Fp::new(1));

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for outer final value mismatch");
    assert!(err.to_string().contains("outer final value/claim mismatch"));
}

#[test]
fn spartan_brakedown_fails_on_inner_round_index_mismatch() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.inner_trace.rounds[0].round += 1;

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for inner round index mismatch");
    assert!(err
        .to_string()
        .contains("inner round index mismatch at position"));
}

#[test]
fn spartan_brakedown_fails_on_public_context_fingerprint_mismatch() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.public.context_fingerprint[0] ^= 1;

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for context fingerprint mismatch");
    assert!(
        err.to_string()
            .contains("public/proof context fingerprint mismatch")
            || err.to_string().contains("public context fingerprint mismatch")
    );
}

#[test]
fn spartan_brakedown_fails_on_commitment_n_cols_mismatch() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.verifier_commitment.n_cols += 1;

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for commitment n_cols mismatch");
    assert!(err
        .to_string()
        .contains("verifier commitment dimensions mismatch for blinded layout"));
}

#[test]
fn spartan_brakedown_fails_on_public_field_profile_mismatch() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.public.field_profile = BrakedownFieldProfile::Goldilocks64Ext2;

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for public/proof field profile mismatch");
    assert!(err
        .to_string()
        .contains("public/proof field profile mismatch"));
}

#[test]
fn spartan_brakedown_fails_on_proof_context_fingerprint_mismatch() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.context_fingerprint[0] ^= 1;

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for context fingerprint mismatch");
    assert!(err
        .to_string()
        .contains("public/proof context fingerprint mismatch"));
}

#[test]
fn spartan_brakedown_with_compiled_fails_on_compiled_context_fingerprint_mismatch() {
    let mut compiled = compile_from_dir(&case_dir()).expect("compile should succeed");
    let result = prove_with_compiled_from_dir(&compiled, &case_dir()).expect("prove should succeed");
    compiled.context_fingerprint[0] ^= 1;

    let err = verify_with_compiled(&compiled, &result.proof, &result.public)
        .expect_err("verify_with_compiled should fail for compiled context mismatch");
    assert!(
        err.to_string()
            .contains("compiled context fingerprint mismatch")
            || err
                .to_string()
                .contains("compiled/public/proof context fingerprint mismatch")
    );
}

#[test]
fn spartan_brakedown_fails_on_wrong_claimed_value() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    let _scope = ModulusScope::enter(result.public.field_profile.base_modulus());
    let new_final_f = result.proof.inner_trace.final_f.add(Fp::new(1));
    let new_final_g = result
        .proof
        .inner_trace
        .final_claim
        .mul(new_final_f.inv().expect("non-zero field element must be invertible"));
    result.proof.inner_trace.final_f = new_final_f;
    result.proof.inner_trace.final_g = new_final_g;

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for wrong claimed value");
    assert!(err.to_string().contains("claimed evaluation mismatch"));
}

#[test]
fn spartan_brakedown_joint_opening_uses_reference_degree_tests() {
    let result = prove_from_dir(&case_dir()).expect("prove should succeed");
    let params = params_for_field_profile(result.public.cols, result.public.field_profile);
    assert!(
        !result.proof.pcs_proof_joint_eval_at_r.p_random_vec.is_empty(),
        "reference-aligned proof should include degree-test random row-collapses"
    );
    assert_eq!(
        result.proof.pcs_proof_joint_eval_at_r.p_random_vec.len(),
        params.n_degree_tests
    );
    assert_eq!(
        result.proof.pcs_proof_joint_eval_at_r.columns.len(),
        params.n_col_opens
    );
}

#[test]
fn spartan_brakedown_joint_opening_serialization_keeps_p_random_vectors() {
    let result = prove_from_dir(&case_dir()).expect("prove should succeed");
    let encoded = serialize_eval_proof(&result.proof.pcs_proof_joint_eval_at_r);
    let _scope = ModulusScope::enter(result.public.field_profile.base_modulus());
    let decoded = deserialize_eval_proof(&encoded).expect("deserialize eval proof");
    assert!(
        !decoded.p_random_vec.is_empty(),
        "reference-aligned proof serialization should carry p_random vectors"
    );
}
