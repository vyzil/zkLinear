use std::path::PathBuf;

use zk_linear::{
    core::field::Fp,
    nizk::spartan_brakedown::{
        build_pipeline_report_from_dir, compile_from_dir, prove_from_dir,
        prove_with_compiled_from_dir, verify_from_dir_strict, verify_public, verify_with_compiled,
    },
    protocol::reference::{PcsReference, ProtocolReference},
    pcs::brakedown::types::BrakedownFieldProfile,
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
    verify_public(&result.proof, &result.public).expect("verify should succeed");
}

#[test]
fn spartan_brakedown_strict_replay_debug_verify_succeeds() {
    let result = prove_from_dir(&case_dir()).expect("prove should succeed");
    verify_from_dir_strict(&case_dir(), &result.proof).expect("strict replay verify should succeed");
}

#[test]
fn spartan_brakedown_full_style_fails_on_wrong_claimed_value() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.claimed_value = result.proof.claimed_value.add(Fp::new(1));

    let err = verify_public(&result.proof, &result.public)
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

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for tampered root");
    assert!(
        err.to_string()
            .contains("blind mix alpha mismatch vs transcript-derived challenge")
            || err.to_string().contains("masked claimed value mismatch")
            || err.to_string().contains("commitment encoder profile mismatch")
            || err.to_string().contains("commitment dimension/encoding mismatch")
            || err.to_string().contains("commitment field profile mismatch")
            || err.to_string().contains("commitment encoder profile mismatch")
            || err.to_string().contains("num openings mismatch")
            || err.to_string().contains("p_eval length mismatch")
            || err.to_string().contains("degree-test vector count mismatch")
            || err.to_string().contains("degree-test vector length mismatch")
            || err.to_string().contains("opened column index mismatch")
            || err.to_string().contains("opened column value length mismatch")
            || err.to_string().contains("opened column merkle path length mismatch")
            || err.to_string().contains("degree-test column check failed")
            || err.to_string().contains("eval column check failed")
            || err.to_string().contains("merkle path failed")
    );
}

#[test]
fn spartan_brakedown_strict_replay_fails_on_tampered_root() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.verifier_commitment.root[0] ^= 1;

    let err = verify_from_dir_strict(&case_dir(), &result.proof)
        .expect_err("strict replay verify should fail for tampered root");
    assert!(
        err.to_string()
            .contains("blind mix alpha mismatch vs transcript-derived challenge")
            || err.to_string().contains("merkle path failed")
            || err.to_string().contains("opened column index mismatch")
    );
}

#[test]
fn spartan_brakedown_full_style_fails_on_tampered_blind_opening() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.pcs_proof_blind_1.columns[0].values[0] =
        result.proof.pcs_proof_blind_1.columns[0].values[0].add(Fp::new(1));

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for tampered blind opening");
    assert!(
        err.to_string().contains("eval column check failed")
            || err.to_string().contains("degree-test column check failed")
            || err.to_string().contains("merkle path failed")
    );
}

#[test]
fn spartan_brakedown_full_style_fails_on_tampered_joint_eval_opening() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.pcs_proof_joint_eval_at_r.columns[0].values[0] =
        result.proof.pcs_proof_joint_eval_at_r.columns[0].values[0].add(Fp::new(1));

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for tampered joint-eval opening");
    assert!(
        err.to_string().contains("eval column check failed")
            || err.to_string().contains("degree-test column check failed")
            || err.to_string().contains("merkle path failed")
            || err.to_string().contains("claimed evaluation mismatch")
    );
}

#[test]
fn spartan_brakedown_full_style_fails_on_tampered_z_eval_opening() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.pcs_proof_z_eval_at_r.columns[0].values[0] =
        result.proof.pcs_proof_z_eval_at_r.columns[0].values[0].add(Fp::new(1));

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for tampered z-eval opening");
    assert!(
        err.to_string().contains("eval column check failed")
            || err.to_string().contains("degree-test column check failed")
            || err.to_string().contains("merkle path failed")
            || err.to_string().contains("claimed evaluation mismatch")
    );
}

#[test]
fn spartan_brakedown_full_style_fails_on_tampered_blind_mix_alpha() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.blind_mix_alpha = result.proof.blind_mix_alpha.add(Fp::new(1));

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for tampered blind mix alpha");
    assert!(err
        .to_string()
        .contains("blind mix alpha mismatch vs transcript-derived challenge"));
}

#[test]
fn spartan_brakedown_full_style_fails_on_tampered_blind_eval_1() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.blind_eval_1 = result.proof.blind_eval_1.add(Fp::new(1));

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for tampered blind_eval_1");
    assert!(err.to_string().contains("masked claimed value mismatch"));
}

#[test]
fn spartan_brakedown_full_style_fails_on_tampered_blind_eval_2() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.blind_eval_2 = result.proof.blind_eval_2.add(Fp::new(1));

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for tampered blind_eval_2");
    assert!(err.to_string().contains("masked claimed value mismatch"));
}

#[test]
fn spartan_brakedown_full_style_fails_on_swapped_blind_openings() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    std::mem::swap(
        &mut result.proof.pcs_proof_blind_1,
        &mut result.proof.pcs_proof_blind_2,
    );

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail when blind openings are swapped");
    assert!(
        err.to_string().contains("claimed evaluation mismatch")
            || err.to_string().contains("eval column check failed")
            || err.to_string().contains("degree-test column check failed")
            || err.to_string().contains("opened column index mismatch")
            || err.to_string().contains("merkle path failed")
    );
}

#[test]
fn spartan_brakedown_full_style_fails_on_reference_profile_mismatch() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.reference_profile.protocol = ProtocolReference::ExperimentalAlt;
    result.proof.reference_profile.pcs = PcsReference::ExperimentalAlt;

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for mismatched reference profile");
    assert!(err.to_string().contains("reference profile mismatch"));
}

#[test]
fn spartan_brakedown_full_style_fails_on_non_standard_reference_profile_even_if_matched() {
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
fn spartan_brakedown_full_style_fails_on_tampered_outer_challenge() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.outer_trace.rounds[0].challenge_r =
        result.proof.outer_trace.rounds[0].challenge_r.add(Fp::new(1));

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for tampered outer challenge");
    assert!(err.to_string().contains("outer challenge mismatch"));
}

#[test]
fn spartan_brakedown_full_style_fails_on_outer_round_index_mismatch() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.outer_trace.rounds[0].round += 1;

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for outer round index mismatch");
    assert!(err
        .to_string()
        .contains("outer round index mismatch at position"));
}

#[test]
fn spartan_brakedown_full_style_fails_on_tampered_outer_folded_values() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.outer_trace.rounds[0].folded_values[0] =
        result.proof.outer_trace.rounds[0].folded_values[0].add(Fp::new(1));

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for tampered outer folded values");
    assert!(err
        .to_string()
        .contains("outer sumcheck verification failed"));
}

#[test]
fn spartan_brakedown_full_style_fails_on_outer_folded_length_mismatch() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    let _ = result.proof.outer_trace.rounds[0].folded_values.pop();

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for outer folded length mismatch");
    assert!(err
        .to_string()
        .contains("outer folded vector length mismatch at round"));
}

#[test]
fn spartan_brakedown_full_style_fails_on_outer_final_value_mismatch() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.outer_trace.final_value = result.proof.outer_trace.final_value.add(Fp::new(1));

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for outer final value mismatch");
    assert!(err.to_string().contains("outer final value/claim mismatch"));
}

#[test]
fn spartan_brakedown_full_style_fails_on_inner_round_index_mismatch() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.inner_trace.rounds[0].round += 1;

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for inner round index mismatch");
    assert!(err
        .to_string()
        .contains("inner round index mismatch at position"));
}

#[test]
fn spartan_brakedown_full_style_fails_on_tampered_inner_folded_values() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.inner_trace.rounds[0].folded_f[0] =
        result.proof.inner_trace.rounds[0].folded_f[0].add(Fp::new(1));

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for tampered inner folded values");
    assert!(err
        .to_string()
        .contains("inner sumcheck verification failed"));
}

#[test]
fn spartan_brakedown_full_style_fails_on_inner_folded_length_mismatch() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    let _ = result.proof.inner_trace.rounds[0].folded_f.pop();

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for inner folded length mismatch");
    assert!(err
        .to_string()
        .contains("inner folded vector length mismatch at round"));
}

#[test]
fn spartan_brakedown_full_style_fails_on_public_context_fingerprint_mismatch() {
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
fn spartan_brakedown_full_style_fails_on_commitment_n_cols_mismatch() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.proof.verifier_commitment.n_cols += 1;

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for commitment n_cols mismatch");
    assert!(err
        .to_string()
        .contains("verifier commitment dimensions mismatch for blinded layout"));
}

#[test]
fn spartan_brakedown_full_style_fails_on_public_field_profile_mismatch() {
    let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
    result.public.field_profile = BrakedownFieldProfile::Goldilocks64Ext2;

    let err = verify_public(&result.proof, &result.public)
        .expect_err("verify should fail for public/proof field profile mismatch");
    assert!(err
        .to_string()
        .contains("public/proof field profile mismatch"));
}

#[test]
fn spartan_brakedown_full_style_fails_on_proof_context_fingerprint_mismatch() {
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
fn spartan_brakedown_with_compiled_fails_on_commitment_dimension_mismatch() {
    let compiled = compile_from_dir(&case_dir()).expect("compile should succeed");
    let mut result =
        prove_with_compiled_from_dir(&compiled, &case_dir()).expect("prove should succeed");
    result.proof.verifier_commitment.n_cols += 1;

    let err = verify_with_compiled(&compiled, &result.proof, &result.public)
        .expect_err("verify_with_compiled should fail for commitment dimension mismatch");
    assert!(err
        .to_string()
        .contains("compiled/proof verifier commitment dimensions mismatch"));
}

#[test]
fn spartan_brakedown_with_compiled_fails_on_public_field_profile_mismatch() {
    let compiled = compile_from_dir(&case_dir()).expect("compile should succeed");
    let mut result =
        prove_with_compiled_from_dir(&compiled, &case_dir()).expect("prove should succeed");
    result.public.field_profile = BrakedownFieldProfile::Goldilocks64Ext2;

    let err = verify_with_compiled(&compiled, &result.proof, &result.public)
        .expect_err("verify_with_compiled should fail for public field profile mismatch");
    assert!(err
        .to_string()
        .contains("compiled/public field profile mismatch"));
}
