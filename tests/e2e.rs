use std::{fs, path::PathBuf};

use zk_linear::{
    core::field::{Fp, ModulusScope},
    nizk::spartan_brakedown::{
        compile_from_dir, prove_from_dir, prove_with_compiled_from_dir, verify_from_dir_strict,
        verify_public, verify_with_compiled,
    },
    protocol::reference::DUAL_REFERENCE_PROFILE,
};
#[path = "testlog.rs"]
mod testlog;

macro_rules! run_case {
    ($id:expr, $summary:expr, $io:expr, $settings:expr, $body:block) => {{
        testlog::run_case($id, $summary, $io, $settings, || $body)
    }};
}

fn case_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/inner_sumcheck_spartan")
}

fn repo_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

#[test]
fn e2e_001_nizk_public_verify_succeeds_on_valid_proof() {
    run_case!(
        "e2e_001",
        "nizk public verifier accepts valid proof",
        "input: case dir -> (proof, public)",
        "verify=public boundary",
        {
            let result = prove_from_dir(&case_dir()).expect("prove should succeed");
            testlog::data("rows", result.public.rows);
            testlog::data("cols", result.public.cols);
            verify_public(&result.proof, &result.public).expect("verify should succeed");
        }
    );
}

#[test]
fn e2e_002_nizk_strict_replay_verify_succeeds() {
    run_case!(
        "e2e_002",
        "strict replay verifier accepts valid proof",
        "input: case dir + proof",
        "verify=strict replay",
        {
            let result = prove_from_dir(&case_dir()).expect("prove should succeed");
            verify_from_dir_strict(&case_dir(), &result.proof)
                .expect("strict replay verify should succeed");
        }
    );
}

#[test]
fn e2e_003_nizk_public_verify_rejects_tampered_root() {
    run_case!(
        "e2e_003",
        "tampered commitment root is rejected",
        "input: valid proof with root bit flipped",
        "verify=public boundary",
        {
            let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
            result.proof.verifier_commitment.root[0] ^= 1;

            let err = verify_public(&result.proof, &result.public)
                .expect_err("verify should fail for tampered root");
            testlog::data("error", &err);
            assert!(
                err.to_string().contains("merkle path failed")
                    || err.to_string().contains("opened column index mismatch")
                    || err.to_string().contains("commitment encoder profile mismatch")
            );
        }
    );
}

#[test]
fn e2e_004_nizk_public_verify_rejects_wrong_claimed_value() {
    run_case!(
        "e2e_004",
        "wrong claimed value is rejected",
        "input: mutate final_f/final_g while keeping final_claim relation",
        "verify=public boundary",
        {
            let mut result = prove_from_dir(&case_dir()).expect("prove should succeed");
            let _scope = ModulusScope::enter(result.public.field_profile.base_modulus());

            let mut new_final_f = result.proof.inner_trace.final_f.add(Fp::new(1));
            if new_final_f == Fp::zero() {
                new_final_f = new_final_f.add(Fp::new(1));
            }
            let new_final_g = result
                .proof
                .inner_trace
                .final_claim
                .mul(new_final_f.inv().expect("non-zero field element must be invertible"));

            result.proof.inner_trace.final_f = new_final_f;
            result.proof.inner_trace.final_g = new_final_g;

            let err = verify_public(&result.proof, &result.public)
                .expect_err("verify should fail for wrong claimed value");
            testlog::data("error", &err);
            assert!(err.to_string().contains("claimed evaluation mismatch"));
        }
    );
}

#[test]
fn e2e_005_nizk_compiled_verify_succeeds_and_detects_context_mismatch() {
    run_case!(
        "e2e_005",
        "compiled boundary catches context mismatch",
        "input: compiled + proof + public with later compiled fingerprint tamper",
        "verify=compiled boundary",
        {
            let mut compiled = compile_from_dir(&case_dir()).expect("compile should succeed");
            let result = prove_with_compiled_from_dir(&compiled, &case_dir())
                .expect("prove with compiled should succeed");

            verify_with_compiled(&compiled, &result.proof, &result.public)
                .expect("verify_with_compiled should succeed");

            compiled.context_fingerprint[0] ^= 1;
            let err = verify_with_compiled(&compiled, &result.proof, &result.public)
                .expect_err("verify_with_compiled should fail for bad compiled fingerprint");
            testlog::data("error", &err);
            assert!(err.to_string().contains("compiled context fingerprint mismatch"));
        }
    );
}

#[test]
fn e2e_006_pipeline_metadata_sidecars_are_consistent() {
    run_case!(
        "e2e_006",
        "proof/public metadata sidecars are internally consistent",
        "input: pipeline result",
        "meta=reference_profile+context_fingerprint",
        {
            let result = prove_from_dir(&case_dir()).expect("prove should succeed");
            testlog::data(
                "ctx_head",
                hex::encode(&result.proof_meta.context_fingerprint[..4]),
            );

            assert_eq!(result.proof_meta.reference_profile, DUAL_REFERENCE_PROFILE);
            assert_eq!(result.public_meta.reference_profile, DUAL_REFERENCE_PROFILE);
            assert_eq!(
                result.proof_meta.context_fingerprint,
                result.public_meta.context_fingerprint
            );
        }
    );
}

#[test]
fn e2e_007_cli_verify_path_uses_compiled_public_boundary_only() {
    run_case!(
        "e2e_007",
        "CLI verify path remains on compiled/public boundary",
        "input: spark_e2e_cli.rs source",
        "lock=verify_with_compiled only",
        {
            let cli_src = fs::read_to_string(repo_path("src/bin/spark_e2e_cli.rs"))
                .expect("failed to read spark_e2e_cli.rs");

            assert!(
                cli_src.contains("verify_with_compiled("),
                "CLI verify path must use verify_with_compiled"
            );
            assert!(
                !cli_src.contains("verify_from_dir_strict("),
                "strict replay verifier must stay out of CLI verify path"
            );
        }
    );
}
