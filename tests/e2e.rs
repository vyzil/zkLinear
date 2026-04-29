use std::{fs, path::PathBuf};

use merlin::Transcript;
use zk_linear::{
    core::field::{Fp, ModulusScope},
    core::transcript::derive_round_challenge_merlin,
    nizk::spartan_brakedown::{
        compile, prove, prove_with_compiled, verify_public, verify_strict, verify_with_compiled,
    },
    pcs::brakedown::types::BrakedownEncoderKind,
    protocol::reference::append_reference_profile_to_transcript,
    protocol::reference::DUAL_REFERENCE_PROFILE,
    protocol::shared::{
        append_field_profile_to_transcript, append_instance_digest_to_transcript,
        sample_joint_challenges_from_transcript,
    },
    protocol::spec_v1::{
        append_spec_domain, append_u64_le, NIZK_TRANSCRIPT_LABEL, OUTER_SUMCHECK_LABEL,
    },
};
#[path = "testlog.rs"]
mod testlog;

macro_rules! run_instance {
    ($id:expr, $summary:expr, $io:expr, $settings:expr, $body:block) => {{
        testlog::run_instance($id, $summary, $io, $settings, || $body)
    }};
}

fn instance_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/inner_sumcheck_spartan")
}

fn repo_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

#[test]
fn e2e_001_nizk_public_verify_succeeds_on_valid_proof() {
    run_instance!(
        "e2e_001",
        "nizk public verifier accepts valid proof",
        "input: instance dir -> (proof, public)",
        "verify=public boundary",
        {
            let result = prove(&instance_dir()).expect("prove should succeed");
            testlog::data("rows", result.public.rows);
            testlog::data("cols", result.public.cols);
            verify_public(&result.proof, &result.public).expect("verify should succeed");
        }
    );
}

#[test]
fn e2e_002_nizk_strict_replay_verify_succeeds() {
    run_instance!(
        "e2e_002",
        "strict replay verifier accepts valid proof",
        "input: instance dir + proof",
        "verify=strict replay",
        {
            let result = prove(&instance_dir()).expect("prove should succeed");
            verify_strict(&instance_dir(), &result.proof)
                .expect("strict replay verify should succeed");
        }
    );
}

#[test]
fn e2e_003_nizk_public_verify_rejects_tampered_root() {
    run_instance!(
        "e2e_003",
        "tampered commitment root is rejected",
        "input: valid proof with root bit flipped",
        "verify=public boundary",
        {
            let mut result = prove(&instance_dir()).expect("prove should succeed");
            result.proof.verifier_commitment.root[0] ^= 1;

            let err = verify_public(&result.proof, &result.public)
                .expect_err("verify should fail for tampered root");
            testlog::data("error", &err);
            assert!(
                err.to_string().contains("merkle path failed")
                    || err.to_string().contains("opened column index mismatch")
                    || err.to_string().contains("outer challenge mismatch")
                    || err
                        .to_string()
                        .contains("joint challenges mismatch vs transcript-derived challenges")
                    || err
                        .to_string()
                        .contains("commitment encoder profile mismatch")
            );
        }
    );
}

#[test]
fn e2e_004_nizk_public_verify_rejects_wrong_claimed_value() {
    run_instance!(
        "e2e_004",
        "wrong claimed value is rejected",
        "input: mutate final_f/final_g while keeping final_claim relation",
        "verify=public boundary",
        {
            let mut result = prove(&instance_dir()).expect("prove should succeed");
            let _scope = ModulusScope::enter(result.public.field_profile.base_modulus());

            let mut new_final_f = result.proof.inner_trace.final_f.add(Fp::new(1));
            if new_final_f == Fp::zero() {
                new_final_f = new_final_f.add(Fp::new(1));
            }
            let new_final_g = result.proof.inner_trace.final_claim.mul(
                new_final_f
                    .inv()
                    .expect("non-zero field element must be invertible"),
            );

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
    run_instance!(
        "e2e_005",
        "compiled boundary catches context mismatch",
        "input: compiled + proof + public with later compiled fingerprint tamper",
        "verify=compiled boundary",
        {
            let mut compiled = compile(&instance_dir()).expect("compile should succeed");
            let result = prove_with_compiled(&compiled, &instance_dir())
                .expect("prove with compiled should succeed");

            verify_with_compiled(&compiled, &result.proof, &result.public)
                .expect("verify_with_compiled should succeed");

            compiled.context_fingerprint[0] ^= 1;
            let err = verify_with_compiled(&compiled, &result.proof, &result.public)
                .expect_err("verify_with_compiled should fail for bad compiled fingerprint");
            testlog::data("error", &err);
            assert!(err
                .to_string()
                .contains("compiled context fingerprint mismatch"));
        }
    );
}

#[test]
fn e2e_006_pipeline_metadata_sidecars_are_consistent() {
    run_instance!(
        "e2e_006",
        "proof/public metadata sidecars are internally consistent",
        "input: pipeline result",
        "meta=reference_profile+context_fingerprint",
        {
            let result = prove(&instance_dir()).expect("prove should succeed");
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
    run_instance!(
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
                !cli_src.contains("verify_strict("),
                "strict replay verifier must stay out of CLI verify path"
            );
        }
    );
}

#[test]
fn e2e_008_nizk_public_verify_rejects_non_spielman_encoder_kind_policy() {
    run_instance!(
        "e2e_008",
        "public verifier rejects non-Spielman encoder kind by policy",
        "input: valid proof with commitment encoder_kind tampered",
        "verify=public boundary + reference alignment",
        {
            let mut result = prove(&instance_dir()).expect("prove should succeed");
            result.proof.verifier_commitment.encoder_kind = BrakedownEncoderKind::ToyHybrid;
            let err = verify_public(&result.proof, &result.public)
                .expect_err("verify should fail for non-Spielman encoder kind");
            testlog::data("error", &err);
            assert!(err.to_string().contains(
                "reference-alignment policy mismatch: verifier commitment encoder kind is not allowed"
            ));
        }
    );
}

#[test]
fn e2e_009_nizk_compiled_verify_rejects_nonzero_encoder_seed_policy() {
    run_instance!(
        "e2e_009",
        "compiled verifier rejects non-zero encoder seed by policy",
        "input: valid proof with commitment encoder_seed tampered",
        "verify=compiled boundary + reference alignment",
        {
            let compiled = compile(&instance_dir()).expect("compile should succeed");
            let mut result =
                prove_with_compiled(&compiled, &instance_dir()).expect("prove should succeed");
            result.proof.verifier_commitment.encoder_seed = 7;
            let err = verify_with_compiled(&compiled, &result.proof, &result.public)
                .expect_err("verify should fail for non-zero encoder seed");
            testlog::data("error", &err);
            assert!(err.to_string().contains(
                "reference-alignment policy mismatch: verifier commitment encoder seed is not allowed"
            ));
        }
    );
}

#[test]
fn e2e_010_nizk_public_verify_rejects_non_reference_spielman_profile_policy() {
    run_instance!(
        "e2e_010",
        "public verifier rejects non-reference Spielman profile knobs",
        "input: valid proof with commitment spel_layers tampered",
        "verify=public boundary + reference alignment",
        {
            let mut result = prove(&instance_dir()).expect("prove should succeed");
            result.proof.verifier_commitment.spel_layers ^= 1;
            let err = verify_public(&result.proof, &result.public)
                .expect_err("verify should fail for non-reference Spielman profile");
            testlog::data("error", &err);
            assert!(err.to_string().contains(
                "reference-alignment policy mismatch: verifier commitment Spielman profile is not allowed"
            ));
        }
    );
}

#[test]
fn e2e_011_nizk_public_verify_rejects_joint_challenges_from_wrong_derivation_point() {
    run_instance!(
        "e2e_011",
        "joint challenges must be sampled after outer rounds",
        "input: valid proof with joint challenges recomputed before outer rounds",
        "verify=public boundary + transcript conformance",
        {
            let mut result = prove(&instance_dir()).expect("prove should succeed");

            let mut tr = Transcript::new(NIZK_TRANSCRIPT_LABEL);
            append_spec_domain(&mut tr);
            append_reference_profile_to_transcript(&mut tr, &DUAL_REFERENCE_PROFILE);
            append_field_profile_to_transcript(&mut tr, result.public.field_profile);
            append_instance_digest_to_transcript(
                &mut tr,
                result.public.rows,
                result.public.cols,
                result.public.instance_digest,
            );
            tr.append_message(b"polycommit", &result.proof.verifier_commitment.root);
            append_u64_le(
                &mut tr,
                b"ncols",
                result.proof.verifier_commitment.n_cols as u64,
            );
            let (ra, rb, rc) = sample_joint_challenges_from_transcript(&mut tr);
            result.proof.joint_challenges.r_a = ra;
            result.proof.joint_challenges.r_b = rb;
            result.proof.joint_challenges.r_c = rc;

            let err = verify_public(&result.proof, &result.public)
                .expect_err("verify should fail when joint challenges are derived at wrong point");
            testlog::data("error", &err);
            assert!(err
                .to_string()
                .contains("joint challenges mismatch vs transcript-derived challenges"));
        }
    );
}

#[test]
fn e2e_012_nizk_public_verify_rejects_outer_challenge_not_bound_to_commitment() {
    run_instance!(
        "e2e_012",
        "outer challenge must be bound after commitment append",
        "input: valid proof with round-0 challenge recomputed before commitment append",
        "verify=public boundary + commit-before-challenge conformance",
        {
            let mut result = prove(&instance_dir()).expect("prove should succeed");
            let r0 = result
                .proof
                .outer_trace
                .rounds
                .first()
                .expect("outer round 0 must exist")
                .clone();

            let mut tr = Transcript::new(NIZK_TRANSCRIPT_LABEL);
            append_spec_domain(&mut tr);
            append_reference_profile_to_transcript(&mut tr, &DUAL_REFERENCE_PROFILE);
            append_field_profile_to_transcript(&mut tr, result.public.field_profile);
            append_instance_digest_to_transcript(
                &mut tr,
                result.public.rows,
                result.public.cols,
                result.public.instance_digest,
            );
            let wrong_r0 = derive_round_challenge_merlin(
                &mut tr,
                OUTER_SUMCHECK_LABEL,
                0,
                r0.g_at_0,
                r0.g_at_2,
                r0.g_at_3,
            );
            result.proof.outer_trace.rounds[0].challenge_r = wrong_r0;

            let err = verify_public(&result.proof, &result.public).expect_err(
                "verify should fail when outer challenge is not bound to commitment state",
            );
            testlog::data("error", &err);
            assert!(err
                .to_string()
                .contains("outer challenge mismatch at round 0"));
        }
    );
}
