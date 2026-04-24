use std::path::PathBuf;

use merlin::Transcript;
use zk_linear::{
    core::{
        field::{Fp, ModulusScope},
        transcript::derive_round_challenge_merlin,
    },
    io::instance_format::load_spartan_like_instance,
    nizk::spartan_brakedown::prove,
    pcs::brakedown::challenges::sample_field_vec_round_t,
    protocol::{
        reference::{append_reference_profile_to_transcript, DUAL_REFERENCE_PROFILE},
        shared::{
            append_field_profile_to_transcript, append_instance_digest_to_transcript,
            matrix_vec_mul, sample_joint_challenges_from_transcript,
            sample_outer_tau_from_transcript,
        },
        spec_v1::{
            append_spec_domain, append_u64_le, INNER_SUMCHECK_JOINT_LABEL, LCPC_DEG_TEST_LABEL,
            NIZK_TRANSCRIPT_LABEL, OUTER_SUMCHECK_LABEL,
        },
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

fn replay_degree_tensors(
    result: &zk_linear::nizk::spartan_brakedown::SpartanBrakedownPipelineResult,
) -> Vec<Vec<Fp>> {
    let proof = &result.proof;
    let public = &result.public;

    let mut tr_v = Transcript::new(NIZK_TRANSCRIPT_LABEL);
    append_spec_domain(&mut tr_v);
    append_reference_profile_to_transcript(&mut tr_v, &DUAL_REFERENCE_PROFILE);
    append_field_profile_to_transcript(&mut tr_v, public.field_profile);
    append_instance_digest_to_transcript(
        &mut tr_v,
        public.rows,
        public.cols,
        public.instance_digest,
    );
    tr_v.append_message(b"polycommit", &proof.verifier_commitment.root);
    append_u64_le(&mut tr_v, b"ncols", proof.verifier_commitment.n_cols as u64);
    let _tau = sample_outer_tau_from_transcript(&mut tr_v, public.rows.trailing_zeros() as usize);

    for r in &proof.outer_trace.rounds {
        let expected_r = derive_round_challenge_merlin(
            &mut tr_v,
            OUTER_SUMCHECK_LABEL,
            r.round,
            r.g_at_0,
            r.g_at_2,
            r.g_at_3,
        );
        assert_eq!(expected_r, r.challenge_r);
    }

    let expected_joint = sample_joint_challenges_from_transcript(&mut tr_v);
    assert_eq!(expected_joint.0, proof.joint_challenges.r_a);
    assert_eq!(expected_joint.1, proof.joint_challenges.r_b);
    assert_eq!(expected_joint.2, proof.joint_challenges.r_c);

    for r in &proof.inner_trace.rounds {
        let expected_r = derive_round_challenge_merlin(
            &mut tr_v,
            INNER_SUMCHECK_JOINT_LABEL,
            r.round,
            r.h_at_0,
            r.h_at_1,
            r.h_at_2,
        );
        assert_eq!(expected_r, r.challenge_r);
    }

    tr_v.append_message(b"nizk_opening_label", b"joint_eval_at_r");

    let mut out = Vec::with_capacity(proof.pcs_proof_joint_eval_at_r.p_random_vec.len());
    for (round, p_rand) in proof
        .pcs_proof_joint_eval_at_r
        .p_random_vec
        .iter()
        .enumerate()
    {
        let t = sample_field_vec_round_t::<Fp>(
            &mut tr_v,
            LCPC_DEG_TEST_LABEL,
            round as u64,
            proof.verifier_commitment.n_rows,
        );
        out.push(t);
        for v in p_rand {
            tr_v.append_message(b"p_random", &v.0.to_le_bytes());
        }
    }
    out
}

#[test]
fn leakage_001_reference_path_exposes_degree_test_row_collapses() {
    run_instance!(
        "leakage_001",
        "reference path exposes degree-test row-collapses",
        "input: pipeline proof payload",
        "check=p_random_vec_presence",
        {
            let result = prove(&instance_dir()).expect("prove should succeed");
            testlog::data(
                "p_random_vec_len",
                result.proof.pcs_proof_joint_eval_at_r.p_random_vec.len(),
            );
            assert!(
                !result
                    .proof
                    .pcs_proof_joint_eval_at_r
                    .p_random_vec
                    .is_empty(),
                "reference-aligned proof currently includes degree-test random row-collapses"
            );
        }
    );
}

#[test]
fn leakage_002_reference_path_can_recover_bound_rows_from_p_random_vec() {
    run_instance!(
        "leakage_002",
        "committed witness row is recoverable from p_random_vec",
        "input: proof p_random_vec + transcript-replayed degree tensors",
        "assumption=n_rows=1 witness layout",
        {
            let result = prove(&instance_dir()).expect("prove should succeed");
            let _mod_scope = ModulusScope::enter(result.public.field_profile.base_modulus());

            let instance = load_spartan_like_instance(&instance_dir()).expect("load instance");
            let az = matrix_vec_mul(&instance.a, &instance.z);
            let bz = matrix_vec_mul(&instance.b, &instance.z);
            let cz = matrix_vec_mul(&instance.c, &instance.z);
            let _residual: Vec<Fp> = az
                .iter()
                .zip(bz.iter())
                .zip(cz.iter())
                .map(|((a, b), c)| a.mul(*b).sub(*c))
                .collect();

            let rand_tensors = replay_degree_tensors(&result);
            assert!(
                !rand_tensors.is_empty(),
                "degree-test rounds must be >= 1 for this probe"
            );
            assert_eq!(result.proof.verifier_commitment.n_rows, 1);

            let round_idx = rand_tensors
                .iter()
                .enumerate()
                .find_map(|(i, t)| (t[0] != Fp::zero()).then_some(i))
                .expect("at least one non-zero degree-test scalar");
            let scalar = rand_tensors[round_idx][0];
            let scalar_inv = scalar.inv().expect("non-zero scalar must be invertible");

            let pf = &result.proof.pcs_proof_joint_eval_at_r;
            let cols = pf.p_eval.len();
            testlog::data("recovery_cols", cols);
            let mut recovered_z = vec![Fp::zero(); cols];
            for c in 0..cols {
                recovered_z[c] = pf.p_random_vec[round_idx][c].mul(scalar_inv);
            }

            assert_eq!(recovered_z, instance.z);
        }
    );
}
