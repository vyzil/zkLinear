use std::path::PathBuf;

use merlin::Transcript;
use zk_linear::{
    core::{
        field::{Fp, ModulusScope},
        transcript::derive_round_challenge_merlin,
    },
    io::case_format::load_spartan_like_case_from_dir,
    nizk::spartan_brakedown::prove_from_dir,
    pcs::brakedown::challenges::sample_field_vec_round_t,
    protocol::{
        reference::{append_reference_profile_to_transcript, DUAL_REFERENCE_PROFILE},
        shared::{
            append_case_digest_to_transcript, append_field_profile_to_transcript, bind_rows,
            build_eq_weights_from_challenges, derive_outer_tau_sha, matrix_vec_mul,
            sample_gamma_from_transcript_light,
        },
        spec_v1::{
            append_spec_domain, append_u64_le, INNER_SUMCHECK_JOINT_LABEL, LCPC_DEG_TEST_LABEL,
            NIZK_TRANSCRIPT_LABEL, OUTER_SUMCHECK_LABEL,
        },
    },
};

fn case_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/inner_sumcheck_spartan")
}

fn invert_3x3(a: [[Fp; 3]; 3]) -> Option<[[Fp; 3]; 3]> {
    let mut aug = vec![vec![Fp::zero(); 6]; 3];
    for i in 0..3 {
        for j in 0..3 {
            aug[i][j] = a[i][j];
        }
        aug[i][3 + i] = Fp::new(1);
    }

    for col in 0..3 {
        let mut pivot = None;
        for (r, row) in aug.iter().enumerate().skip(col).take(3 - col) {
            if row[col] != Fp::zero() {
                pivot = Some(r);
                break;
            }
        }
        let pivot_row = pivot?;
        if pivot_row != col {
            aug.swap(col, pivot_row);
        }

        let inv = aug[col][col].inv()?;
        for cell in aug[col].iter_mut().take(6) {
            *cell = cell.mul(inv);
        }
        let pivot_snapshot = aug[col].clone();

        for (r, row) in aug.iter_mut().enumerate().take(3) {
            if r == col {
                continue;
            }
            let factor = row[col];
            if factor == Fp::zero() {
                continue;
            }
            for (dst, src) in row.iter_mut().zip(pivot_snapshot.iter()).take(6) {
                *dst = dst.sub(factor.mul(*src));
            }
        }
    }

    let mut inv = [[Fp::zero(); 3]; 3];
    for i in 0..3 {
        for j in 0..3 {
            inv[i][j] = aug[i][3 + j];
        }
    }
    Some(inv)
}

fn mul_3x3_vec(a: [[Fp; 3]; 3], v: [Fp; 3]) -> [Fp; 3] {
    let mut out = [Fp::zero(); 3];
    for i in 0..3 {
        out[i] = a[i][0].mul(v[0]).add(a[i][1].mul(v[1])).add(a[i][2].mul(v[2]));
    }
    out
}

fn replay_degree_tensors(
    result: &zk_linear::nizk::spartan_brakedown::SpartanBrakedownPipelineResult,
) -> Vec<[Fp; 3]> {
    let proof = &result.proof;
    let public = &result.public;

    let mut tr_v = Transcript::new(NIZK_TRANSCRIPT_LABEL);
    append_spec_domain(&mut tr_v);
    append_reference_profile_to_transcript(&mut tr_v, &DUAL_REFERENCE_PROFILE);
    append_field_profile_to_transcript(&mut tr_v, public.field_profile);
    append_case_digest_to_transcript(&mut tr_v, public.rows, public.cols, public.case_digest);

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

    let expected_gamma = sample_gamma_from_transcript_light(&mut tr_v);
    assert_eq!(expected_gamma, proof.gamma);

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
    tr_v.append_message(b"polycommit", &proof.verifier_commitment.root);
    append_u64_le(&mut tr_v, b"ncols", proof.verifier_commitment.n_cols as u64);

    let mut out = Vec::with_capacity(proof.pcs_proof_joint_eval_at_r.p_random_vec.len());
    for (round, p_rand) in proof.pcs_proof_joint_eval_at_r.p_random_vec.iter().enumerate() {
        let t = sample_field_vec_round_t::<Fp>(&mut tr_v, LCPC_DEG_TEST_LABEL, round as u64, 3);
        out.push([t[0], t[1], t[2]]);
        for v in p_rand {
            tr_v.append_message(b"p_random", &v.0.to_le_bytes());
        }
    }
    out
}

#[test]
fn reference_path_leaks_bound_rows_via_p_random_vec() {
    let result = prove_from_dir(&case_dir()).expect("prove should succeed");
    let _mod_scope = ModulusScope::enter(result.public.field_profile.base_modulus());

    let case = load_spartan_like_case_from_dir(&case_dir()).expect("load case");
    let az = matrix_vec_mul(&case.a, &case.z);
    let bz = matrix_vec_mul(&case.b, &case.z);
    let cz = matrix_vec_mul(&case.c, &case.z);
    let _tau = derive_outer_tau_sha(case.a.len().trailing_zeros() as usize, &az, &bz, &cz, &case.z);
    let r_x = result
        .proof
        .outer_trace
        .rounds
        .iter()
        .map(|r| r.challenge_r)
        .collect::<Vec<_>>();
    let row_weights = build_eq_weights_from_challenges(&r_x);
    let a_bound = bind_rows(&case.a, &row_weights);
    let b_bound = bind_rows(&case.b, &row_weights);
    let c_bound = bind_rows(&case.c, &row_weights);

    let rand_tensors = replay_degree_tensors(&result);
    assert!(
        rand_tensors.len() >= 3,
        "degree-test rounds must be >=3 for this probe"
    );

    let mut inv_mat = None;
    let mut idx = [0usize; 3];
    for i in 0..rand_tensors.len() {
        for j in (i + 1)..rand_tensors.len() {
            for k in (j + 1)..rand_tensors.len() {
                let m = [rand_tensors[i], rand_tensors[j], rand_tensors[k]];
                if let Some(inv) = invert_3x3(m) {
                    inv_mat = Some(inv);
                    idx = [i, j, k];
                    break;
                }
            }
            if inv_mat.is_some() {
                break;
            }
        }
        if inv_mat.is_some() {
            break;
        }
    }
    let inv = inv_mat.expect("at least one invertible 3-round subset");

    let pf = &result.proof.pcs_proof_joint_eval_at_r;
    let cols = pf.p_eval.len();
    let mut rec_a = vec![Fp::zero(); cols];
    let mut rec_b = vec![Fp::zero(); cols];
    let mut rec_c = vec![Fp::zero(); cols];
    for c in 0..cols {
        let rhs = [
            pf.p_random_vec[idx[0]][c],
            pf.p_random_vec[idx[1]][c],
            pf.p_random_vec[idx[2]][c],
        ];
        let x = mul_3x3_vec(inv, rhs);
        rec_a[c] = x[0];
        rec_b[c] = x[1];
        rec_c[c] = x[2];
    }

    assert_eq!(rec_a, a_bound);
    assert_eq!(rec_b, b_bound);
    assert_eq!(rec_c, c_bound);
}
