use std::{path::PathBuf, str};

use anyhow::{anyhow, Result};
use zk_linear::{
    core::field::{Fp, ModulusScope},
    io::case_format::{load_spartan_like_case_from_dir, SpartanLikeCase},
    nizk::spartan_brakedown::{
        compile_from_dir_with_profile, parse_field_profile, prove_with_compiled_from_dir,
        verify_from_dir_strict, verify_with_compiled,
    },
    pcs::brakedown::{
        profiles::params_for_field_profile,
        wire::{serialize_eval_proof, serialize_verifier_commitment},
        BrakedownPcs,
    },
    protocol::{
        reference::{append_reference_profile_to_transcript, DUAL_REFERENCE_PROFILE},
        shared::{
            append_case_digest_to_transcript, append_field_profile_to_transcript, bind_rows,
            build_eq_weights_from_challenges, compute_case_digest, matrix_vec_mul,
            sample_outer_tau_from_transcript,
        },
        spec_v1::{
            append_spec_domain, append_u64_le, BLIND_MIX_LABEL, INNER_SUMCHECK_JOINT_LABEL,
            JOINT_CHALLENGE_DOMAIN, JOINT_CHALLENGE_RA_LABEL, JOINT_CHALLENGE_RB_LABEL,
            JOINT_CHALLENGE_RC_LABEL, LCPC_COL_OPEN_LABEL, LCPC_DEG_TEST_LABEL,
            NIZK_TRANSCRIPT_LABEL, OUTER_SUMCHECK_LABEL, OUTER_TAU_LABEL, TRANSCRIPT_DOMAIN,
        },
    },
};

fn label_to_str(label: &[u8]) -> &str {
    str::from_utf8(label).unwrap_or("<non-utf8>")
}

fn fmt_vec_head(v: &[Fp], head: usize) -> String {
    let mut out = String::new();
    out.push('[');
    for (i, x) in v.iter().take(head).enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&x.0.to_string());
    }
    if v.len() > head {
        out.push_str(", ...");
    }
    out.push(']');
    out
}

fn fmt_row_head(m: &[Vec<Fp>], row: usize, head: usize) -> String {
    if m.is_empty() || row >= m.len() {
        return "[]".to_string();
    }
    fmt_vec_head(&m[row], head)
}

fn dot(a: &[Fp], b: &[Fp]) -> Fp {
    a.iter()
        .zip(b.iter())
        .fold(Fp::zero(), |acc, (x, y)| acc.add((*x).mul(*y)))
}

fn parse_args() -> Result<(PathBuf, String, usize)> {
    let mut args = std::env::args().skip(1);
    let case_dir = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("tests/inner_sumcheck_spartan"));
    let profile_s = args.next().unwrap_or_else(|| "m61".to_string());
    let show_head = args
        .next()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(8)
        .max(1);
    Ok((case_dir, profile_s, show_head))
}

fn print_case_snapshot(case: &SpartanLikeCase, show_head: usize) {
    println!("[Input Snapshot]");
    println!(
        "- A: {}x{} | first row head: {}",
        case.a.len(),
        case.a[0].len(),
        fmt_row_head(&case.a, 0, show_head)
    );
    println!(
        "- B: {}x{} | first row head: {}",
        case.b.len(),
        case.b[0].len(),
        fmt_row_head(&case.b, 0, show_head)
    );
    println!(
        "- C: {}x{} | first row head: {}",
        case.c.len(),
        case.c[0].len(),
        fmt_row_head(&case.c, 0, show_head)
    );
    println!(
        "- z: len={} | head: {}",
        case.z.len(),
        fmt_vec_head(&case.z, show_head)
    );
}

fn main() -> Result<()> {
    let (case_dir, profile_s, show_head) = parse_args()?;
    let profile = parse_field_profile(&profile_s).ok_or_else(|| {
        anyhow!(
            "unknown profile '{}'; use one of: toy | m61 | gold",
            profile_s
        )
    })?;

    let _scope = ModulusScope::enter(profile.base_modulus());
    let case = load_spartan_like_case_from_dir(&case_dir)?;
    let rows = case.a.len();
    let cols = case.a[0].len();
    let digest = compute_case_digest(&case);

    println!("=== E2E Explain Profile (Spartan2 + Brakedown + Spielman) ===");
    println!();
    println!("[Run Config]");
    println!("- case_dir: {}", case_dir.display());
    println!("- field_profile: {:?}", profile);
    println!("- base_modulus: {}", profile.base_modulus());
    println!("- rows: {} (2^{})", rows, rows.trailing_zeros());
    println!("- cols: {} (2^{})", cols, cols.trailing_zeros());
    println!("- circuit_digest(A,B,C only): {}", hex::encode(digest));
    println!();

    print_case_snapshot(&case, show_head);
    println!();

    println!("[Randomness + Transcript Contract]");
    println!(
        "- domain: {} / transcript: {}",
        label_to_str(TRANSCRIPT_DOMAIN),
        label_to_str(NIZK_TRANSCRIPT_LABEL)
    );
    println!(
        "- outer tau: Merlin(label={}, idx) after domain/reference/field/case-digest binding",
        label_to_str(OUTER_TAU_LABEL)
    );
    println!(
        "- outer round FS: Merlin(label={}, round_idx, g0,g2,g3)",
        label_to_str(OUTER_SUMCHECK_LABEL)
    );
    println!(
        "- joint challenges FS: Merlin(domain={}, challenges=[{}, {}, {}])",
        label_to_str(JOINT_CHALLENGE_DOMAIN),
        label_to_str(JOINT_CHALLENGE_RA_LABEL),
        label_to_str(JOINT_CHALLENGE_RB_LABEL),
        label_to_str(JOINT_CHALLENGE_RC_LABEL)
    );
    println!(
        "- inner round FS: Merlin(label={}, round_idx, h0,h1,h2)",
        label_to_str(INNER_SUMCHECK_JOINT_LABEL)
    );
    println!(
        "- PCS transcript labels: deg_test={}, col_open={}",
        label_to_str(LCPC_DEG_TEST_LABEL),
        label_to_str(LCPC_COL_OPEN_LABEL)
    );
    println!(
        "- transcript order note: polycommit(root,ncols) is bound before tau/outer/joint/inner"
    );
    println!(
        "- blind mix label (reserved/reference): {}",
        label_to_str(BLIND_MIX_LABEL)
    );
    println!();

    let compiled = compile_from_dir_with_profile(&case_dir, profile)?;
    let res = prove_with_compiled_from_dir(&compiled, &case_dir)?;

    let az = matrix_vec_mul(&case.a, &case.z);
    let bz = matrix_vec_mul(&case.b, &case.z);
    let cz = matrix_vec_mul(&case.c, &case.z);
    let residual = az
        .iter()
        .zip(bz.iter())
        .zip(cz.iter())
        .map(|((a, b), c)| a.mul(*b).sub(*c))
        .collect::<Vec<_>>();

    let params = params_for_field_profile(cols, profile);
    let pcs = BrakedownPcs::new(params.clone());

    let row_vars = rows.trailing_zeros() as usize;
    let mut tr_tau = merlin::Transcript::new(NIZK_TRANSCRIPT_LABEL);
    append_spec_domain(&mut tr_tau);
    append_reference_profile_to_transcript(&mut tr_tau, &DUAL_REFERENCE_PROFILE);
    append_field_profile_to_transcript(&mut tr_tau, profile);
    append_case_digest_to_transcript(&mut tr_tau, rows, cols, digest);
    tr_tau.append_message(b"polycommit", &res.proof.verifier_commitment.root);
    append_u64_le(
        &mut tr_tau,
        b"ncols",
        res.proof.verifier_commitment.n_cols as u64,
    );
    let tau = sample_outer_tau_from_transcript(&mut tr_tau, row_vars);
    let eq_tau = build_eq_weights_from_challenges(&tau);
    let weighted_residual = residual
        .iter()
        .zip(eq_tau.iter())
        .map(|(r, w)| r.mul(*w))
        .collect::<Vec<_>>();
    let expected_outer_claim = weighted_residual
        .iter()
        .fold(Fp::zero(), |acc, v| acc.add(*v));

    let outer_chals = res
        .proof
        .outer_trace
        .rounds
        .iter()
        .map(|r| r.challenge_r)
        .collect::<Vec<_>>();
    let row_weights = build_eq_weights_from_challenges(&outer_chals);
    let a_bound = bind_rows(&case.a, &row_weights);
    let b_bound = bind_rows(&case.b, &row_weights);
    let c_bound = bind_rows(&case.c, &row_weights);

    let r_a = res.proof.joint_challenges.r_a;
    let r_b = res.proof.joint_challenges.r_b;
    let r_c = res.proof.joint_challenges.r_c;
    let joint_bound = a_bound
        .iter()
        .zip(b_bound.iter())
        .zip(c_bound.iter())
        .map(|((a, b), c)| r_a.mul(*a).add(r_b.mul(*b)).add(r_c.mul(*c)))
        .collect::<Vec<_>>();
    let expected_inner_claim = dot(&joint_bound, &case.z);

    let inner_chals = res
        .proof
        .inner_trace
        .rounds
        .iter()
        .map(|r| r.challenge_r)
        .collect::<Vec<_>>();
    let eq_r = build_eq_weights_from_challenges(&inner_chals);
    let expected_final_g = dot(&eq_r, &case.z);

    println!("[E2E Flow: Prover Side]");
    println!("1) Input parse -> Az/Bz/Cz/residual computation");
    println!("   - Az head: {}", fmt_vec_head(&az, show_head));
    println!("   - Bz head: {}", fmt_vec_head(&bz, show_head));
    println!("   - Cz head: {}", fmt_vec_head(&cz, show_head));
    println!("   - residual head: {}", fmt_vec_head(&residual, show_head));
    println!();

    println!("2) PCS commit + transcript binding");
    println!(
        "   - params: encoder={:?}, n_degree_tests={}, n_col_opens={}, col_open_start={}",
        params.encoder_kind, params.n_degree_tests, params.n_col_opens, params.col_open_start
    );
    println!(
        "   - encoded n_cols={} | verifier commitment dims=({}, {}, {})",
        pcs.encoding.n_cols,
        res.proof.verifier_commitment.n_rows,
        res.proof.verifier_commitment.n_per_row,
        res.proof.verifier_commitment.n_cols
    );
    println!(
        "   - commitment root: {}",
        hex::encode(res.proof.verifier_commitment.root)
    );
    println!("   - bound to transcript before tau/outer/joint/inner");
    println!();

    println!("3) Outer sumcheck binding");
    println!("   - tau(head): {}", fmt_vec_head(&tau, show_head));
    println!("   - eq(tau) head: {}", fmt_vec_head(&eq_tau, show_head));
    println!(
        "   - outer claim: expected={} | proof={} | ok={}",
        expected_outer_claim.0,
        res.proof.outer_trace.claim_initial.0,
        expected_outer_claim == res.proof.outer_trace.claim_initial
    );
    for rr in &res.proof.outer_trace.rounds {
        println!(
            "   - round {}: g0={}, g2={}, g3={}, r={}",
            rr.round, rr.g_at_0.0, rr.g_at_2.0, rr.g_at_3.0, rr.challenge_r.0
        );
    }
    println!(
        "   - outer final_value={}, final_claim={}",
        res.proof.outer_trace.final_value.0, res.proof.outer_trace.final_claim.0
    );
    println!();

    println!("4) Joint binding + inner sumcheck + PCS opening");
    println!("   - r_a={}, r_b={}, r_c={}", r_a.0, r_b.0, r_c.0);
    println!("   - a_bound head: {}", fmt_vec_head(&a_bound, show_head));
    println!("   - b_bound head: {}", fmt_vec_head(&b_bound, show_head));
    println!("   - c_bound head: {}", fmt_vec_head(&c_bound, show_head));
    println!(
        "   - joint_bound head: {}",
        fmt_vec_head(&joint_bound, show_head)
    );
    println!(
        "   - inner claim: expected={} | proof={} | ok={}",
        expected_inner_claim.0,
        res.proof.inner_trace.claim_initial.0,
        expected_inner_claim == res.proof.inner_trace.claim_initial
    );
    for rr in &res.proof.inner_trace.rounds {
        println!(
            "   - round {}: h0={}, h1={}, h2={}, r={}",
            rr.round, rr.h_at_0.0, rr.h_at_1.0, rr.h_at_2.0, rr.challenge_r.0
        );
    }
    println!(
        "   - inner final_f={}, final_g={}, final_claim={}",
        res.proof.inner_trace.final_f.0,
        res.proof.inner_trace.final_g.0,
        res.proof.inner_trace.final_claim.0
    );
    println!(
        "   - expected final_g from eq(r)·z={} | ok={}",
        expected_final_g.0,
        expected_final_g == res.proof.inner_trace.final_g
    );
    println!(
        "   - proof.p_eval.len={}, p_random_vec.len={}, opened_cols={}",
        res.proof.pcs_proof_joint_eval_at_r.p_eval.len(),
        res.proof.pcs_proof_joint_eval_at_r.p_random_vec.len(),
        res.proof.pcs_proof_joint_eval_at_r.columns.len()
    );
    println!(
        "   - opened col idx: {:?}",
        res.proof
            .pcs_proof_joint_eval_at_r
            .columns
            .iter()
            .map(|c| c.col_idx)
            .collect::<Vec<_>>()
    );
    println!();

    let vc_bytes = serialize_verifier_commitment(&res.proof.verifier_commitment).len();
    let eval_bytes = serialize_eval_proof(&res.proof.pcs_proof_joint_eval_at_r).len();

    println!("[Proof/Public Boundary]");
    println!("- public: rows, cols, case_digest, field_profile");
    println!(
        "- proof: outer_trace + inner_trace + (r_a,r_b,r_c) + verifier_commitment + pcs_opening"
    );
    println!(
        "- serialized bytes: verifier_commitment={}B, pcs_opening={}B, subtotal={}B",
        vc_bytes,
        eval_bytes,
        vc_bytes + eval_bytes
    );
    println!();

    println!("[Verifier Side]");
    verify_with_compiled(&compiled, &res.proof, &res.public)?;
    println!("- succinct(public+proof) verify: PASS");

    verify_from_dir_strict(&case_dir, &res.proof)?;
    println!("- strict replay(case+proof) verify: PASS");

    println!(
        "- verifier read set: public(rows/cols/digest/profile), sumcheck messages, (r_a,r_b,r_c), commitment root+dims, PCS opening"
    );
    println!("- verifier compute set: FS challenge replay, compact sumcheck transitions, PCS opening consistency + claimed eval check");
    println!();

    println!("[Timing]");
    println!("- input_parse_ms: {:.3}", res.timings.k0_input_parse_ms);
    println!(
        "- spartan_prove_core_ms: {:.3}",
        res.timings.k1_spartan_prove_ms
    );
    println!(
        "- pcs_commit_open_prove_ms: {:.3}",
        res.timings.k2_pcs_prove_ms
    );
    println!("- verify_ms: {:.3}", res.timings.k3_verify_ms);
    println!("- total_ms: {:.3}", res.timings.total_ms());

    Ok(())
}
