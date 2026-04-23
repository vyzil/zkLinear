use std::{path::PathBuf, time::Instant};

use merlin::Transcript;
use zk_linear::{
    bridge::{prove_bridge_from_dir, verify_bridge_bundle, BRIDGE_TRANSCRIPT_LABEL},
    core::field::Fp,
    protocol::reference::{PcsReference, ProtocolReference},
};

fn case_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/inner_sumcheck_spartan")
}

#[test]
fn spartan_brakedown_style_pipeline_main_like() {
    println!("=== Spartan + Brakedown Style Pipeline (Research Bridge) ===");
    println!("\n[Scope]");
    println!("- This is NOT full Spartan2 NIZK integration.");
    println!(
    "- It is a staged software bridge: Spartan-like prove outputs -> Brakedown-style PCS commit/open/verify."
  );

    let dir = case_dir();
    let built = prove_bridge_from_dir(&dir).expect("bridge prove should succeed");

    let data = &built.spartan_data;
    let bundle = &built.bundle;
    let query = &built.verifier_query;

    println!("\n[Kernel: input_parse]");
    println!("input source: tests/inner_sumcheck_spartan/_A.data, _B.data, _C.data, _z.data");
    println!(
        "rows={}, cols={}, z_len={}",
        data.case.a.len(),
        data.case.a[0].len(),
        data.case.z.len()
    );
    println!(
        "A={:?}",
        data.case
            .a
            .iter()
            .map(|r| r.iter().map(|x| x.0).collect::<Vec<_>>())
            .collect::<Vec<_>>()
    );
    println!(
        "B={:?}",
        data.case
            .b
            .iter()
            .map(|r| r.iter().map(|x| x.0).collect::<Vec<_>>())
            .collect::<Vec<_>>()
    );
    println!(
        "C={:?}",
        data.case
            .c
            .iter()
            .map(|r| r.iter().map(|x| x.0).collect::<Vec<_>>())
            .collect::<Vec<_>>()
    );
    println!(
        "z={:?}",
        data.case.z.iter().map(|x| x.0).collect::<Vec<_>>()
    );
    println!("time: {:.3} ms", built.timings.k0_input_parse_ms);
    println!("payload -> spartan_prove_core: {{A, B, C, z}} [source=parsed input files]");

    println!("\n[Kernel: spartan_prove_core]");
    println!("input source: payload from input_parse");
    println!(
        "outer claim C0=sum(eq(tau)*residual)={}",
        bundle.outer_trace.claim_initial.0
    );
    println!(
        "outer rounds={}, r_x={:?}",
        bundle.outer_trace.rounds.len(),
        bundle
            .outer_trace
            .rounds
            .iter()
            .map(|r| r.challenge_r.0)
            .collect::<Vec<_>>()
    );
    println!(
        "row weights eq(r_x)={:?}",
        data.row_weights.iter().map(|x| x.0).collect::<Vec<_>>()
    );
    println!(
        "gamma={} (gamma^2={})",
        bundle.gamma.0,
        bundle.gamma.mul(bundle.gamma).0
    );
    println!(
        "A_bound={:?}",
        data.a_bound.iter().map(|x| x.0).collect::<Vec<_>>()
    );
    println!(
        "B_bound={:?}",
        data.b_bound.iter().map(|x| x.0).collect::<Vec<_>>()
    );
    println!(
        "C_bound={:?}",
        data.c_bound.iter().map(|x| x.0).collect::<Vec<_>>()
    );
    println!(
        "joint_bound={:?}",
        data.joint_bound.iter().map(|x| x.0).collect::<Vec<_>>()
    );
    println!(
        "joint inner claim C0=<joint_bound,z>={}",
        bundle.claimed_evaluation.0
    );
    println!("inner rounds={}", bundle.inner_trace.rounds.len());
    println!("time: {:.3} ms", built.timings.k1_spartan_ms);

    println!("payload -> pcs_commit_open_prove:");
    println!("  coeff rows=[A_bound, B_bound, C_bound] [source=spartan_prove_core row binding]");
    let derived_outer_tensor = [Fp::new(1), query.gamma, query.gamma.mul(query.gamma)];
    println!(
        "  outer tensor=[1, gamma, gamma^2] [source=spartan_prove_core challenge] => {:?}",
        derived_outer_tensor.iter().map(|x| x.0).collect::<Vec<_>>()
    );
    println!("  inner tensor=z [source=input_parse input, verifier-side hidden in bridge query]");
    println!(
        "  claimed value=<joint_bound,z>={} [source=spartan_prove_core inner claim]",
        query.claimed_value.0
    );

    println!("\n[Kernel: pcs_commit_open_prove]");
    println!("input source: payload from spartan_prove_core");
    println!(
        "coeff matrix dims: rows={}, per_row={}, encoded_cols={}",
        bundle.verifier_commitment.n_rows,
        bundle.verifier_commitment.n_per_row,
        bundle.verifier_commitment.n_cols
    );
    println!(
        "commitment(root)={}",
        hex::encode(bundle.verifier_commitment.root)
    );
    println!(
        "proof payload: p_eval_len={}, p_random_count={}, opened_cols={}",
        bundle.pcs_opening_proof.p_eval.len(),
        bundle.pcs_opening_proof.p_random_vec.len(),
        bundle.pcs_opening_proof.columns.len()
    );
    println!(
        "opened col indices={:?}",
        bundle
            .pcs_opening_proof
            .columns
            .iter()
            .map(|c| c.col_idx)
            .collect::<Vec<_>>()
    );
    println!("time: {:.3} ms", built.timings.k2_pcs_ms);

    println!("payload -> verify:");
    println!("  proof_bundle: outer/inner sumcheck traces + PCS commitment/opening");
    println!(
        "  verifier_query: gamma={}, claimed_value={}, case_digest={}",
        query.gamma.0,
        query.claimed_value.0,
        hex::encode(query.public_case_digest)
    );

    let t3 = Instant::now();
    let mut tr_v = Transcript::new(BRIDGE_TRANSCRIPT_LABEL);
    let verify =
        verify_bridge_bundle(bundle, query, &mut tr_v).expect("bridge verify should succeed");
    let k3_ms = t3.elapsed().as_secs_f64() * 1000.0;

    println!("\n[Kernel: verify]");
    println!("input source: proof_bundle + verifier_query");
    println!(
        "Spartan outer verify: final_ok={}, verifier_claim={}, trace_claim={}",
        verify.outer_verify.final_consistent,
        verify.outer_verify.final_claim_from_verifier.0,
        verify.outer_verify.final_claim_from_trace.0
    );
    println!(
        "Spartan inner verify: final_ok={}, verifier_claim={}, trace_claim={}",
        verify.inner_verify.final_consistent,
        verify.inner_verify.final_claim_from_verifier.0,
        verify.inner_verify.final_claim_from_trace.0
    );
    println!(
        "PCS verify: success for claimed_value={} with Merkle openings + encoded checks",
        query.claimed_value.0
    );
    println!("time: {:.3} ms", k3_ms);

    let total_ms = built.timings.k0_input_parse_ms
        + built.timings.k1_spartan_ms
        + built.timings.k2_pcs_ms
        + k3_ms;
    println!("\n[Summary]");
    println!(
        "input_parse: {:.3} ms ({:.1}%)",
        built.timings.k0_input_parse_ms,
        (built.timings.k0_input_parse_ms / total_ms) * 100.0
    );
    println!(
        "spartan_prove_core: {:.3} ms ({:.1}%)",
        built.timings.k1_spartan_ms,
        (built.timings.k1_spartan_ms / total_ms) * 100.0
    );
    println!(
        "pcs_commit_open_prove: {:.3} ms ({:.1}%)",
        built.timings.k2_pcs_ms,
        (built.timings.k2_pcs_ms / total_ms) * 100.0
    );
    println!("verify: {:.3} ms ({:.1}%)", k3_ms, (k3_ms / total_ms) * 100.0);
    println!("total: {:.3} ms", total_ms);

    assert!(
        verify.outer_verify.final_consistent,
        "outer sumcheck verify should pass"
    );
    assert!(
        verify.inner_verify.final_consistent,
        "inner sumcheck verify should pass"
    );
}

#[test]
fn bridge_verify_fails_on_wrong_claimed_evaluation() {
    let dir = case_dir();
    let built = prove_bridge_from_dir(&dir).expect("bridge prove should succeed");
    let mut query = built.verifier_query.clone();
    query.claimed_value = query.claimed_value.add(Fp::new(1));

    let mut tr_v = Transcript::new(BRIDGE_TRANSCRIPT_LABEL);
    let err = verify_bridge_bundle(&built.bundle, &query, &mut tr_v)
        .expect_err("verify should fail on wrong claimed value");
    assert!(err.to_string().contains("claimed value mismatch"));
}

#[test]
fn bridge_verify_fails_on_tampered_pcs_root() {
    let dir = case_dir();
    let mut built = prove_bridge_from_dir(&dir).expect("bridge prove should succeed");
    built.bundle.verifier_commitment.root[0] ^= 1;

    let mut tr_v = Transcript::new(BRIDGE_TRANSCRIPT_LABEL);
    let err = verify_bridge_bundle(&built.bundle, &built.verifier_query, &mut tr_v)
        .expect_err("verify should fail on tampered root");
    assert!(
        err.to_string().contains("merkle path failed")
            || err.to_string().contains("opened column index mismatch")
    );
}

#[test]
fn bridge_verify_fails_on_tampered_opening() {
    let dir = case_dir();
    let mut built = prove_bridge_from_dir(&dir).expect("bridge prove should succeed");
    built.bundle.pcs_opening_proof.columns[0].values[0] =
        built.bundle.pcs_opening_proof.columns[0].values[0].add(Fp::new(1));

    let mut tr_v = Transcript::new(BRIDGE_TRANSCRIPT_LABEL);
    let err = verify_bridge_bundle(&built.bundle, &built.verifier_query, &mut tr_v)
        .expect_err("verify should fail on tampered opening");
    assert!(
        err.to_string().contains("eval column check failed")
            || err.to_string().contains("degree-test column check failed")
    );
}

#[test]
fn bridge_verify_fails_on_public_metadata_mismatch() {
    let dir = case_dir();
    let built = prove_bridge_from_dir(&dir).expect("bridge prove should succeed");
    let mut query = built.verifier_query.clone();
    query.public_case_digest[0] ^= 1;

    let mut tr_v = Transcript::new(BRIDGE_TRANSCRIPT_LABEL);
    let err = verify_bridge_bundle(&built.bundle, &query, &mut tr_v)
        .expect_err("verify should fail on public metadata mismatch");
    assert!(err.to_string().contains("public case digest mismatch"));
}

#[test]
fn bridge_verify_fails_on_reference_profile_mismatch() {
    let dir = case_dir();
    let mut built = prove_bridge_from_dir(&dir).expect("bridge prove should succeed");
    let query = built.verifier_query.clone();
    built.bundle.reference_profile.protocol = ProtocolReference::ExperimentalAlt;
    built.bundle.reference_profile.pcs = PcsReference::ExperimentalAlt;

    let mut tr_v = Transcript::new(BRIDGE_TRANSCRIPT_LABEL);
    let err = verify_bridge_bundle(&built.bundle, &query, &mut tr_v)
        .expect_err("verify should fail on reference profile mismatch");
    assert!(err.to_string().contains("reference profile mismatch"));
}

#[test]
fn bridge_verify_fails_on_non_standard_reference_profile_even_if_matched() {
    let dir = case_dir();
    let mut built = prove_bridge_from_dir(&dir).expect("bridge prove should succeed");
    built.bundle.reference_profile.protocol = ProtocolReference::ExperimentalAlt;
    built.bundle.reference_profile.pcs = PcsReference::ExperimentalAlt;
    built.verifier_query.reference_profile.protocol = ProtocolReference::ExperimentalAlt;
    built.verifier_query.reference_profile.pcs = PcsReference::ExperimentalAlt;

    let mut tr_v = Transcript::new(BRIDGE_TRANSCRIPT_LABEL);
    let err = verify_bridge_bundle(&built.bundle, &built.verifier_query, &mut tr_v)
        .expect_err("verify should fail on non-standard reference profile");
    assert!(err
        .to_string()
        .contains("unsupported reference profile for this bridge flow"));
}
