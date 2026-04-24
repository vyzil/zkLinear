use std::path::Path;

use crate::core::field::current_modulus;

use super::types::SpartanBrakedownPipelineResult;

pub fn format_pipeline_report(case_dir: &Path, result: &SpartanBrakedownPipelineResult) -> String {
    let proof = &result.proof;
    let public = &result.public;
    let t = &result.timings;

    let mut out = String::new();
    out.push_str("=== Spartan + Brakedown Full-Style NIZK Report (Research) ===\n");
    out.push_str("\n[Scope]\n");
    out.push_str("- modular/unit tests keep SHA path for local arithmetic isolation\n");
    out.push_str("- integrated NIZK path uses single merlin transcript across outer/inner/pcs\n");
    out.push_str("- includes transcript-bound two-component ZK masking at PCS boundary\n");
    out.push_str("- NOTE: this is research/demo code, not production-hardened NIZK\n");

    out.push_str("\n[Prove/Kernels]\n");
    out.push_str("input_parse:\n");
    out.push_str(&format!("  source: {}\n", case_dir.display()));
    out.push_str(&format!("  time_ms: {:.3}\n", t.k0_input_parse_ms));

    out.push_str("spartan_prove_core:\n");
    out.push_str(&format!(
        "  output: outer_rounds={}, inner_rounds={}, gamma={}\n",
        proof.outer_trace.rounds.len(),
        proof.inner_trace.rounds.len(),
        proof.gamma.0
    ));
    out.push_str(&format!(
        "  unblinded_claim(inner sumcheck)={}\n",
        proof.claimed_value_unblinded.0
    ));
    out.push_str(&format!("  blind_eval_1={}\n", proof.blind_eval_1.0));
    out.push_str(&format!("  blind_eval_2={}\n", proof.blind_eval_2.0));
    out.push_str(&format!("  blind_mix_alpha={}\n", proof.blind_mix_alpha.0));
    out.push_str(&format!("  masked_claim={}\n", proof.claimed_value.0));
    out.push_str(&format!("  time_ms: {:.3}\n", t.k1_spartan_prove_ms));

    out.push_str("pcs_commit_open_prove:\n");
    out.push_str(&format!(
        "  output: root={}\n",
        hex::encode(proof.verifier_commitment.root)
    ));
    out.push_str(&format!(
        "  main payload: p_eval_len={}, p_random_count={}, opening_count={}\n",
        proof.pcs_proof_main.p_eval.len(),
        proof.pcs_proof_main.p_random_vec.len(),
        proof.pcs_proof_main.columns.len()
    ));
    out.push_str(&format!(
        "  blind1 payload: p_eval_len={}, p_random_count={}, opening_count={}\n",
        proof.pcs_proof_blind_1.p_eval.len(),
        proof.pcs_proof_blind_1.p_random_vec.len(),
        proof.pcs_proof_blind_1.columns.len()
    ));
    out.push_str(&format!(
        "  blind2 payload: p_eval_len={}, p_random_count={}, opening_count={}\n",
        proof.pcs_proof_blind_2.p_eval.len(),
        proof.pcs_proof_blind_2.p_random_vec.len(),
        proof.pcs_proof_blind_2.columns.len()
    ));
    out.push_str(&format!("  time_ms: {:.3}\n", t.k2_pcs_prove_ms));

    out.push_str("\n[Payload Prove -> Verify]\n");
    out.push_str("from spartan_prove_core:\n");
    out.push_str("  - outer_trace messages (g0,g2,g3 per round)\n");
    out.push_str("  - inner_trace messages (h0,h1,h2 per round)\n");
    out.push_str(&format!("  - gamma={}\n", proof.gamma.0));
    out.push_str(&format!(
        "  - unblinded_claim={}\n",
        proof.claimed_value_unblinded.0
    ));
    out.push_str(&format!("  - blind_eval_1={}\n", proof.blind_eval_1.0));
    out.push_str(&format!("  - blind_eval_2={}\n", proof.blind_eval_2.0));
    out.push_str(&format!("  - blind_mix_alpha={}\n", proof.blind_mix_alpha.0));
    out.push_str(&format!("  - masked_claim={}\n", proof.claimed_value.0));
    out.push_str("from pcs_commit_open_prove:\n");
    out.push_str(&format!(
        "  - verifier commitment root={}\n",
        hex::encode(proof.verifier_commitment.root)
    ));
    out.push_str("  - pcs main opening proof (masked claim)\n");
    out.push_str("  - pcs blind opening proof #1 (blind component 1)\n");
    out.push_str("  - pcs blind opening proof #2 (blind component 2)\n");
    out.push_str("public verifier input:\n");
    out.push_str("  - rows, cols, case_digest, reference_profile\n");
    out.push_str("  - claimed_value_masked\n");
    out.push_str("  - no witness-like tensor inputs on succinct public boundary\n");

    out.push_str("\n[Verify]\n");
    out.push_str("step 1: replay transcript on public metadata + outer rounds and check r_x\n");
    out.push_str("step 2: derive gamma from transcript and check equality\n");
    out.push_str("step 3: replay transcript on inner rounds and check inner challenges\n");
    out.push_str("step 4: check masked_claim = unblinded_claim + blind_eval_1 + alpha*blind_eval_2\n");
    out.push_str("step 5: derive PCS outer tensors from transcript-bound proof claims\n");
    out.push_str("step 6: verify PCS claimed-evaluation equality for main/blind1/blind2 openings\n");
    out.push_str("step 7: verify joint_eval_at_r and z_eval_at_r openings against sumcheck finals\n");
    out.push_str(&format!(
        "verify_result: success, masked_claim={}\n",
        public.claimed_value_masked.0
    ));
    out.push_str(&format!("verify time_ms: {:.3}\n", t.k3_verify_ms));

    out.push_str("\n[Timing Summary]\n");
    out.push_str(&format!(
        "input_parse: {:.3} ms ({:.1}%)\n",
        t.k0_input_parse_ms,
        t.pct(t.k0_input_parse_ms)
    ));
    out.push_str(&format!(
        "spartan_prove_core: {:.3} ms ({:.1}%)\n",
        t.k1_spartan_prove_ms,
        t.pct(t.k1_spartan_prove_ms)
    ));
    out.push_str(&format!(
        "pcs_commit_open_prove: {:.3} ms ({:.1}%)\n",
        t.k2_pcs_prove_ms,
        t.pct(t.k2_pcs_prove_ms)
    ));
    out.push_str(&format!(
        "verify: {:.3} ms ({:.1}%)\n",
        t.k3_verify_ms,
        t.pct(t.k3_verify_ms)
    ));
    out.push_str(&format!("total: {:.3} ms\n", t.total_ms()));
    out.push_str(&format!("\nfield: F_{}\n", current_modulus()));
    out.push_str(&format!(
        "pcs_profile: {:?}\n",
        proof.verifier_commitment.field_profile
    ));
    out.push_str(&format!(
        "pcs_params: n_degree_tests={}, n_col_opens={}\n",
        proof.pcs_proof_main.p_random_vec.len(),
        proof.pcs_proof_main.columns.len()
    ));
    out.push_str("verify_mode: succinct(public+proof)\n");

    out
}
