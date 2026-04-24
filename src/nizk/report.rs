use std::path::Path;

use crate::core::field::current_modulus;

use super::types::SpartanBrakedownPipelineResult;

pub fn format_pipeline_report(case_dir: &Path, result: &SpartanBrakedownPipelineResult) -> String {
    let proof = &result.proof;
    let public = &result.public;
    let public_meta = &result.public_meta;
    let t = &result.timings;

    let mut out = String::new();
    out.push_str("=== Spartan + Brakedown NIZK Report (Leakage-Reduced) ===\n");
    out.push_str("\n[Scope]\n");
    out.push_str("- sumcheck trace payload keeps canonical round messages only\n");
    out.push_str("- no explicit unblinded/masked/blind scalar payload fields\n");
    out.push_str("- no witness-row PCS opening on the public boundary\n");

    out.push_str("\n[Prove/Kernels]\n");
    out.push_str(&format!("source: {}\n", case_dir.display()));
    out.push_str(&format!(
        "outer rounds: {}\n",
        proof.outer_trace.rounds.len()
    ));
    out.push_str(&format!(
        "inner rounds: {}\n",
        proof.inner_trace.rounds.len()
    ));
    out.push_str(&format!("gamma: {}\n", proof.gamma.0));
    out.push_str(&format!("input_parse_ms: {:.3}\n", t.k0_input_parse_ms));
    out.push_str(&format!(
        "spartan_prove_core_ms: {:.3}\n",
        t.k1_spartan_prove_ms
    ));
    out.push_str(&format!(
        "pcs_commit_open_prove_ms: {:.3}\n",
        t.k2_pcs_prove_ms
    ));
    out.push_str(&format!("verify_ms: {:.3}\n", t.k3_verify_ms));

    out.push_str("\n[Payload]\n");
    out.push_str("- outer_trace: (g0,g2,g3,r) per round\n");
    out.push_str("- inner_trace: (h0,h1,h2,r) per round\n");
    out.push_str("- PCS: single joint_eval_at_r opening\n");
    out.push_str(&format!(
        "- verifier_root: {}\n",
        hex::encode(proof.verifier_commitment.root)
    ));

    out.push_str("\n[Public Input]\n");
    out.push_str("- rows, cols, case_digest, field_profile\n");
    out.push_str("- reference_profile/context_fingerprint are sidecar metadata\n");
    out.push_str(&format!(
        "- context_fingerprint(meta): {}\n",
        hex::encode(public_meta.context_fingerprint)
    ));
    out.push_str("- no masked-claim scalar on this boundary\n");

    out.push_str("\n[Verify]\n");
    out.push_str("1) replay outer/inner Fiat-Shamir challenges\n");
    out.push_str("2) check compact sumcheck transitions\n");
    out.push_str("3) verify joint_eval_at_r opening against inner final_f\n");
    out.push_str(&format!(
        "verify_result: success (rows={}, cols={})\n",
        public.rows, public.cols
    ));

    out.push_str("\n[Timing Summary]\n");
    out.push_str(&format!("total_ms: {:.3}\n", t.total_ms()));
    out.push_str(&format!("field: F_{}\n", current_modulus()));
    out.push_str(&format!(
        "pcs_profile: {:?}\n",
        proof.verifier_commitment.field_profile
    ));
    out.push_str("verify_mode: succinct(public+proof)\n");

    out
}
