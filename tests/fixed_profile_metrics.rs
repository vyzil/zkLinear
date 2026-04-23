use std::{fs, path::PathBuf};

use zk_linear::{
    nizk::spartan_brakedown::prove_from_dir,
    pcs::brakedown::wire::{serialize_eval_proof, serialize_verifier_commitment},
};

fn case_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/inner_sumcheck_spartan")
}

fn docs_metrics_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/FIXED_PROFILE_METRICS.md")
}

fn mean(v: &[f64]) -> f64 {
    v.iter().sum::<f64>() / v.len() as f64
}

fn min(v: &[f64]) -> f64 {
    v.iter().copied().fold(f64::INFINITY, f64::min)
}

fn max(v: &[f64]) -> f64 {
    v.iter().copied().fold(f64::NEG_INFINITY, f64::max)
}

#[test]
fn fixed_profile_repeat_metrics_table() {
    let runs = 10usize;
    let dir = case_dir();

    let mut k0 = Vec::with_capacity(runs);
    let mut k1 = Vec::with_capacity(runs);
    let mut k2 = Vec::with_capacity(runs);
    let mut k3 = Vec::with_capacity(runs);
    let mut totals = Vec::with_capacity(runs);

    let mut vc_bytes = 0usize;
    let mut main_pf_bytes = 0usize;
    let mut blind1_pf_bytes = 0usize;
    let mut blind2_pf_bytes = 0usize;
    let mut sumcheck_bytes_est = 0usize;
    let mut scalar_bytes_est = 0usize;

    for _ in 0..runs {
        let r = prove_from_dir(&dir).expect("prove/verify should succeed");
        k0.push(r.timings.k0_input_parse_ms);
        k1.push(r.timings.k1_spartan_prove_ms);
        k2.push(r.timings.k2_pcs_prove_ms);
        k3.push(r.timings.k3_verify_ms);
        totals.push(
            r.timings.k0_input_parse_ms
                + r.timings.k1_spartan_prove_ms
                + r.timings.k2_pcs_prove_ms
                + r.timings.k3_verify_ms,
        );

        vc_bytes = serialize_verifier_commitment(&r.proof.verifier_commitment).len();
        main_pf_bytes = serialize_eval_proof(&r.proof.pcs_proof_main).len();
        blind1_pf_bytes = serialize_eval_proof(&r.proof.pcs_proof_blind_1).len();
        blind2_pf_bytes = serialize_eval_proof(&r.proof.pcs_proof_blind_2).len();

        // Outer sends (h0,h1) each round; inner sends (h0,h1,h2) each round.
        let outer_elems = r.proof.outer_trace.rounds.len() * 2;
        let inner_elems = r.proof.inner_trace.rounds.len() * 3;
        sumcheck_bytes_est = (outer_elems + inner_elems) * 8;

        // claimed_value, blind_eval_1, blind_eval_2, blind_mix_alpha, gamma
        scalar_bytes_est = 5 * 8;
    }

    let pcs_payload_bytes = vc_bytes + main_pf_bytes + blind1_pf_bytes + blind2_pf_bytes;
    let protocol_payload_est = pcs_payload_bytes + sumcheck_bytes_est + scalar_bytes_est;

    let mut md = String::new();
    md.push_str("# Fixed Profile Metrics (Case: inner_sumcheck_spartan)\n\n");
    md.push_str("| metric | mean_ms | min_ms | max_ms |\n");
    md.push_str("|---|---:|---:|---:|\n");
    md.push_str(&format!(
        "| input_parse | {:.3} | {:.3} | {:.3} |\n",
        mean(&k0),
        min(&k0),
        max(&k0)
    ));
    md.push_str(&format!(
        "| spartan_prove_core | {:.3} | {:.3} | {:.3} |\n",
        mean(&k1),
        min(&k1),
        max(&k1)
    ));
    md.push_str(&format!(
        "| pcs_commit_open_prove | {:.3} | {:.3} | {:.3} |\n",
        mean(&k2),
        min(&k2),
        max(&k2)
    ));
    md.push_str(&format!(
        "| verify | {:.3} | {:.3} | {:.3} |\n",
        mean(&k3),
        min(&k3),
        max(&k3)
    ));
    md.push_str(&format!(
        "| total (input_parse+spartan_prove_core+pcs_commit_open_prove+verify) | {:.3} | {:.3} | {:.3} |\n",
        mean(&totals),
        min(&totals),
        max(&totals)
    ));

    md.push_str("\n## Payload Size (bytes)\n\n");
    md.push_str("| component | bytes |\n");
    md.push_str("|---|---:|\n");
    md.push_str(&format!("| verifier commitment wire | {} |\n", vc_bytes));
    md.push_str(&format!("| main PCS opening wire | {} |\n", main_pf_bytes));
    md.push_str(&format!("| blind PCS opening #1 wire | {} |\n", blind1_pf_bytes));
    md.push_str(&format!("| blind PCS opening #2 wire | {} |\n", blind2_pf_bytes));
    md.push_str(&format!("| PCS subtotal | {} |\n", pcs_payload_bytes));
    md.push_str(&format!(
        "| sumcheck rounds (field elements only, est.) | {} |\n",
        sumcheck_bytes_est
    ));
    md.push_str(&format!(
        "| scalar public/proof values (est.) | {} |\n",
        scalar_bytes_est
    ));
    md.push_str(&format!(
        "| protocol subtotal (PCS + estimates) | {} |\n",
        protocol_payload_est
    ));

    println!("{md}");

    if std::env::var("ZKLINEAR_WRITE_FIXED_METRICS").as_deref() == Ok("1") {
        fs::write(docs_metrics_file(), md).expect("write fixed metrics markdown");
    }
}
