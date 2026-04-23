use std::path::PathBuf;

use anyhow::{anyhow, Result};
use zk_linear::{
    nizk::spartan_brakedown::{parse_field_profile, prove_from_dir_with_profile},
    pcs::brakedown::wire::{serialize_eval_proof, serialize_verifier_commitment},
};

fn profile_list_from_arg(s: Option<String>) -> Result<Vec<String>> {
    let raw = s.unwrap_or_else(|| "toy,m61,gold".to_string());
    let mut out = Vec::new();
    for tok in raw.split(',').map(str::trim).filter(|x| !x.is_empty()) {
        if parse_field_profile(tok).is_none() {
            return Err(anyhow!(
                "unknown profile '{}'; use comma list from: toy,m61,gold",
                tok
            ));
        }
        out.push(tok.to_string());
    }
    Ok(out)
}

fn mean(v: &[f64]) -> f64 {
    v.iter().sum::<f64>() / v.len() as f64
}

fn fmt_profile(p: &str) -> &'static str {
    match p {
        "toy" | "toyf97" | "f97" => "ToyF97",
        "m61" | "mersenne61" | "mersenne61ext2" | "ext2-m61" => "Mersenne61Ext2",
        "gold" | "goldilocks" | "goldilocks64ext2" | "ext2-gold" => "Goldilocks64Ext2",
        _ => "Unknown",
    }
}

fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let case_dir = args
        .first()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("tests/inner_sumcheck_spartan"));
    let runs = args
        .get(1)
        .and_then(|x| x.parse::<usize>().ok())
        .unwrap_or(5)
        .max(1);
    let profiles = profile_list_from_arg(args.get(2).cloned())?;

    let mut md = String::new();
    md.push_str("# Profile Matrix Metrics\n\n");
    md.push_str(&format!("- case: `{}`\n", case_dir.display()));
    md.push_str(&format!("- runs per profile: `{}`\n\n", runs));

    md.push_str("## Timing (ms)\n\n");
    md.push_str("| profile | input_parse | spartan_prove_core | pcs_commit_open_prove | verify | total |\n");
    md.push_str("|---|---:|---:|---:|---:|---:|\n");

    let mut size_rows = Vec::new();

    for pstr in profiles {
        let profile = parse_field_profile(&pstr).expect("validated profile");
        let mut k0 = Vec::with_capacity(runs);
        let mut k1 = Vec::with_capacity(runs);
        let mut k2 = Vec::with_capacity(runs);
        let mut k3 = Vec::with_capacity(runs);
        let mut total = Vec::with_capacity(runs);

        let mut vc_bytes = 0usize;
        let mut pf_main = 0usize;
        let mut pf_b1 = 0usize;
        let mut pf_b2 = 0usize;

        for _ in 0..runs {
            let r = prove_from_dir_with_profile(&case_dir, profile)?;
            k0.push(r.timings.k0_input_parse_ms);
            k1.push(r.timings.k1_spartan_prove_ms);
            k2.push(r.timings.k2_pcs_prove_ms);
            k3.push(r.timings.k3_verify_ms);
            total.push(r.timings.total_ms());

            vc_bytes = serialize_verifier_commitment(&r.proof.verifier_commitment).len();
            pf_main = serialize_eval_proof(&r.proof.pcs_proof_main).len();
            pf_b1 = serialize_eval_proof(&r.proof.pcs_proof_blind_1).len();
            pf_b2 = serialize_eval_proof(&r.proof.pcs_proof_blind_2).len();
        }

        md.push_str(&format!(
            "| {} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} |\n",
            fmt_profile(&pstr),
            mean(&k0),
            mean(&k1),
            mean(&k2),
            mean(&k3),
            mean(&total)
        ));

        size_rows.push((fmt_profile(&pstr), vc_bytes, pf_main, pf_b1, pf_b2));
    }

    md.push_str("\n## Wire Payload Size (bytes)\n\n");
    md.push_str(
        "| profile | verifier_commitment | opening_main | opening_blind1 | opening_blind2 | pcs_subtotal |\n",
    );
    md.push_str("|---|---:|---:|---:|---:|---:|\n");
    for (p, vc, m, b1, b2) in size_rows {
        let subtotal = vc + m + b1 + b2;
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            p, vc, m, b1, b2, subtotal
        ));
    }

    println!("{md}");
    Ok(())
}
