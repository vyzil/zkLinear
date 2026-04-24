use std::path::PathBuf;

use anyhow::{anyhow, Result};
use zk_linear::nizk::spartan_brakedown::{collect_nizk_metrics, parse_field_profile};

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
    let instance_dir = args
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
    md.push_str(&format!("- instance: `{}`\n", instance_dir.display()));
    md.push_str(&format!("- runs per profile: `{}`\n\n", runs));

    md.push_str("## Timing (ms)\n\n");
    md.push_str(
        "| profile | input_parse | spartan_prove_core | pcs_commit_open_prove | verify | total |\n",
    );
    md.push_str("|---|---:|---:|---:|---:|---:|\n");

    let mut size_rows = Vec::new();

    for pstr in profiles {
        let profile = parse_field_profile(&pstr).expect("validated profile");
        let m = collect_nizk_metrics(&instance_dir, profile, 0, runs)?;
        let mean = |f: fn(&zk_linear::nizk::metrics::NizkMeasuredRun) -> f64| -> f64 {
            m.runs.iter().map(f).sum::<f64>() / m.runs.len() as f64
        };
        let last = m.runs.last().expect("metrics runs should be non-empty");

        md.push_str(&format!(
            "| {} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} |\n",
            fmt_profile(&pstr),
            mean(|r| r.input_parse_ms),
            mean(|r| r.spartan_prove_core_ms),
            mean(|r| r.pcs_commit_open_prove_ms),
            mean(|r| r.inline_verify_ms),
            mean(|r| r.total_kernel_ms)
        ));

        size_rows.push((fmt_profile(&pstr), last.vc_bytes, last.joint_r_bytes));
    }

    md.push_str("\n## Wire Payload Size (bytes)\n\n");
    md.push_str("| profile | verifier_commitment | opening_joint_eval_at_r | pcs_subtotal |\n");
    md.push_str("|---|---:|---:|---:|\n");
    for (p, vc, joint) in size_rows {
        let subtotal = vc + joint;
        md.push_str(&format!("| {} | {} | {} | {} |\n", p, vc, joint, subtotal));
    }

    println!("{md}");
    Ok(())
}
