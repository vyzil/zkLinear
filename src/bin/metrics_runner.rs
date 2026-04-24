use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use zk_linear::nizk::spartan_brakedown::{
    collect_nizk_metrics, metrics_mean, metrics_stddev, parse_field_profile,
};

#[derive(Debug, Clone, Serialize)]
struct SummaryMetrics {
    compile_ms: f64,
    warmup_runs: usize,
    measured_runs: usize,
    prove_avg_ms: f64,
    prove_stddev_ms: f64,
    verify_avg_ms: f64,
    verify_stddev_ms: f64,
    proof_bytes_avg: f64,
    proof_bytes_stddev: f64,
}

#[derive(Debug, Clone, Serialize)]
struct MetricsReportOut {
    instance_dir: String,
    profile: String,
    summary: SummaryMetrics,
    runs: Vec<zk_linear::nizk::metrics::NizkMeasuredRun>,
}

fn write_outputs(out_prefix: &Path, report: &MetricsReportOut) -> Result<()> {
    if let Some(parent) = out_prefix.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let json_path = out_prefix.with_extension("json");
    let csv_path = out_prefix.with_extension("csv");

    let json = serde_json::to_string_pretty(report)?;
    fs::write(&json_path, json)
        .with_context(|| format!("failed to write {}", json_path.display()))?;

    let mut csv =
        String::from("run_id,prove_ms,verify_ms,proof_bytes_total,vc_bytes,joint_r_bytes\n");
    for r in &report.runs {
        csv.push_str(&format!(
            "{},{:.6},{:.6},{},{},{}\n",
            r.run_id,
            r.prove_wall_ms,
            r.verify_wall_ms,
            r.proof_bytes_total,
            r.vc_bytes,
            r.joint_r_bytes
        ));
    }
    fs::write(&csv_path, csv).with_context(|| format!("failed to write {}", csv_path.display()))?;
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        bail!(
            "usage: metrics_runner <instance_dir> <out_prefix> [profile] [warmup_runs] [measured_runs]"
        );
    }
    let instance_dir = PathBuf::from(&args[1]);
    let out_prefix = PathBuf::from(&args[2]);
    let profile_s = args.get(3).cloned().unwrap_or_else(|| "m61".to_string());
    let warmup_runs = args
        .get(4)
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1);
    let measured_runs = args
        .get(5)
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(5);
    let profile = parse_field_profile(&profile_s)
        .ok_or_else(|| anyhow!("unknown profile '{}'; use toy|m61|gold", profile_s))?;

    let report = collect_nizk_metrics(&instance_dir, profile, warmup_runs, measured_runs)?;
    let prove_vals = report
        .runs
        .iter()
        .map(|r| r.prove_wall_ms)
        .collect::<Vec<_>>();
    let verify_vals = report
        .runs
        .iter()
        .map(|r| r.verify_wall_ms)
        .collect::<Vec<_>>();
    let proof_vals = report
        .runs
        .iter()
        .map(|r| r.proof_bytes_total as f64)
        .collect::<Vec<_>>();

    let prove_avg = metrics_mean(&prove_vals);
    let verify_avg = metrics_mean(&verify_vals);
    let proof_avg = metrics_mean(&proof_vals);

    let out = MetricsReportOut {
        instance_dir: report.instance_dir.clone(),
        profile: profile_s.clone(),
        summary: SummaryMetrics {
            compile_ms: report.compile_ms,
            warmup_runs: report.warmup_runs,
            measured_runs: report.measured_runs,
            prove_avg_ms: prove_avg,
            prove_stddev_ms: metrics_stddev(&prove_vals, prove_avg),
            verify_avg_ms: verify_avg,
            verify_stddev_ms: metrics_stddev(&verify_vals, verify_avg),
            proof_bytes_avg: proof_avg,
            proof_bytes_stddev: metrics_stddev(&proof_vals, proof_avg),
        },
        runs: report.runs,
    };

    write_outputs(&out_prefix, &out)?;

    let json_path = out_prefix.with_extension("json");
    let csv_path = out_prefix.with_extension("csv");
    println!("metrics_runner: ok");
    println!("  instance_dir={}", instance_dir.display());
    println!("  profile={}", out.profile);
    println!("  warmup_runs={}", warmup_runs);
    println!("  measured_runs={}", measured_runs);
    println!("  compile_ms={:.3}", out.summary.compile_ms);
    println!(
        "  prove_avg_ms={:.3} (stddev={:.3})",
        out.summary.prove_avg_ms, out.summary.prove_stddev_ms
    );
    println!(
        "  verify_avg_ms={:.3} (stddev={:.3})",
        out.summary.verify_avg_ms, out.summary.verify_stddev_ms
    );
    println!(
        "  proof_bytes_avg={:.1} (stddev={:.1})",
        out.summary.proof_bytes_avg, out.summary.proof_bytes_stddev
    );
    println!("  out_json={}", json_path.display());
    println!("  out_csv={}", csv_path.display());
    Ok(())
}
