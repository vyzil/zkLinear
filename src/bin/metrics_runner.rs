use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use zk_linear::{
    nizk::spartan_brakedown::{
        compile_from_dir_with_profile, parse_field_profile, prove_with_compiled_from_dir,
        verify_with_compiled, SpartanBrakedownCompiledCircuit,
    },
    pcs::brakedown::wire::{serialize_eval_proof, serialize_verifier_commitment},
};

#[derive(Debug, Clone, Serialize)]
struct RunMetrics {
    run_id: usize,
    prove_ms: f64,
    verify_ms: f64,
    proof_bytes_total: usize,
    vc_bytes: usize,
    main_bytes: usize,
    blind1_bytes: usize,
    blind2_bytes: usize,
    joint_r_bytes: usize,
    z_r_bytes: usize,
}

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
struct MetricsReport {
    case_dir: String,
    profile: String,
    summary: SummaryMetrics,
    runs: Vec<RunMetrics>,
}

fn mean(vals: &[f64]) -> f64 {
    if vals.is_empty() {
        return 0.0;
    }
    vals.iter().sum::<f64>() / vals.len() as f64
}

fn stddev(vals: &[f64], avg: f64) -> f64 {
    if vals.is_empty() {
        return 0.0;
    }
    let var = vals.iter().map(|v| (v - avg) * (v - avg)).sum::<f64>() / vals.len() as f64;
    var.sqrt()
}

fn run_once(
    case_dir: &Path,
    compiled: &SpartanBrakedownCompiledCircuit,
) -> Result<RunMetrics> {
    let t_prove = Instant::now();
    let res = prove_with_compiled_from_dir(compiled, case_dir)?;
    let prove_ms = t_prove.elapsed().as_secs_f64() * 1000.0;

    let t_verify = Instant::now();
    verify_with_compiled(compiled, &res.proof, &res.public)?;
    let verify_ms = t_verify.elapsed().as_secs_f64() * 1000.0;

    let vc_bytes = serialize_verifier_commitment(&res.proof.verifier_commitment).len();
    let main_bytes = serialize_eval_proof(&res.proof.pcs_proof_main).len();
    let blind1_bytes = serialize_eval_proof(&res.proof.pcs_proof_blind_1).len();
    let blind2_bytes = serialize_eval_proof(&res.proof.pcs_proof_blind_2).len();
    let joint_r_bytes = serialize_eval_proof(&res.proof.pcs_proof_joint_eval_at_r).len();
    let z_r_bytes = serialize_eval_proof(&res.proof.pcs_proof_z_eval_at_r).len();
    let proof_bytes_total =
        vc_bytes + main_bytes + blind1_bytes + blind2_bytes + joint_r_bytes + z_r_bytes;

    Ok(RunMetrics {
        run_id: 0,
        prove_ms,
        verify_ms,
        proof_bytes_total,
        vc_bytes,
        main_bytes,
        blind1_bytes,
        blind2_bytes,
        joint_r_bytes,
        z_r_bytes,
    })
}

fn write_outputs(out_prefix: &Path, report: &MetricsReport) -> Result<()> {
    if let Some(parent) = out_prefix.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let json_path = out_prefix.with_extension("json");
    let csv_path = out_prefix.with_extension("csv");

    let json = serde_json::to_string_pretty(report)?;
    fs::write(&json_path, json).with_context(|| format!("failed to write {}", json_path.display()))?;

    let mut csv = String::from(
        "run_id,prove_ms,verify_ms,proof_bytes_total,vc_bytes,main_bytes,blind1_bytes,blind2_bytes,joint_r_bytes,z_r_bytes\n",
    );
    for r in &report.runs {
        csv.push_str(&format!(
            "{},{:.6},{:.6},{},{},{},{},{},{},{}\n",
            r.run_id,
            r.prove_ms,
            r.verify_ms,
            r.proof_bytes_total,
            r.vc_bytes,
            r.main_bytes,
            r.blind1_bytes,
            r.blind2_bytes,
            r.joint_r_bytes,
            r.z_r_bytes
        ));
    }
    fs::write(&csv_path, csv).with_context(|| format!("failed to write {}", csv_path.display()))?;
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        bail!(
            "usage: metrics_runner <case_dir> <out_prefix> [profile] [warmup_runs] [measured_runs]"
        );
    }
    let case_dir = PathBuf::from(&args[1]);
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
    if measured_runs == 0 {
        return Err(anyhow!("measured_runs must be >= 1"));
    }
    let profile = parse_field_profile(&profile_s)
        .ok_or_else(|| anyhow!("unknown profile '{}'; use toy|m61|gold", profile_s))?;

    let t_compile = Instant::now();
    let compiled = compile_from_dir_with_profile(&case_dir, profile)?;
    let compile_ms = t_compile.elapsed().as_secs_f64() * 1000.0;

    for _ in 0..warmup_runs {
        let _ = run_once(&case_dir, &compiled)?;
    }

    let mut runs = Vec::with_capacity(measured_runs);
    for i in 0..measured_runs {
        let mut run = run_once(&case_dir, &compiled)?;
        run.run_id = i + 1;
        runs.push(run);
    }

    let prove_vals = runs.iter().map(|r| r.prove_ms).collect::<Vec<_>>();
    let verify_vals = runs.iter().map(|r| r.verify_ms).collect::<Vec<_>>();
    let proof_vals = runs
        .iter()
        .map(|r| r.proof_bytes_total as f64)
        .collect::<Vec<_>>();

    let prove_avg = mean(&prove_vals);
    let verify_avg = mean(&verify_vals);
    let proof_avg = mean(&proof_vals);

    let summary = SummaryMetrics {
        compile_ms,
        warmup_runs,
        measured_runs,
        prove_avg_ms: prove_avg,
        prove_stddev_ms: stddev(&prove_vals, prove_avg),
        verify_avg_ms: verify_avg,
        verify_stddev_ms: stddev(&verify_vals, verify_avg),
        proof_bytes_avg: proof_avg,
        proof_bytes_stddev: stddev(&proof_vals, proof_avg),
    };

    let report = MetricsReport {
        case_dir: case_dir.display().to_string(),
        profile: profile_s,
        summary,
        runs,
    };
    write_outputs(&out_prefix, &report)?;

    let json_path = out_prefix.with_extension("json");
    let csv_path = out_prefix.with_extension("csv");
    println!("metrics_runner: ok");
    println!("  case_dir={}", case_dir.display());
    println!("  profile={}", report.profile);
    println!("  warmup_runs={}", warmup_runs);
    println!("  measured_runs={}", measured_runs);
    println!("  compile_ms={:.3}", report.summary.compile_ms);
    println!(
        "  prove_avg_ms={:.3} (stddev={:.3})",
        report.summary.prove_avg_ms, report.summary.prove_stddev_ms
    );
    println!(
        "  verify_avg_ms={:.3} (stddev={:.3})",
        report.summary.verify_avg_ms, report.summary.verify_stddev_ms
    );
    println!(
        "  proof_bytes_avg={:.1} (stddev={:.1})",
        report.summary.proof_bytes_avg, report.summary.proof_bytes_stddev
    );
    println!("  out_json={}", json_path.display());
    println!("  out_csv={}", csv_path.display());
    Ok(())
}
