use std::{path::Path, time::Instant};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use crate::{
    nizk::spartan_brakedown::{
        compile_from_dir_with_profile, prove_with_compiled_from_dir, verify_with_compiled,
    },
    pcs::brakedown::{
        types::BrakedownFieldProfile,
        wire::{serialize_eval_proof, serialize_verifier_commitment},
    },
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NizkMeasuredRun {
    pub run_id: usize,
    pub input_parse_ms: f64,
    pub spartan_prove_core_ms: f64,
    pub pcs_commit_open_prove_ms: f64,
    pub inline_verify_ms: f64,
    pub total_kernel_ms: f64,
    pub prove_wall_ms: f64,
    pub verify_wall_ms: f64,
    pub vc_bytes: usize,
    pub main_bytes: usize,
    pub blind1_bytes: usize,
    pub blind2_bytes: usize,
    pub joint_r_bytes: usize,
    pub z_r_bytes: usize,
    pub proof_bytes_total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NizkMetricsReport {
    pub case_dir: String,
    pub profile: String,
    pub compile_ms: f64,
    pub warmup_runs: usize,
    pub measured_runs: usize,
    pub runs: Vec<NizkMeasuredRun>,
}

pub fn mean(vals: &[f64]) -> f64 {
    if vals.is_empty() {
        return 0.0;
    }
    vals.iter().sum::<f64>() / vals.len() as f64
}

pub fn stddev(vals: &[f64], avg: f64) -> f64 {
    if vals.is_empty() {
        return 0.0;
    }
    let var = vals.iter().map(|v| (v - avg) * (v - avg)).sum::<f64>() / vals.len() as f64;
    var.sqrt()
}

fn run_once(
    case_dir: &Path,
    compiled: &crate::nizk::types::SpartanBrakedownCompiledCircuit,
    run_id: usize,
) -> Result<NizkMeasuredRun> {
    let t_prove = Instant::now();
    let res = prove_with_compiled_from_dir(compiled, case_dir)?;
    let prove_wall_ms = t_prove.elapsed().as_secs_f64() * 1000.0;

    let t_verify = Instant::now();
    verify_with_compiled(compiled, &res.proof, &res.public)?;
    let verify_wall_ms = t_verify.elapsed().as_secs_f64() * 1000.0;

    let vc_bytes = serialize_verifier_commitment(&res.proof.verifier_commitment).len();
    let main_bytes = serialize_eval_proof(&res.proof.pcs_proof_main).len();
    let blind1_bytes = serialize_eval_proof(&res.proof.pcs_proof_blind_1).len();
    let blind2_bytes = serialize_eval_proof(&res.proof.pcs_proof_blind_2).len();
    let joint_r_bytes = serialize_eval_proof(&res.proof.pcs_proof_joint_eval_at_r).len();
    let z_r_bytes = serialize_eval_proof(&res.proof.pcs_proof_z_eval_at_r).len();
    let proof_bytes_total =
        vc_bytes + main_bytes + blind1_bytes + blind2_bytes + joint_r_bytes + z_r_bytes;

    Ok(NizkMeasuredRun {
        run_id,
        input_parse_ms: res.timings.k0_input_parse_ms,
        spartan_prove_core_ms: res.timings.k1_spartan_prove_ms,
        pcs_commit_open_prove_ms: res.timings.k2_pcs_prove_ms,
        inline_verify_ms: res.timings.k3_verify_ms,
        total_kernel_ms: res.timings.total_ms(),
        prove_wall_ms,
        verify_wall_ms,
        vc_bytes,
        main_bytes,
        blind1_bytes,
        blind2_bytes,
        joint_r_bytes,
        z_r_bytes,
        proof_bytes_total,
    })
}

pub fn collect_nizk_metrics(
    case_dir: &Path,
    profile: BrakedownFieldProfile,
    warmup_runs: usize,
    measured_runs: usize,
) -> Result<NizkMetricsReport> {
    if measured_runs == 0 {
        return Err(anyhow!("measured_runs must be >= 1"));
    }
    let t_compile = Instant::now();
    let compiled = compile_from_dir_with_profile(case_dir, profile)?;
    let compile_ms = t_compile.elapsed().as_secs_f64() * 1000.0;

    for _ in 0..warmup_runs {
        let _ = run_once(case_dir, &compiled, 0)?;
    }

    let mut runs = Vec::with_capacity(measured_runs);
    for i in 0..measured_runs {
        runs.push(run_once(case_dir, &compiled, i + 1)?);
    }

    Ok(NizkMetricsReport {
        case_dir: case_dir.display().to_string(),
        profile: format!("{:?}", profile),
        compile_ms,
        warmup_runs,
        measured_runs,
        runs,
    })
}
