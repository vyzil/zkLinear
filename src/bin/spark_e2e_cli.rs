use std::{fs, path::PathBuf, time::Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use zk_linear::{
    core::field::{Fp, ModulusScope},
    nizk::{
        spartan_brakedown::{
            compile_from_dir_with_profile, parse_field_profile, prove_with_compiled_from_dir,
            verify_with_compiled, SpartanBrakedownCompiledCircuit, SpartanBrakedownProof,
            SpartanBrakedownPublic, KernelTimingMs,
        },
    },
    pcs::brakedown::wire::{
        deserialize_eval_proof, deserialize_verifier_commitment, serialize_eval_proof,
        serialize_verifier_commitment,
    },
    protocol::reference::{PcsReference, ProtocolReference, ReferenceProfile},
    sumcheck::{
        inner::{RoundTranscript, SumcheckTrace},
        outer::{OuterRoundTranscript, OuterSumcheckTrace},
    },
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RefProfileJson {
    protocol: String,
    pcs: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompiledJson {
    rows: usize,
    cols: usize,
    case_digest_hex: String,
    field_profile: String,
    reference_profile: RefProfileJson,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OuterRoundJson {
    round: usize,
    g_at_0: u64,
    g_at_2: u64,
    g_at_3: u64,
    challenge_r: u64,
    folded_values: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OuterTraceJson {
    claim_initial: u64,
    rounds: Vec<OuterRoundJson>,
    final_value: u64,
    final_claim: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InnerRoundJson {
    round: usize,
    h_at_0: u64,
    h_at_1: u64,
    h_at_2: u64,
    challenge_r: u64,
    folded_f: Vec<u64>,
    folded_g: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InnerTraceJson {
    claim_initial: u64,
    rounds: Vec<InnerRoundJson>,
    final_f: u64,
    final_g: u64,
    final_claim: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProofJson {
    outer_trace: OuterTraceJson,
    inner_trace: InnerTraceJson,
    gamma: u64,
    claimed_value: u64,
    blind_eval_1: u64,
    blind_eval_2: u64,
    blind_mix_alpha: u64,
    reference_profile: RefProfileJson,
    verifier_commitment_hex: String,
    pcs_proof_main_hex: String,
    pcs_proof_blind_1_hex: String,
    pcs_proof_blind_2_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PublicJson {
    rows: usize,
    cols: usize,
    case_digest_hex: String,
    outer_tensor_main: Vec<u64>,
    outer_tensor_blind_1: Vec<u64>,
    outer_tensor_blind_2: Vec<u64>,
    inner_tensor: Vec<u64>,
    claimed_value_unblinded: u64,
    claimed_value_masked: u64,
    reference_profile: RefProfileJson,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KernelTimingJson {
    input_parse_ms: f64,
    spartan_prove_core_ms: f64,
    pcs_commit_open_prove_ms: f64,
    verify_ms: f64,
    total_ms: f64,
}

fn fp_to_u64(v: Fp) -> u64 {
    v.0
}

fn u64_to_fp(v: u64) -> Fp {
    Fp(v)
}

fn ref_to_json(r: ReferenceProfile) -> RefProfileJson {
    let protocol = match r.protocol {
        ProtocolReference::Spartan2Like => "Spartan2Like",
        ProtocolReference::ExperimentalAlt => "ExperimentalAlt",
    };
    let pcs = match r.pcs {
        PcsReference::LcpcBrakedownLike => "LcpcBrakedownLike",
        PcsReference::ExperimentalAlt => "ExperimentalAlt",
    };
    RefProfileJson {
        protocol: protocol.to_string(),
        pcs: pcs.to_string(),
    }
}

fn ref_from_json(j: &RefProfileJson) -> Result<ReferenceProfile> {
    let protocol = match j.protocol.as_str() {
        "Spartan2Like" => ProtocolReference::Spartan2Like,
        "ExperimentalAlt" => ProtocolReference::ExperimentalAlt,
        _ => bail!("unknown protocol reference '{}'", j.protocol),
    };
    let pcs = match j.pcs.as_str() {
        "LcpcBrakedownLike" => PcsReference::LcpcBrakedownLike,
        "ExperimentalAlt" => PcsReference::ExperimentalAlt,
        _ => bail!("unknown pcs reference '{}'", j.pcs),
    };
    Ok(ReferenceProfile { protocol, pcs })
}

fn digest_to_hex(d: [u8; 32]) -> String {
    hex::encode(d)
}

fn digest_from_hex(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).context("invalid hex digest")?;
    if bytes.len() != 32 {
        bail!("digest must be 32 bytes, got {}", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn outer_trace_to_json(t: &OuterSumcheckTrace<Fp>) -> OuterTraceJson {
    OuterTraceJson {
        claim_initial: fp_to_u64(t.claim_initial),
        rounds: t
            .rounds
            .iter()
            .map(|r| OuterRoundJson {
                round: r.round,
                g_at_0: fp_to_u64(r.g_at_0),
                g_at_2: fp_to_u64(r.g_at_2),
                g_at_3: fp_to_u64(r.g_at_3),
                challenge_r: fp_to_u64(r.challenge_r),
                folded_values: r.folded_values.iter().map(|v| fp_to_u64(*v)).collect(),
            })
            .collect(),
        final_value: fp_to_u64(t.final_value),
        final_claim: fp_to_u64(t.final_claim),
    }
}

fn outer_trace_from_json(t: &OuterTraceJson) -> OuterSumcheckTrace<Fp> {
    OuterSumcheckTrace {
        claim_initial: u64_to_fp(t.claim_initial),
        rounds: t
            .rounds
            .iter()
            .map(|r| OuterRoundTranscript {
                round: r.round,
                g_at_0: u64_to_fp(r.g_at_0),
                g_at_2: u64_to_fp(r.g_at_2),
                g_at_3: u64_to_fp(r.g_at_3),
                challenge_r: u64_to_fp(r.challenge_r),
                folded_values: r.folded_values.iter().map(|v| u64_to_fp(*v)).collect(),
            })
            .collect(),
        final_value: u64_to_fp(t.final_value),
        final_claim: u64_to_fp(t.final_claim),
    }
}

fn inner_trace_to_json(t: &SumcheckTrace<Fp>) -> InnerTraceJson {
    InnerTraceJson {
        claim_initial: fp_to_u64(t.claim_initial),
        rounds: t
            .rounds
            .iter()
            .map(|r| InnerRoundJson {
                round: r.round,
                h_at_0: fp_to_u64(r.h_at_0),
                h_at_1: fp_to_u64(r.h_at_1),
                h_at_2: fp_to_u64(r.h_at_2),
                challenge_r: fp_to_u64(r.challenge_r),
                folded_f: r.folded_f.iter().map(|v| fp_to_u64(*v)).collect(),
                folded_g: r.folded_g.iter().map(|v| fp_to_u64(*v)).collect(),
            })
            .collect(),
        final_f: fp_to_u64(t.final_f),
        final_g: fp_to_u64(t.final_g),
        final_claim: fp_to_u64(t.final_claim),
    }
}

fn inner_trace_from_json(t: &InnerTraceJson) -> SumcheckTrace<Fp> {
    SumcheckTrace {
        claim_initial: u64_to_fp(t.claim_initial),
        rounds: t
            .rounds
            .iter()
            .map(|r| RoundTranscript {
                round: r.round,
                h_at_0: u64_to_fp(r.h_at_0),
                h_at_1: u64_to_fp(r.h_at_1),
                h_at_2: u64_to_fp(r.h_at_2),
                challenge_r: u64_to_fp(r.challenge_r),
                folded_f: r.folded_f.iter().map(|v| u64_to_fp(*v)).collect(),
                folded_g: r.folded_g.iter().map(|v| u64_to_fp(*v)).collect(),
            })
            .collect(),
        final_f: u64_to_fp(t.final_f),
        final_g: u64_to_fp(t.final_g),
        final_claim: u64_to_fp(t.final_claim),
    }
}

fn compiled_to_json(c: &SpartanBrakedownCompiledCircuit) -> CompiledJson {
    CompiledJson {
        rows: c.rows,
        cols: c.cols,
        case_digest_hex: digest_to_hex(c.case_digest),
        field_profile: format!("{:?}", c.field_profile),
        reference_profile: ref_to_json(c.reference_profile),
    }
}

fn compiled_from_json(j: &CompiledJson) -> Result<SpartanBrakedownCompiledCircuit> {
    let field_profile = parse_field_profile(&j.field_profile)
        .ok_or_else(|| anyhow!("unknown field profile '{}'", j.field_profile))?;
    Ok(SpartanBrakedownCompiledCircuit {
        rows: j.rows,
        cols: j.cols,
        case_digest: digest_from_hex(&j.case_digest_hex)?,
        field_profile,
        reference_profile: ref_from_json(&j.reference_profile)?,
    })
}

fn proof_to_json(p: &SpartanBrakedownProof) -> ProofJson {
    ProofJson {
        outer_trace: outer_trace_to_json(&p.outer_trace),
        inner_trace: inner_trace_to_json(&p.inner_trace),
        gamma: fp_to_u64(p.gamma),
        claimed_value: fp_to_u64(p.claimed_value),
        blind_eval_1: fp_to_u64(p.blind_eval_1),
        blind_eval_2: fp_to_u64(p.blind_eval_2),
        blind_mix_alpha: fp_to_u64(p.blind_mix_alpha),
        reference_profile: ref_to_json(p.reference_profile),
        verifier_commitment_hex: hex::encode(serialize_verifier_commitment(&p.verifier_commitment)),
        pcs_proof_main_hex: hex::encode(serialize_eval_proof(&p.pcs_proof_main)),
        pcs_proof_blind_1_hex: hex::encode(serialize_eval_proof(&p.pcs_proof_blind_1)),
        pcs_proof_blind_2_hex: hex::encode(serialize_eval_proof(&p.pcs_proof_blind_2)),
    }
}

fn proof_from_json(j: &ProofJson) -> Result<SpartanBrakedownProof> {
    Ok(SpartanBrakedownProof {
        outer_trace: outer_trace_from_json(&j.outer_trace),
        inner_trace: inner_trace_from_json(&j.inner_trace),
        gamma: u64_to_fp(j.gamma),
        claimed_value: u64_to_fp(j.claimed_value),
        blind_eval_1: u64_to_fp(j.blind_eval_1),
        blind_eval_2: u64_to_fp(j.blind_eval_2),
        blind_mix_alpha: u64_to_fp(j.blind_mix_alpha),
        reference_profile: ref_from_json(&j.reference_profile)?,
        verifier_commitment: deserialize_verifier_commitment(
            &hex::decode(&j.verifier_commitment_hex).context("bad verifier_commitment hex")?,
        )?,
        pcs_proof_main: deserialize_eval_proof(
            &hex::decode(&j.pcs_proof_main_hex).context("bad pcs_proof_main hex")?,
        )?,
        pcs_proof_blind_1: deserialize_eval_proof(
            &hex::decode(&j.pcs_proof_blind_1_hex).context("bad pcs_proof_blind_1 hex")?,
        )?,
        pcs_proof_blind_2: deserialize_eval_proof(
            &hex::decode(&j.pcs_proof_blind_2_hex).context("bad pcs_proof_blind_2 hex")?,
        )?,
    })
}

fn public_to_json(p: &SpartanBrakedownPublic) -> PublicJson {
    PublicJson {
        rows: p.rows,
        cols: p.cols,
        case_digest_hex: digest_to_hex(p.case_digest),
        outer_tensor_main: p.outer_tensor_main.iter().map(|v| fp_to_u64(*v)).collect(),
        outer_tensor_blind_1: p.outer_tensor_blind_1.iter().map(|v| fp_to_u64(*v)).collect(),
        outer_tensor_blind_2: p.outer_tensor_blind_2.iter().map(|v| fp_to_u64(*v)).collect(),
        inner_tensor: p.inner_tensor.iter().map(|v| fp_to_u64(*v)).collect(),
        claimed_value_unblinded: fp_to_u64(p.claimed_value_unblinded),
        claimed_value_masked: fp_to_u64(p.claimed_value_masked),
        reference_profile: ref_to_json(p.reference_profile),
    }
}

fn public_from_json(j: &PublicJson) -> Result<SpartanBrakedownPublic> {
    Ok(SpartanBrakedownPublic {
        rows: j.rows,
        cols: j.cols,
        case_digest: digest_from_hex(&j.case_digest_hex)?,
        outer_tensor_main: j.outer_tensor_main.iter().map(|v| u64_to_fp(*v)).collect(),
        outer_tensor_blind_1: j.outer_tensor_blind_1.iter().map(|v| u64_to_fp(*v)).collect(),
        outer_tensor_blind_2: j.outer_tensor_blind_2.iter().map(|v| u64_to_fp(*v)).collect(),
        inner_tensor: j.inner_tensor.iter().map(|v| u64_to_fp(*v)).collect(),
        claimed_value_unblinded: u64_to_fp(j.claimed_value_unblinded),
        claimed_value_masked: u64_to_fp(j.claimed_value_masked),
        reference_profile: ref_from_json(&j.reference_profile)?,
    })
}

fn timings_to_json(t: &KernelTimingMs) -> KernelTimingJson {
    KernelTimingJson {
        input_parse_ms: t.k0_input_parse_ms,
        spartan_prove_core_ms: t.k1_spartan_prove_ms,
        pcs_commit_open_prove_ms: t.k2_pcs_prove_ms,
        verify_ms: t.k3_verify_ms,
        total_ms: t.total_ms(),
    }
}

fn write_json<T: Serialize>(path: &PathBuf, v: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let body = serde_json::to_string_pretty(v)?;
    fs::write(path, body).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &PathBuf) -> Result<T> {
    let body =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(serde_json::from_str(&body)?)
}

fn run_compile(args: &[String]) -> Result<()> {
    if args.len() < 3 {
        bail!("usage: spark_e2e_cli compile <case_dir> <compiled.json> [profile]");
    }
    let case_dir = PathBuf::from(&args[1]);
    let out_compiled = PathBuf::from(&args[2]);
    let profile_s = args.get(3).cloned().unwrap_or_else(|| "m61".to_string());
    let profile = parse_field_profile(&profile_s)
        .ok_or_else(|| anyhow!("unknown profile '{}'; use toy|m61|gold", profile_s))?;
    let compiled = compile_from_dir_with_profile(&case_dir, profile)?;
    write_json(&out_compiled, &compiled_to_json(&compiled))?;
    println!("compile: ok");
    println!("  case_dir={}", case_dir.display());
    println!("  compiled={}", out_compiled.display());
    println!("  field_profile={:?}", compiled.field_profile);
    println!("  rows={}, cols={}", compiled.rows, compiled.cols);
    Ok(())
}

fn run_prove(args: &[String]) -> Result<()> {
    if args.len() < 5 {
        bail!("usage: spark_e2e_cli prove <compiled.json> <case_dir> <proof.json> <public.json>");
    }
    let compiled_path = PathBuf::from(&args[1]);
    let case_dir = PathBuf::from(&args[2]);
    let proof_path = PathBuf::from(&args[3]);
    let public_path = PathBuf::from(&args[4]);

    let compiled_json: CompiledJson = read_json(&compiled_path)?;
    let compiled = compiled_from_json(&compiled_json)?;
    let started = Instant::now();
    let res = prove_with_compiled_from_dir(&compiled, &case_dir)?;
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;

    write_json(&proof_path, &proof_to_json(&res.proof))?;
    write_json(&public_path, &public_to_json(&res.public))?;
    let timing = timings_to_json(&res.timings);
    let timing_path = proof_path.with_extension("timings.json");
    write_json(&timing_path, &timing)?;

    println!("prove: ok");
    println!("  compiled={}", compiled_path.display());
    println!("  case_dir={}", case_dir.display());
    println!("  proof={}", proof_path.display());
    println!("  public={}", public_path.display());
    println!("  timings={}", timing_path.display());
    println!(
        "  runtime_ms={:.3} (k1={:.3}, k2={:.3}, k3={:.3})",
        elapsed_ms, timing.spartan_prove_core_ms, timing.pcs_commit_open_prove_ms, timing.verify_ms
    );
    Ok(())
}

fn run_verify(args: &[String]) -> Result<()> {
    if args.len() < 4 {
        bail!("usage: spark_e2e_cli verify <compiled.json> <proof.json> <public.json>");
    }
    let compiled_path = PathBuf::from(&args[1]);
    let proof_path = PathBuf::from(&args[2]);
    let public_path = PathBuf::from(&args[3]);

    let compiled = compiled_from_json(&read_json::<CompiledJson>(&compiled_path)?)?;
    let _mod_scope = ModulusScope::enter(compiled.field_profile.base_modulus());
    let proof = proof_from_json(&read_json::<ProofJson>(&proof_path)?)?;
    let public = public_from_json(&read_json::<PublicJson>(&public_path)?)?;

    let started = Instant::now();
    verify_with_compiled(&compiled, &proof, &public)?;
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;

    println!("verify: ok");
    println!("  compiled={}", compiled_path.display());
    println!("  proof={}", proof_path.display());
    println!("  public={}", public_path.display());
    println!("  runtime_ms={:.3}", elapsed_ms);
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        bail!(
            "usage:\n  spark_e2e_cli compile <case_dir> <compiled.json> [profile]\n  spark_e2e_cli prove <compiled.json> <case_dir> <proof.json> <public.json>\n  spark_e2e_cli verify <compiled.json> <proof.json> <public.json>"
        );
    }

    match args[1].as_str() {
        "compile" => run_compile(&args[1..]),
        "prove" => run_prove(&args[1..]),
        "verify" => run_verify(&args[1..]),
        other => bail!("unknown command '{}'", other),
    }
}
