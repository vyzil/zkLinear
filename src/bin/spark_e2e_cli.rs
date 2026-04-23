use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

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
    context_fingerprint_hex: String,
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
    claimed_value_unblinded: u64,
    claimed_value: u64,
    blind_eval_1: u64,
    blind_eval_2: u64,
    blind_mix_alpha: u64,
    reference_profile: RefProfileJson,
    verifier_commitment_hex: String,
    pcs_proof_main_hex: String,
    pcs_proof_blind_1_hex: String,
    pcs_proof_blind_2_hex: String,
    pcs_proof_joint_eval_at_r_hex: String,
    pcs_proof_z_eval_at_r_hex: String,
    context_fingerprint_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PublicJson {
    rows: usize,
    cols: usize,
    case_digest_hex: String,
    claimed_value_masked: u64,
    context_fingerprint_hex: String,
    reference_profile: RefProfileJson,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompiledWire {
    rows: usize,
    cols: usize,
    case_digest: [u8; 32],
    context_fingerprint: [u8; 32],
    field_profile: String,
    reference_profile: RefProfileJson,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProofWire {
    outer_trace: OuterTraceJson,
    inner_trace: InnerTraceJson,
    gamma: u64,
    claimed_value_unblinded: u64,
    claimed_value: u64,
    blind_eval_1: u64,
    blind_eval_2: u64,
    blind_mix_alpha: u64,
    reference_profile: RefProfileJson,
    verifier_commitment: Vec<u8>,
    pcs_proof_main: Vec<u8>,
    pcs_proof_blind_1: Vec<u8>,
    pcs_proof_blind_2: Vec<u8>,
    pcs_proof_joint_eval_at_r: Vec<u8>,
    pcs_proof_z_eval_at_r: Vec<u8>,
    context_fingerprint: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PublicWire {
    rows: usize,
    cols: usize,
    case_digest: [u8; 32],
    claimed_value_masked: u64,
    context_fingerprint: [u8; 32],
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
        context_fingerprint_hex: digest_to_hex(c.context_fingerprint),
        field_profile: format!("{:?}", c.field_profile),
        reference_profile: ref_to_json(c.reference_profile),
    }
}

fn compiled_to_wire(c: &SpartanBrakedownCompiledCircuit) -> CompiledWire {
    CompiledWire {
        rows: c.rows,
        cols: c.cols,
        case_digest: c.case_digest,
        context_fingerprint: c.context_fingerprint,
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
        context_fingerprint: digest_from_hex(&j.context_fingerprint_hex)?,
        field_profile,
        reference_profile: ref_from_json(&j.reference_profile)?,
    })
}

fn compiled_from_wire(j: &CompiledWire) -> Result<SpartanBrakedownCompiledCircuit> {
    let field_profile = parse_field_profile(&j.field_profile)
        .ok_or_else(|| anyhow!("unknown field profile '{}'", j.field_profile))?;
    Ok(SpartanBrakedownCompiledCircuit {
        rows: j.rows,
        cols: j.cols,
        case_digest: j.case_digest,
        context_fingerprint: j.context_fingerprint,
        field_profile,
        reference_profile: ref_from_json(&j.reference_profile)?,
    })
}

fn proof_to_json(p: &SpartanBrakedownProof) -> ProofJson {
    ProofJson {
        outer_trace: outer_trace_to_json(&p.outer_trace),
        inner_trace: inner_trace_to_json(&p.inner_trace),
        gamma: fp_to_u64(p.gamma),
        claimed_value_unblinded: fp_to_u64(p.claimed_value_unblinded),
        claimed_value: fp_to_u64(p.claimed_value),
        blind_eval_1: fp_to_u64(p.blind_eval_1),
        blind_eval_2: fp_to_u64(p.blind_eval_2),
        blind_mix_alpha: fp_to_u64(p.blind_mix_alpha),
        reference_profile: ref_to_json(p.reference_profile),
        verifier_commitment_hex: hex::encode(serialize_verifier_commitment(&p.verifier_commitment)),
        pcs_proof_main_hex: hex::encode(serialize_eval_proof(&p.pcs_proof_main)),
        pcs_proof_blind_1_hex: hex::encode(serialize_eval_proof(&p.pcs_proof_blind_1)),
        pcs_proof_blind_2_hex: hex::encode(serialize_eval_proof(&p.pcs_proof_blind_2)),
        pcs_proof_joint_eval_at_r_hex: hex::encode(serialize_eval_proof(&p.pcs_proof_joint_eval_at_r)),
        pcs_proof_z_eval_at_r_hex: hex::encode(serialize_eval_proof(&p.pcs_proof_z_eval_at_r)),
        context_fingerprint_hex: digest_to_hex(p.context_fingerprint),
    }
}

fn proof_to_wire(p: &SpartanBrakedownProof) -> ProofWire {
    ProofWire {
        outer_trace: outer_trace_to_json(&p.outer_trace),
        inner_trace: inner_trace_to_json(&p.inner_trace),
        gamma: fp_to_u64(p.gamma),
        claimed_value_unblinded: fp_to_u64(p.claimed_value_unblinded),
        claimed_value: fp_to_u64(p.claimed_value),
        blind_eval_1: fp_to_u64(p.blind_eval_1),
        blind_eval_2: fp_to_u64(p.blind_eval_2),
        blind_mix_alpha: fp_to_u64(p.blind_mix_alpha),
        reference_profile: ref_to_json(p.reference_profile),
        verifier_commitment: serialize_verifier_commitment(&p.verifier_commitment),
        pcs_proof_main: serialize_eval_proof(&p.pcs_proof_main),
        pcs_proof_blind_1: serialize_eval_proof(&p.pcs_proof_blind_1),
        pcs_proof_blind_2: serialize_eval_proof(&p.pcs_proof_blind_2),
        pcs_proof_joint_eval_at_r: serialize_eval_proof(&p.pcs_proof_joint_eval_at_r),
        pcs_proof_z_eval_at_r: serialize_eval_proof(&p.pcs_proof_z_eval_at_r),
        context_fingerprint: p.context_fingerprint,
    }
}

fn proof_from_json(j: &ProofJson) -> Result<SpartanBrakedownProof> {
    Ok(SpartanBrakedownProof {
        outer_trace: outer_trace_from_json(&j.outer_trace),
        inner_trace: inner_trace_from_json(&j.inner_trace),
        gamma: u64_to_fp(j.gamma),
        claimed_value_unblinded: u64_to_fp(j.claimed_value_unblinded),
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
        pcs_proof_joint_eval_at_r: deserialize_eval_proof(
            &hex::decode(&j.pcs_proof_joint_eval_at_r_hex)
                .context("bad pcs_proof_joint_eval_at_r hex")?,
        )?,
        pcs_proof_z_eval_at_r: deserialize_eval_proof(
            &hex::decode(&j.pcs_proof_z_eval_at_r_hex)
                .context("bad pcs_proof_z_eval_at_r hex")?,
        )?,
        context_fingerprint: digest_from_hex(&j.context_fingerprint_hex)?,
    })
}

fn proof_from_wire(j: &ProofWire) -> Result<SpartanBrakedownProof> {
    Ok(SpartanBrakedownProof {
        outer_trace: outer_trace_from_json(&j.outer_trace),
        inner_trace: inner_trace_from_json(&j.inner_trace),
        gamma: u64_to_fp(j.gamma),
        claimed_value_unblinded: u64_to_fp(j.claimed_value_unblinded),
        claimed_value: u64_to_fp(j.claimed_value),
        blind_eval_1: u64_to_fp(j.blind_eval_1),
        blind_eval_2: u64_to_fp(j.blind_eval_2),
        blind_mix_alpha: u64_to_fp(j.blind_mix_alpha),
        reference_profile: ref_from_json(&j.reference_profile)?,
        verifier_commitment: deserialize_verifier_commitment(&j.verifier_commitment)?,
        pcs_proof_main: deserialize_eval_proof(&j.pcs_proof_main)?,
        pcs_proof_blind_1: deserialize_eval_proof(&j.pcs_proof_blind_1)?,
        pcs_proof_blind_2: deserialize_eval_proof(&j.pcs_proof_blind_2)?,
        pcs_proof_joint_eval_at_r: deserialize_eval_proof(&j.pcs_proof_joint_eval_at_r)?,
        pcs_proof_z_eval_at_r: deserialize_eval_proof(&j.pcs_proof_z_eval_at_r)?,
        context_fingerprint: j.context_fingerprint,
    })
}

fn public_to_json(p: &SpartanBrakedownPublic) -> PublicJson {
    PublicJson {
        rows: p.rows,
        cols: p.cols,
        case_digest_hex: digest_to_hex(p.case_digest),
        claimed_value_masked: fp_to_u64(p.claimed_value_masked),
        context_fingerprint_hex: digest_to_hex(p.context_fingerprint),
        reference_profile: ref_to_json(p.reference_profile),
    }
}

fn public_to_wire(p: &SpartanBrakedownPublic) -> PublicWire {
    PublicWire {
        rows: p.rows,
        cols: p.cols,
        case_digest: p.case_digest,
        claimed_value_masked: fp_to_u64(p.claimed_value_masked),
        context_fingerprint: p.context_fingerprint,
        reference_profile: ref_to_json(p.reference_profile),
    }
}

fn public_from_json(j: &PublicJson) -> Result<SpartanBrakedownPublic> {
    Ok(SpartanBrakedownPublic {
        rows: j.rows,
        cols: j.cols,
        case_digest: digest_from_hex(&j.case_digest_hex)?,
        claimed_value_masked: u64_to_fp(j.claimed_value_masked),
        context_fingerprint: digest_from_hex(&j.context_fingerprint_hex)?,
        reference_profile: ref_from_json(&j.reference_profile)?,
    })
}

fn public_from_wire(j: &PublicWire) -> Result<SpartanBrakedownPublic> {
    Ok(SpartanBrakedownPublic {
        rows: j.rows,
        cols: j.cols,
        case_digest: j.case_digest,
        claimed_value_masked: u64_to_fp(j.claimed_value_masked),
        context_fingerprint: j.context_fingerprint,
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

fn write_wire<T: Serialize>(path: &PathBuf, v: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let body = bincode::serialize(v).context("failed to serialize wire payload")?;
    fs::write(path, body).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn read_wire<T: for<'de> Deserialize<'de>>(path: &PathBuf) -> Result<T> {
    let body = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    bincode::deserialize(&body).context("failed to deserialize wire payload")
}

fn sidecar_wire_path(path: &Path) -> PathBuf {
    path.with_extension("wire")
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
    let compiled_wire = sidecar_wire_path(&out_compiled);
    write_json(&out_compiled, &compiled_to_json(&compiled))?;
    write_wire(&compiled_wire, &compiled_to_wire(&compiled))?;
    println!("compile: ok");
    println!("  case_dir={}", case_dir.display());
    println!("  compiled={}", out_compiled.display());
    println!("  compiled_wire={}", compiled_wire.display());
    println!("  field_profile={:?}", compiled.field_profile);
    println!("  rows={}, cols={}", compiled.rows, compiled.cols);
    Ok(())
}

fn run_prove(args: &[String]) -> Result<()> {
    if args.len() < 5 {
        bail!("usage: spark_e2e_cli prove <compiled.json|compiled.wire> <case_dir> <proof.json> <public.json>");
    }
    let compiled_path = PathBuf::from(&args[1]);
    let case_dir = PathBuf::from(&args[2]);
    let proof_path = PathBuf::from(&args[3]);
    let public_path = PathBuf::from(&args[4]);

    let compiled = if compiled_path.extension().and_then(|s| s.to_str()) == Some("wire") {
        compiled_from_wire(&read_wire::<CompiledWire>(&compiled_path)?)?
    } else {
        let compiled_json: CompiledJson = read_json(&compiled_path)?;
        compiled_from_json(&compiled_json)?
    };
    let started = Instant::now();
    let res = prove_with_compiled_from_dir(&compiled, &case_dir)?;
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;

    write_json(&proof_path, &proof_to_json(&res.proof))?;
    write_json(&public_path, &public_to_json(&res.public))?;
    let proof_wire = sidecar_wire_path(&proof_path);
    let public_wire = sidecar_wire_path(&public_path);
    write_wire(&proof_wire, &proof_to_wire(&res.proof))?;
    write_wire(&public_wire, &public_to_wire(&res.public))?;
    let timing = timings_to_json(&res.timings);
    let timing_path = proof_path.with_extension("timings.json");
    write_json(&timing_path, &timing)?;

    println!("prove: ok");
    println!("  compiled={}", compiled_path.display());
    println!("  case_dir={}", case_dir.display());
    println!("  proof={}", proof_path.display());
    println!("  proof_wire={}", proof_wire.display());
    println!("  public={}", public_path.display());
    println!("  public_wire={}", public_wire.display());
    println!("  timings={}", timing_path.display());
    println!(
        "  runtime_ms={:.3} (k1={:.3}, k2={:.3}, k3={:.3})",
        elapsed_ms, timing.spartan_prove_core_ms, timing.pcs_commit_open_prove_ms, timing.verify_ms
    );
    Ok(())
}

fn run_prove_k(args: &[String]) -> Result<()> {
    if args.len() < 3 {
        bail!("usage: spark_e2e_cli prove-k <k> <out_dir> [profile]");
    }
    let k = args[1]
        .parse::<u32>()
        .with_context(|| format!("invalid k '{}'", args[1]))?;
    let out_dir = PathBuf::from(&args[2]);
    let profile_s = args.get(3).cloned().unwrap_or_else(|| "m61".to_string());
    let profile = parse_field_profile(&profile_s)
        .ok_or_else(|| anyhow!("unknown profile '{}'; use toy|m61|gold", profile_s))?;

    let case_dir = PathBuf::from(format!("tests/generated_cases/circom_repeat_2pow{}/case", k));
    if !case_dir.exists() {
        bail!(
            "case dir not found: {} (generate it first, e.g. with circom_repeat_e2e_demo)",
            case_dir.display()
        );
    }

    let compiled_path = out_dir.join("compiled.json");
    let proof_path = out_dir.join("proof.json");
    let public_path = out_dir.join("public.json");
    let compiled_wire = sidecar_wire_path(&compiled_path);
    let proof_wire = sidecar_wire_path(&proof_path);
    let public_wire = sidecar_wire_path(&public_path);

    let t_compile = Instant::now();
    let compiled = compile_from_dir_with_profile(&case_dir, profile)?;
    let compile_ms = t_compile.elapsed().as_secs_f64() * 1000.0;
    write_json(&compiled_path, &compiled_to_json(&compiled))?;
    write_wire(&compiled_wire, &compiled_to_wire(&compiled))?;

    let t_prove = Instant::now();
    let res = prove_with_compiled_from_dir(&compiled, &case_dir)?;
    let prove_ms = t_prove.elapsed().as_secs_f64() * 1000.0;
    write_json(&proof_path, &proof_to_json(&res.proof))?;
    write_json(&public_path, &public_to_json(&res.public))?;
    write_wire(&proof_wire, &proof_to_wire(&res.proof))?;
    write_wire(&public_wire, &public_to_wire(&res.public))?;
    let timing_path = out_dir.join("prove.timings.json");
    write_json(&timing_path, &timings_to_json(&res.timings))?;

    println!("prove-k: ok");
    println!("  k={}", k);
    println!("  case_dir={}", case_dir.display());
    println!("  compiled={}", compiled_path.display());
    println!("  compiled_wire={}", compiled_wire.display());
    println!("  proof={}", proof_path.display());
    println!("  proof_wire={}", proof_wire.display());
    println!("  public={}", public_path.display());
    println!("  public_wire={}", public_wire.display());
    println!("  timings={}", timing_path.display());
    println!("  compile_ms={:.3}", compile_ms);
    println!("  prove_end_to_end_ms={:.3}", prove_ms);
    println!(
        "  prove_breakdown_ms: input_parse={:.3}, spartan_core={:.3}, pcs_prove={:.3}, inline_verify={:.3}",
        res.timings.k0_input_parse_ms,
        res.timings.k1_spartan_prove_ms,
        res.timings.k2_pcs_prove_ms,
        res.timings.k3_verify_ms
    );
    Ok(())
}

fn run_verify(args: &[String]) -> Result<()> {
    if args.len() < 4 {
        bail!("usage: spark_e2e_cli verify <compiled.json|compiled.wire> <proof.json|proof.wire> <public.json|public.wire>");
    }
    let compiled_path = PathBuf::from(&args[1]);
    let proof_path = PathBuf::from(&args[2]);
    let public_path = PathBuf::from(&args[3]);

    let compiled = if compiled_path.extension().and_then(|s| s.to_str()) == Some("wire") {
        compiled_from_wire(&read_wire::<CompiledWire>(&compiled_path)?)?
    } else {
        compiled_from_json(&read_json::<CompiledJson>(&compiled_path)?)?
    };
    let _mod_scope = ModulusScope::enter(compiled.field_profile.base_modulus());
    let proof = if proof_path.extension().and_then(|s| s.to_str()) == Some("wire") {
        proof_from_wire(&read_wire::<ProofWire>(&proof_path)?)?
    } else {
        proof_from_json(&read_json::<ProofJson>(&proof_path)?)?
    };
    let public = if public_path.extension().and_then(|s| s.to_str()) == Some("wire") {
        public_from_wire(&read_wire::<PublicWire>(&public_path)?)?
    } else {
        public_from_json(&read_json::<PublicJson>(&public_path)?)?
    };

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

fn run_inspect(args: &[String]) -> Result<()> {
    if args.len() < 2 {
        bail!("usage: spark_e2e_cli inspect <proof.json|proof.wire>");
    }
    let proof_path = PathBuf::from(&args[1]);
    let proof_wire = if proof_path.extension().and_then(|s| s.to_str()) == Some("wire") {
        read_wire::<ProofWire>(&proof_path)?
    } else {
        let proof_json = read_json::<ProofJson>(&proof_path)?;
        let proof = proof_from_json(&proof_json)?;
        proof_to_wire(&proof)
    };

    let vc_bytes_raw = proof_wire.verifier_commitment.clone();
    let verifier_commitment = deserialize_verifier_commitment(&vc_bytes_raw)?;
    let _mod_scope = ModulusScope::enter(verifier_commitment.field_profile.base_modulus());
    let vc_bytes = vc_bytes_raw.len();
    let pf_main_bytes = proof_wire.pcs_proof_main.clone();
    let pf_b1_bytes = proof_wire.pcs_proof_blind_1.clone();
    let pf_b2_bytes = proof_wire.pcs_proof_blind_2.clone();
    let pf_joint_r_bytes = proof_wire.pcs_proof_joint_eval_at_r.clone();
    let pf_z_r_bytes = proof_wire.pcs_proof_z_eval_at_r.clone();
    let main_openings = deserialize_eval_proof(&pf_main_bytes)?.columns.len();
    let b1_openings = deserialize_eval_proof(&pf_b1_bytes)?.columns.len();
    let b2_openings = deserialize_eval_proof(&pf_b2_bytes)?.columns.len();
    let joint_r_openings = deserialize_eval_proof(&pf_joint_r_bytes)?.columns.len();
    let z_r_openings = deserialize_eval_proof(&pf_z_r_bytes)?.columns.len();
    let proof_wire_bytes = bincode::serialize(&proof_wire)
        .context("failed to encode proof wire for sizing")?
        .len();

    println!("inspect: {}", proof_path.display());
    println!(
        "  rounds: outer={}, inner={}",
        proof_wire.outer_trace.rounds.len(),
        proof_wire.inner_trace.rounds.len()
    );
    println!("  gamma={}", proof_wire.gamma);
    println!("  claimed(masked)={}", proof_wire.claimed_value);
    println!("  blind_eval_1={}", proof_wire.blind_eval_1);
    println!("  blind_eval_2={}", proof_wire.blind_eval_2);
    println!("  blind_mix_alpha={}", proof_wire.blind_mix_alpha);
    println!("  proof_wire_bytes={}", proof_wire_bytes);
    println!(
        "  pcs payload bytes: vc={}, main={}, blind1={}, blind2={}, joint_r={}, z_r={}, subtotal={}",
        vc_bytes,
        pf_main_bytes.len(),
        pf_b1_bytes.len(),
        pf_b2_bytes.len(),
        pf_joint_r_bytes.len(),
        pf_z_r_bytes.len(),
        vc_bytes
            + pf_main_bytes.len()
            + pf_b1_bytes.len()
            + pf_b2_bytes.len()
            + pf_joint_r_bytes.len()
            + pf_z_r_bytes.len()
    );
    println!(
        "  pcs openings count: main={}, blind1={}, blind2={}, joint_r={}, z_r={}",
        main_openings, b1_openings, b2_openings, joint_r_openings, z_r_openings
    );
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        bail!(
            "usage:\n  spark_e2e_cli compile <case_dir> <compiled.json> [profile]\n  spark_e2e_cli prove <compiled.json|compiled.wire> <case_dir> <proof.json> <public.json>\n  spark_e2e_cli prove-k <k> <out_dir> [profile]\n  spark_e2e_cli inspect <proof.json|proof.wire>\n  spark_e2e_cli verify <compiled.json|compiled.wire> <proof.json|proof.wire> <public.json|public.wire>"
        );
    }

    match args[1].as_str() {
        "compile" => run_compile(&args[1..]),
        "prove" => run_prove(&args[1..]),
        "prove-k" => run_prove_k(&args[1..]),
        "inspect" => run_inspect(&args[1..]),
        "verify" => run_verify(&args[1..]),
        other => bail!("unknown command '{}'", other),
    }
}
