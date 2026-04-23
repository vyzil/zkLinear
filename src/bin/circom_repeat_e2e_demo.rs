use std::{fs, path::PathBuf, process::Command};

use anyhow::{anyhow, bail, Result};
use zk_linear::{
    io::r1cs_circom::import_spartan_like_case_from_circom_json,
    nizk::spartan_brakedown::prove_from_dir,
    pcs::brakedown::wire::{serialize_eval_proof, serialize_verifier_commitment},
};

fn fmt_commas_u64(v: u64) -> String {
    let s = v.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    let bytes = s.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        out.push(*b as char);
        let rem = bytes.len() - i - 1;
        if rem > 0 && rem.is_multiple_of(3) {
            out.push(',');
        }
    }
    out
}

fn run_cmd(cmd: &mut Command, label: &str) -> Result<()> {
    let out = cmd.output().map_err(|e| anyhow!("{} spawn error: {}", label, e))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        bail!(
            "{} failed\nstdout:\n{}\nstderr:\n{}",
            label,
            stdout,
            stderr
        );
    }
    Ok(())
}

fn main() -> Result<()> {
    let k: u32 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(14); // default: 2^14 constraints
    if k >= usize::BITS {
        bail!("k is too large for this platform (k={})", k);
    }
    let n_constraints: usize = 1usize << k;

    let base = PathBuf::from(format!(
        "tests/generated_cases/circom_repeat_2pow{}",
        k
    ));
    let ws = base.join("workspace");
    let case = base.join("case");
    fs::create_dir_all(&ws)?;
    fs::create_dir_all(&case)?;

    let circom_src = format!(
        r#"pragma circom 2.1.6;
template RepeatEq(N) {{
  signal input x;
  signal input y;
  signal output z;
  z <== x * y;
  for (var i = 0; i < N; i++) {{
    x * y === z;
  }}
}}
component main = RepeatEq({n});
"#,
        n = n_constraints
    );
    fs::write(ws.join("repeat.circom"), circom_src)?;
    fs::write(ws.join("input.json"), r#"{"x":"7","y":"13"}"#)?;

    run_cmd(
        Command::new("circom")
            .arg("repeat.circom")
            .arg("--r1cs")
            .arg("--wasm")
            .arg("--sym")
            .arg("-o")
            .arg(".")
            .current_dir(&ws),
        "circom build",
    )?;

    run_cmd(
        Command::new("node")
            .arg("repeat_js/generate_witness.js")
            .arg("repeat_js/repeat.wasm")
            .arg("input.json")
            .arg("witness.wtns")
            .current_dir(&ws),
        "witness generate",
    )?;

    run_cmd(
        Command::new("snarkjs")
            .arg("r1cs")
            .arg("info")
            .arg("repeat.r1cs")
            .current_dir(&ws),
        "snarkjs r1cs info",
    )?;

    run_cmd(
        Command::new("snarkjs")
            .arg("r1cs")
            .arg("export")
            .arg("json")
            .arg("repeat.r1cs")
            .arg("repeat.r1cs.json")
            .current_dir(&ws),
        "snarkjs r1cs export json",
    )?;
    run_cmd(
        Command::new("snarkjs")
            .arg("wtns")
            .arg("export")
            .arg("json")
            .arg("witness.wtns")
            .arg("witness.json")
            .current_dir(&ws),
        "snarkjs wtns export json",
    )?;

    import_spartan_like_case_from_circom_json(
        &ws.join("repeat.r1cs.json"),
        &ws.join("witness.json"),
        &case,
    )?;

    let res = prove_from_dir(&case)?;

    println!(
        "circom constraints: 2^{} = {}",
        k,
        fmt_commas_u64(n_constraints as u64)
    );
    println!("workspace: {}", ws.display());
    println!("case: {}", case.display());
    let t = &res.timings;
    println!("timing(ms):");
    println!(
        "  input_parse: {:.3} ({:.1}%)",
        t.k0_input_parse_ms,
        t.pct(t.k0_input_parse_ms)
    );
    println!(
        "  spartan_prove_core: {:.3} ({:.1}%)",
        t.k1_spartan_prove_ms,
        t.pct(t.k1_spartan_prove_ms)
    );
    println!(
        "  pcs_commit_open_prove: {:.3} ({:.1}%)",
        t.k2_pcs_prove_ms,
        t.pct(t.k2_pcs_prove_ms)
    );
    println!("  verify: {:.3} ({:.1}%)", t.k3_verify_ms, t.pct(t.k3_verify_ms));
    println!("  total: {:.3}", t.total_ms());
    println!(
        "payload openings: main={}, blind1={}, blind2={}",
        res.proof.pcs_proof_main.columns.len(),
        res.proof.pcs_proof_blind_1.columns.len(),
        res.proof.pcs_proof_blind_2.columns.len()
    );
    let vc_bytes = serialize_verifier_commitment(&res.proof.verifier_commitment).len();
    let pf_main_bytes = serialize_eval_proof(&res.proof.pcs_proof_main).len();
    let pf_b1_bytes = serialize_eval_proof(&res.proof.pcs_proof_blind_1).len();
    let pf_b2_bytes = serialize_eval_proof(&res.proof.pcs_proof_blind_2).len();
    let pcs_total = vc_bytes + pf_main_bytes + pf_b1_bytes + pf_b2_bytes;
    println!("proof size(bytes):");
    println!("  verifier_commitment: {}", fmt_commas_u64(vc_bytes as u64));
    println!("  pcs_opening_main: {}", fmt_commas_u64(pf_main_bytes as u64));
    println!("  pcs_opening_blind1: {}", fmt_commas_u64(pf_b1_bytes as u64));
    println!("  pcs_opening_blind2: {}", fmt_commas_u64(pf_b2_bytes as u64));
    println!("  pcs_subtotal: {}", fmt_commas_u64(pcs_total as u64));
    println!("claimed(masked)={}", res.proof.claimed_value.0);

    Ok(())
}
