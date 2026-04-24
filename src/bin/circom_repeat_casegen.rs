use std::{fs, path::PathBuf, process::Command};

use anyhow::{anyhow, bail, Result};
use zk_linear::io::r1cs_circom::import_spartan_like_case_from_circom_json;

fn run_cmd(cmd: &mut Command, label: &str) -> Result<()> {
    let out = cmd
        .output()
        .map_err(|e| anyhow!("{} spawn error: {}", label, e))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        bail!("{} failed\nstdout:\n{}\nstderr:\n{}", label, stdout, stderr);
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

    let base = PathBuf::from(format!("tests/generated_cases/circom_repeat_2pow{}", k));
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

    println!("generated case:");
    println!("  constraints: 2^{}", k);
    println!("  workspace: {}", ws.display());
    println!("  case: {}", case.display());
    Ok(())
}
