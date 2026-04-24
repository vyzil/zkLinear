use std::{fs, path::PathBuf};

use anyhow::{anyhow, Result};
use zk_linear::{
    io::r1cs_zkif::import_spartan_like_instance_from_zkif_workspace, nizk::spartan_brakedown::prove,
};
use zkinterface::producers::{
    builder::Sink,
    examples::{example_circuit_header, example_constraints, example_witness},
    workspace::WorkspaceSink,
};

fn main() -> Result<()> {
    let base = PathBuf::from("tests/generated_cases/zkif_example");
    let src_ws = base.join("workspace");
    let dst_case = base.join("instance");
    fs::create_dir_all(&src_ws)?;
    fs::create_dir_all(&dst_case)?;

    let mut sink = WorkspaceSink::new(&src_ws).map_err(|e| anyhow!(e.to_string()))?;
    sink.push_header(example_circuit_header())
        .map_err(|e| anyhow!(e.to_string()))?;
    sink.push_witness(example_witness())
        .map_err(|e| anyhow!(e.to_string()))?;
    sink.push_constraints(example_constraints())
        .map_err(|e| anyhow!(e.to_string()))?;

    import_spartan_like_instance_from_zkif_workspace(&src_ws, &dst_case)?;
    let res = prove(&dst_case)?;

    println!("generated zkif workspace: {}", src_ws.display());
    println!("generated zklinear instance: {}", dst_case.display());
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
    println!(
        "  verify: {:.3} ({:.1}%)",
        t.k3_verify_ms,
        t.pct(t.k3_verify_ms)
    );
    println!("  total: {:.3}", t.total_ms());
    Ok(())
}
