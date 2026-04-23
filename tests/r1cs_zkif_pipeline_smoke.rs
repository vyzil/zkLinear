use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use zk_linear::{
    io::r1cs_zkif::import_spartan_like_case_from_zkif_workspace,
    nizk::spartan_brakedown::prove_from_dir,
};
use zkinterface::{
    producers::{
        builder::Sink,
        examples::{example_circuit_header, example_constraints, example_witness},
        workspace::WorkspaceSink,
    },
};

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{}_{}_{}", prefix, std::process::id(), now))
}

#[test]
fn r1cs_zkif_import_and_profile_smoke() {
    let src_ws = unique_temp_dir("zklinear_r1cs_zkif_src");
    let dst_case = unique_temp_dir("zklinear_r1cs_zkif_case");
    fs::create_dir_all(&src_ws).expect("create src workspace dir");
    fs::create_dir_all(&dst_case).expect("create dst case dir");

    let mut sink = WorkspaceSink::new(&src_ws).expect("create workspace sink");
    sink.push_header(example_circuit_header())
        .expect("write header zkif");
    sink.push_witness(example_witness())
        .expect("write witness zkif");
    sink.push_constraints(example_constraints())
        .expect("write constraints zkif");

    import_spartan_like_case_from_zkif_workspace(&src_ws, &dst_case)
        .expect("import zkif->case should succeed");
    let res = prove_from_dir(&dst_case).expect("prove/verify should succeed on imported case");

    println!("=== R1CS zkInterface Import Smoke ===");
    println!("workspace: {}", src_ws.display());
    println!("case: {}", dst_case.display());
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
    println!("claimed(masked)={}", res.proof.claimed_value.0);
    println!(
        "payload openings: main={}, blind1={}, blind2={}",
        res.proof.pcs_proof_main.columns.len(),
        res.proof.pcs_proof_blind_1.columns.len(),
        res.proof.pcs_proof_blind_2.columns.len()
    );

    let _ = fs::remove_dir_all(&src_ws);
    let _ = fs::remove_dir_all(&dst_case);
}
