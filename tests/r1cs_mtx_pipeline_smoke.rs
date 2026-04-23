use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use zk_linear::{
    io::r1cs_mtx::import_spartan_like_case_from_mtx_dir,
    nizk::spartan_brakedown::prove_from_dir,
};

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{}_{}_{}", prefix, std::process::id(), now))
}

fn write_text(path: &PathBuf, body: &str) {
    fs::write(path, body).expect("failed to write fixture file");
}

#[test]
fn r1cs_mtx_import_and_profile_smoke() {
    let src = unique_temp_dir("zklinear_r1cs_mtx_src");
    let dst = unique_temp_dir("zklinear_r1cs_mtx_dst");
    fs::create_dir_all(&src).expect("create src fixture dir");
    fs::create_dir_all(&dst).expect("create dst fixture dir");

    // 4x8 sparse matrices in Matrix Market coordinate format (1-based indices).
    write_text(
        &src.join("A.mtx"),
        r#"%%MatrixMarket matrix coordinate integer general
4 8 4
1 1 1
2 2 1
3 3 1
4 4 1
"#,
    );
    write_text(
        &src.join("B.mtx"),
        r#"%%MatrixMarket matrix coordinate integer general
4 8 4
1 2 1
2 3 1
3 4 1
4 1 1
"#,
    );
    write_text(
        &src.join("C.mtx"),
        r#"%%MatrixMarket matrix coordinate integer general
4 8 1
1 3 1
"#,
    );
    write_text(&src.join("z.vec"), "3 4 12 5 0 0 0 0\n");

    import_spartan_like_case_from_mtx_dir(&src, &dst).expect("import mtx->case should succeed");
    let res = prove_from_dir(&dst).expect("prove/verify on imported case should succeed");

    println!("=== R1CS MTX Import Smoke ===");
    println!("src: {}", src.display());
    println!("dst: {}", dst.display());
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
        "payload lens: main={}, blind1={}, blind2={}",
        res.proof.pcs_proof_main.columns.len(),
        res.proof.pcs_proof_blind_1.columns.len(),
        res.proof.pcs_proof_blind_2.columns.len()
    );
    println!("claimed(masked)={}", res.proof.claimed_value.0);

    // cleanup best-effort
    let _ = fs::remove_dir_all(&src);
    let _ = fs::remove_dir_all(&dst);
}
