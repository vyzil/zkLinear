use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use zk_linear::nizk::spartan_brakedown::{
    compile_from_dir, compile_from_dir_with_profile, parse_field_profile, prove_from_dir,
};

fn case_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/inner_sumcheck_spartan")
}

fn unique_tmp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic")
        .as_nanos();
    std::env::temp_dir().join(format!("{}_{}_{}", prefix, std::process::id(), nanos))
}

fn write_matrix(path: &PathBuf, rows: usize, cols: usize) {
    let mut body = format!("size: {},{}\n", rows, cols);
    body.push_str("data:\n");
    for r in 0..rows {
        let line = (0..cols)
            .map(|c| ((r * cols + c + 1) as u64).to_string())
            .collect::<Vec<_>>()
            .join(", ");
        body.push_str(&line);
        body.push('\n');
    }
    fs::write(path, body).expect("write matrix");
}

fn write_vector(path: &PathBuf, len: usize) {
    let mut body = format!("size: {}\n", len);
    body.push_str("data:\n");
    body.push_str(
        &(0..len)
            .map(|i| ((i + 1) as u64).to_string())
            .collect::<Vec<_>>()
            .join(", "),
    );
    body.push('\n');
    fs::write(path, body).expect("write vector");
}

fn build_case(rows: usize, cols: usize, z_len: usize) -> PathBuf {
    let dir = unique_tmp_dir("zklinear_compiler_case");
    fs::create_dir_all(&dir).expect("create temp case dir");
    write_matrix(&dir.join("_A.data"), rows, cols);
    write_matrix(&dir.join("_B.data"), rows, cols);
    write_matrix(&dir.join("_C.data"), rows, cols);
    write_vector(&dir.join("_z.data"), z_len);
    dir
}

#[test]
fn compiler_001_compile_is_deterministic_on_reference_case() {
    let c1 = compile_from_dir(&case_dir()).expect("compile should succeed");
    let c2 = compile_from_dir(&case_dir()).expect("compile should succeed");

    assert_eq!(c1.rows, c2.rows);
    assert_eq!(c1.cols, c2.cols);
    assert_eq!(c1.case_digest, c2.case_digest);
    assert_eq!(c1.context_fingerprint, c2.context_fingerprint);
}

#[test]
fn compiler_002_compile_rejects_non_power_of_two_rows() {
    let dir = build_case(3, 8, 8);
    let err = compile_from_dir(&dir).expect_err("compile should reject non-power-of-two rows");
    assert!(err.to_string().contains("powers of two"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn compiler_003_compile_rejects_witness_length_mismatch() {
    let dir = build_case(4, 8, 7);
    let err = compile_from_dir(&dir).expect_err("compile should reject witness length mismatch");
    assert!(
        err.to_string()
            .contains("z length must match matrix column count")
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn compiler_004_context_fingerprint_changes_with_profile() {
    let m61 = parse_field_profile("m61").expect("m61 profile should parse");
    let gold = parse_field_profile("gold").expect("gold profile should parse");

    let c_m61 =
        compile_from_dir_with_profile(&case_dir(), m61).expect("m61 compile should succeed");
    let c_gold =
        compile_from_dir_with_profile(&case_dir(), gold).expect("gold compile should succeed");

    assert_ne!(c_m61.context_fingerprint, c_gold.context_fingerprint);
}

#[test]
fn compiler_005_prove_rejects_invalid_case_shape_early() {
    let dir = build_case(3, 8, 8);
    let err = prove_from_dir(&dir).expect_err("prove should reject invalid shape");
    assert!(err.to_string().contains("powers of two"));
    let _ = fs::remove_dir_all(dir);
}
