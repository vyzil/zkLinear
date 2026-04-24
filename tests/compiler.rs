use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use zk_linear::nizk::spartan_brakedown::{
    compile_from_dir, compile_from_dir_with_profile, parse_field_profile, prove_from_dir,
};
#[path = "testlog.rs"]
mod testlog;

macro_rules! run_case {
    ($id:expr, $summary:expr, $io:expr, $settings:expr, $body:block) => {{
        testlog::run_case($id, $summary, $io, $settings, || $body)
    }};
}

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
    run_case!(
        "compiler_001",
        "compile determinism on reference case",
        "input: case dir, output: compiled metadata",
        "profile=default",
        {
            let c1 = compile_from_dir(&case_dir()).expect("compile should succeed");
            let c2 = compile_from_dir(&case_dir()).expect("compile should succeed");

            testlog::data("rows", c1.rows);
            testlog::data("cols", c1.cols);
            testlog::data("digest_head", hex::encode(&c1.case_digest[..4]));

            assert_eq!(c1.rows, c2.rows);
            assert_eq!(c1.cols, c2.cols);
            assert_eq!(c1.case_digest, c2.case_digest);
            assert_eq!(c1.context_fingerprint, c2.context_fingerprint);
        }
    );
}

#[test]
fn compiler_002_compile_rejects_non_power_of_two_rows() {
    run_case!(
        "compiler_002",
        "invalid shape guard for rows",
        "input: synthetic bad case rows=3",
        "expect_error=shape_power_of_two",
        {
            let dir = build_case(3, 8, 8);
            let err = compile_from_dir(&dir).expect_err("compile should reject non-power-of-two rows");
            testlog::data("error", &err);
            assert!(err.to_string().contains("powers of two"));
            let _ = fs::remove_dir_all(dir);
        }
    );
}

#[test]
fn compiler_003_compile_rejects_witness_length_mismatch() {
    run_case!(
        "compiler_003",
        "witness length mismatch guard",
        "input: synthetic bad case z_len=7 with cols=8",
        "expect_error=z_length_mismatch",
        {
            let dir = build_case(4, 8, 7);
            let err =
                compile_from_dir(&dir).expect_err("compile should reject witness length mismatch");
            testlog::data("error", &err);
            assert!(
                err.to_string()
                    .contains("z length must match matrix column count")
            );
            let _ = fs::remove_dir_all(dir);
        }
    );
}

#[test]
fn compiler_004_context_fingerprint_changes_with_profile() {
    run_case!(
        "compiler_004",
        "profile-sensitive context fingerprint",
        "input: same case with m61/gold profiles",
        "expect=context_fingerprint_differs",
        {
            let m61 = parse_field_profile("m61").expect("m61 profile should parse");
            let gold = parse_field_profile("gold").expect("gold profile should parse");

            let c_m61 =
                compile_from_dir_with_profile(&case_dir(), m61).expect("m61 compile should succeed");
            let c_gold =
                compile_from_dir_with_profile(&case_dir(), gold).expect("gold compile should succeed");
            testlog::data("m61_ctx_head", hex::encode(&c_m61.context_fingerprint[..4]));
            testlog::data("gold_ctx_head", hex::encode(&c_gold.context_fingerprint[..4]));

            assert_ne!(c_m61.context_fingerprint, c_gold.context_fingerprint);
        }
    );
}

#[test]
fn compiler_005_prove_rejects_invalid_case_shape_early() {
    run_case!(
        "compiler_005",
        "prove path rejects invalid shape before proving",
        "input: synthetic bad case rows=3",
        "expect_error=shape_power_of_two",
        {
            let dir = build_case(3, 8, 8);
            let err = prove_from_dir(&dir).expect_err("prove should reject invalid shape");
            testlog::data("error", &err);
            assert!(err.to_string().contains("powers of two"));
            let _ = fs::remove_dir_all(dir);
        }
    );
}
