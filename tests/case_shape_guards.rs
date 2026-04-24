use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use zk_linear::{
    bridge::prove_bridge_from_dir,
    nizk::spartan_brakedown::{compile_from_dir, prove_from_dir},
};

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
    let dir = unique_tmp_dir("zklinear_bad_case");
    fs::create_dir_all(&dir).expect("create tmp case dir");
    write_matrix(&dir.join("_A.data"), rows, cols);
    write_matrix(&dir.join("_B.data"), rows, cols);
    write_matrix(&dir.join("_C.data"), rows, cols);
    write_vector(&dir.join("_z.data"), z_len);
    dir
}

#[test]
fn compile_rejects_non_power_of_two_rows() {
    let dir = build_case(3, 8, 8);
    let err = compile_from_dir(&dir).expect_err("compile should reject non-power-of-two rows");
    assert!(err.to_string().contains("powers of two"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn prove_rejects_non_power_of_two_rows() {
    let dir = build_case(3, 8, 8);
    let err = prove_from_dir(&dir).expect_err("prove should reject non-power-of-two rows");
    assert!(err.to_string().contains("powers of two"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn bridge_rejects_non_power_of_two_rows() {
    let dir = build_case(3, 8, 8);
    let err = prove_bridge_from_dir(&dir).expect_err("bridge should reject non-power-of-two rows");
    assert!(err.to_string().contains("power-of-two"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn compile_rejects_z_length_mismatch() {
    let dir = build_case(4, 8, 7);
    let err = compile_from_dir(&dir).expect_err("compile should reject z length mismatch");
    assert!(err.to_string().contains("z length"));
    let _ = fs::remove_dir_all(dir);
}
