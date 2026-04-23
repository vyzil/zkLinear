use std::path::PathBuf;

use zk_linear::nizk::spartan_brakedown::{
    compile_from_dir, prove_with_compiled_from_dir, verify_with_compiled,
};

fn case_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/inner_sumcheck_spartan")
}

#[test]
fn compiled_flow_succeeds() {
    let compiled = compile_from_dir(&case_dir()).expect("compile should succeed");
    let result = prove_with_compiled_from_dir(&compiled, &case_dir())
        .expect("prove with compiled should succeed");
    verify_with_compiled(&compiled, &result.proof, &result.public)
        .expect("verify with compiled should succeed");
}

#[test]
fn compiled_flow_fails_on_digest_mismatch_at_prove_boundary() {
    let mut compiled = compile_from_dir(&case_dir()).expect("compile should succeed");
    compiled.case_digest[0] ^= 1;

    let err = prove_with_compiled_from_dir(&compiled, &case_dir())
        .expect_err("prove should fail with wrong compiled digest");
    assert!(
        err.to_string().contains("digest mismatch"),
        "unexpected error: {}",
        err
    );
}

#[test]
fn compiled_flow_fails_on_digest_mismatch_at_verify_boundary() {
    let compiled = compile_from_dir(&case_dir()).expect("compile should succeed");
    let mut result = prove_with_compiled_from_dir(&compiled, &case_dir())
        .expect("prove with compiled should succeed");
    result.public.case_digest[0] ^= 1;

    let err = verify_with_compiled(&compiled, &result.proof, &result.public)
        .expect_err("verify should fail with public digest mismatch");
    assert!(
        err.to_string().contains("digest mismatch"),
        "unexpected error: {}",
        err
    );
}

