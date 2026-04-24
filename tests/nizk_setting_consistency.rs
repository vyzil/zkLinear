use std::path::PathBuf;

use zk_linear::nizk::spartan_brakedown::{
    compile_from_dir_with_profile, parse_field_profile, prove_from_dir, prove_from_dir_with_profile,
    verify_public, NIZK_BLINDED_LAYOUT_ROWS,
};

fn case_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/inner_sumcheck_spartan")
}

#[test]
fn nizk_blinded_layout_row_count_is_fixed_and_enforced() {
    let result = prove_from_dir(&case_dir()).expect("prove should succeed");
    assert_eq!(
        result.proof.verifier_commitment.n_rows,
        NIZK_BLINDED_LAYOUT_ROWS,
        "proof commitment row count should match fixed NIZK blinded layout"
    );
    verify_public(&result.proof, &result.public).expect("verify should succeed");
}

#[test]
fn context_fingerprint_is_stable_across_proof_randomness() {
    let r1 = prove_from_dir(&case_dir()).expect("first prove should succeed");
    let r2 = prove_from_dir(&case_dir()).expect("second prove should succeed");

    assert_eq!(
        r1.proof_meta.context_fingerprint, r2.proof_meta.context_fingerprint,
        "proof context fingerprint should be deterministic for same case/profile"
    );
    assert_eq!(
        r1.public_meta.context_fingerprint, r2.public_meta.context_fingerprint,
        "public context fingerprint should be deterministic for same case/profile"
    );
}

#[test]
fn context_fingerprint_changes_when_profile_changes() {
    let m61 = parse_field_profile("m61").expect("m61 profile should parse");
    let gold = parse_field_profile("gold").expect("gold profile should parse");
    let c_m61 = compile_from_dir_with_profile(&case_dir(), m61).expect("m61 compile should succeed");
    let c_gold =
        compile_from_dir_with_profile(&case_dir(), gold).expect("gold compile should succeed");

    assert_ne!(
        c_m61.context_fingerprint, c_gold.context_fingerprint,
        "context fingerprint should change across field profiles"
    );
}

#[test]
fn prove_public_fingerprint_matches_compiled_profile_choice() {
    let m61 = parse_field_profile("m61").expect("m61 profile should parse");
    let compiled =
        compile_from_dir_with_profile(&case_dir(), m61).expect("compiled should succeed");
    let proved =
        prove_from_dir_with_profile(&case_dir(), m61).expect("prove_with_profile should succeed");

    assert_eq!(
        compiled.context_fingerprint, proved.proof_meta.context_fingerprint,
        "proof fingerprint should match compiled fingerprint for same profile/case"
    );
    assert_eq!(
        compiled.context_fingerprint, proved.public_meta.context_fingerprint,
        "public fingerprint should match compiled fingerprint for same profile/case"
    );
}
