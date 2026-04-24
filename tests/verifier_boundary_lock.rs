use std::{fs, path::PathBuf};

fn repo_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

#[test]
fn spark_cli_verify_path_is_compiled_public_only() {
    let cli_src = fs::read_to_string(repo_path("src/bin/spark_e2e_cli.rs"))
        .expect("failed to read spark_e2e_cli.rs");

    assert!(
        cli_src.contains("verify_with_compiled("),
        "spark_e2e_cli verify path must use verify_with_compiled"
    );
    assert!(
        !cli_src.contains("verify_from_dir_strict("),
        "strict replay verifier must stay out of benchmark/user CLI verify path"
    );
    assert!(
        !cli_src.contains("verify_from_dir("),
        "dir replay verifier must stay out of benchmark/user CLI verify path"
    );
}

#[test]
fn e2e_script_uses_cli_verify_only() {
    let script = fs::read_to_string(repo_path("scripts/run_e2e_with_cache_flush.sh"))
        .expect("failed to read run_e2e_with_cache_flush.sh");

    assert!(
        script.contains("\"${CLI}\" verify"),
        "e2e script must verify through succinct CLI path"
    );
    assert!(
        !script.contains("verify_from_dir"),
        "e2e script must not call replay verifier directly"
    );
}
