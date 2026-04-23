use std::{fs, path::PathBuf};

use zk_linear::parity::lcpc_like::{build_local_lcpc_like_snapshot, LcpcLikeParitySnapshot};

fn case_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/inner_sumcheck_spartan")
}

fn ref_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/reference_vectors/lcpc_like_case_01.json")
}

#[test]
fn lcpc_like_parity_with_reference_snapshot() {
    let snapshot =
        build_local_lcpc_like_snapshot(&case_dir()).expect("lcpc-like snapshot build should succeed");
    let path = ref_file();

    if std::env::var("ZKLINEAR_UPDATE_LCPC_LIKE_REF").as_deref() == Ok("1") {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create ref vector dir");
        }
        let body = serde_json::to_string_pretty(&snapshot).expect("serialize snapshot");
        fs::write(&path, body).expect("write snapshot file");
        return;
    }

    let body = fs::read_to_string(&path).expect(
        "reference vector missing; set ZKLINEAR_UPDATE_LCPC_LIKE_REF=1 and rerun this test once",
    );
    let expected: LcpcLikeParitySnapshot =
        serde_json::from_str(&body).expect("parse reference snapshot json");

    let got = snapshot.must_match_view();
    let exp = expected.must_match_view();
    assert_eq!(
        got.n_per_row, exp.n_per_row,
        "lcpc-like parity n_per_row mismatch"
    );
    assert_eq!(got.n_cols, exp.n_cols, "lcpc-like parity n_cols mismatch");
    assert_eq!(
        got.n_degree_tests, exp.n_degree_tests,
        "lcpc-like parity n_degree_tests mismatch"
    );
    assert_eq!(
        got.n_col_opens, exp.n_col_opens,
        "lcpc-like parity n_col_opens mismatch"
    );
    assert_eq!(
        got.opened_cols, exp.opened_cols,
        "lcpc-like parity opened_cols mismatch"
    );
    assert_eq!(
        got.p_eval_len, exp.p_eval_len,
        "lcpc-like parity p_eval_len mismatch"
    );
    assert_eq!(
        got.p_random_count, exp.p_random_count,
        "lcpc-like parity p_random_count mismatch"
    );
}
