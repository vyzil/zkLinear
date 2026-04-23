use std::{fs, path::PathBuf};

use zk_linear::parity::{
    lcpc_like::{
        build_local_lcpc_like_snapshot, LcpcLikeMustMatchView, LcpcLikeParitySnapshot,
    },
    reference::{build_local_parity_snapshot, MustMatchParityView, ParitySnapshot},
};

fn case_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/inner_sumcheck_spartan")
}

fn external_spartan2_ref() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/reference_vectors/external/spartan2_case_01.json")
}

fn external_lcpc_like_ref() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/reference_vectors/external/lcpc_like_case_01.json")
}

fn load_view(path: &PathBuf) -> MustMatchParityView {
    let body = fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("missing external spartan2 snapshot: {}", path.display()));
    let snap: ParitySnapshot = serde_json::from_str(&body)
        .unwrap_or_else(|_| panic!("bad external spartan2 snapshot json: {}", path.display()));
    snap.must_match_view()
}

fn load_lcpc_like_view(path: &PathBuf) -> LcpcLikeMustMatchView {
    let body = fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("missing external lcpc-like snapshot: {}", path.display()));
    let snap: LcpcLikeParitySnapshot = serde_json::from_str(&body)
        .unwrap_or_else(|_| panic!("bad external lcpc-like snapshot json: {}", path.display()));
    snap.must_match_view()
}

#[test]
fn parity_must_match_with_external_snapshots() {
    let local = build_local_parity_snapshot(&case_dir())
        .expect("local parity snapshot should build")
        .must_match_view();
    let local_lcpc = build_local_lcpc_like_snapshot(&case_dir())
        .expect("local lcpc-like parity snapshot should build")
        .must_match_view();

    let spartan2 = load_view(&external_spartan2_ref());
    let lcpc_like = load_lcpc_like_view(&external_lcpc_like_ref());

    assert_eq!(
        local, spartan2,
        "must-match parity mismatch against external Spartan2 snapshot"
    );
    assert_eq!(
        local_lcpc.n_per_row, lcpc_like.n_per_row,
        "lcpc-like n_per_row mismatch against external snapshot"
    );
    assert_eq!(
        local_lcpc.n_cols, lcpc_like.n_cols,
        "lcpc-like n_cols mismatch against external snapshot"
    );
    assert_eq!(
        local_lcpc.n_degree_tests, lcpc_like.n_degree_tests,
        "lcpc-like n_degree_tests mismatch against external snapshot"
    );
    assert_eq!(
        local_lcpc.n_col_opens, lcpc_like.n_col_opens,
        "lcpc-like n_col_opens mismatch against external snapshot"
    );
    assert_eq!(
        local_lcpc.opened_cols, lcpc_like.opened_cols,
        "lcpc-like opened_cols mismatch against external snapshot"
    );
    assert_eq!(
        local_lcpc.p_eval_len, lcpc_like.p_eval_len,
        "lcpc-like p_eval_len mismatch against external snapshot"
    );
    assert_eq!(
        local_lcpc.p_random_count, lcpc_like.p_random_count,
        "lcpc-like p_random_count mismatch against external snapshot"
    );
}
