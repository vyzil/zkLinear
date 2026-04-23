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

fn try_load_view(path: &PathBuf) -> Option<MustMatchParityView> {
    if !path.exists() {
        return None;
    }
    let body = fs::read_to_string(path).ok()?;
    let snap: ParitySnapshot = serde_json::from_str(&body).ok()?;
    Some(snap.must_match_view())
}

fn try_load_lcpc_like_view(path: &PathBuf) -> Option<LcpcLikeMustMatchView> {
    if !path.exists() {
        return None;
    }
    let body = fs::read_to_string(path).ok()?;
    let snap: LcpcLikeParitySnapshot = serde_json::from_str(&body).ok()?;
    Some(snap.must_match_view())
}

#[test]
fn parity_must_match_with_external_snapshots_if_present() {
    let local = build_local_parity_snapshot(&case_dir())
        .expect("local parity snapshot should build")
        .must_match_view();
    let local_lcpc = build_local_lcpc_like_snapshot(&case_dir())
        .expect("local lcpc-like parity snapshot should build")
        .must_match_view();

    let spartan2 = try_load_view(&external_spartan2_ref());
    let lcpc_like = try_load_lcpc_like_view(&external_lcpc_like_ref());

    if spartan2.is_none() && lcpc_like.is_none() {
        eprintln!(
            "external parity snapshots not found; expected files:\n  - {}\n  - {}",
            external_spartan2_ref().display(),
            external_lcpc_like_ref().display()
        );
        return;
    }

    if let Some(v) = spartan2 {
        assert_eq!(
            local, v,
            "must-match parity mismatch against external Spartan2 snapshot"
        );
    }
    if let Some(v) = lcpc_like {
        assert_eq!(
            local_lcpc, v,
            "must-match parity mismatch against external lcpc-like snapshot"
        );
    }
}
