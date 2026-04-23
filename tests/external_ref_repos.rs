use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RefRepoRevisions {
    spartan2: String,
    lcpc: String,
    zkmetal: String,
}

fn ref_root() -> PathBuf {
    if let Ok(v) = std::env::var("ZKLINEAR_REF_ROOT") {
        return PathBuf::from(v);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("manifest dir has parent")
        .join("ref")
}

fn snapshot_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/reference_vectors/external/ref_repo_revisions.json")
}

fn repo_dir(root: &Path, name: &str) -> PathBuf {
    root.join(name)
}

fn git_rev_parse_head(repo: &Path) -> Option<String> {
    if !repo.exists() {
        return None;
    }
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn build_revisions(root: &Path) -> Option<RefRepoRevisions> {
    Some(RefRepoRevisions {
        spartan2: git_rev_parse_head(&repo_dir(root, "Spartan2"))?,
        lcpc: git_rev_parse_head(&repo_dir(root, "lcpc"))?,
        zkmetal: git_rev_parse_head(&repo_dir(root, "zkMetal"))?,
    })
}

fn run_cmd_in(dir: &Path, args: &[&str]) {
    let out = Command::new(args[0])
        .args(&args[1..])
        .current_dir(dir)
        .output()
        .expect("spawn external command");
    if !out.status.success() {
        panic!(
            "command failed in {}: {:?}\nstdout:\n{}\nstderr:\n{}",
            dir.display(),
            args,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn external_ref_repo_revisions_match_snapshot() {
    let root = ref_root();
    let Some(snapshot) = build_revisions(&root) else {
        eprintln!(
            "ref repos missing under {}; set ZKLINEAR_REF_ROOT if needed",
            root.display()
        );
        return;
    };
    let path = snapshot_file();

    if std::env::var("ZKLINEAR_UPDATE_EXTERNAL_REFS").as_deref() == Ok("1") {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create external ref vector dir");
        }
        let body = serde_json::to_string_pretty(&snapshot).expect("serialize revisions");
        fs::write(&path, body).expect("write external revisions snapshot");
        return;
    }

    let body = fs::read_to_string(&path).expect(
        "external revisions snapshot missing; set ZKLINEAR_UPDATE_EXTERNAL_REFS=1 and rerun once",
    );
    let expected: RefRepoRevisions = serde_json::from_str(&body).expect("parse revisions snapshot");

    assert_eq!(
        snapshot, expected,
        "external ref repo revisions changed; if intentional, update with ZKLINEAR_UPDATE_EXTERNAL_REFS=1",
    );
}

#[test]
#[ignore = "runs external ref repo tests; opt-in validation only"]
fn external_ref_spartan2_setting_smoke_passes() {
    let root = ref_root();
    let spartan2 = repo_dir(&root, "Spartan2");
    if !spartan2.exists() {
        eprintln!("Spartan2 ref repo not found at {}", spartan2.display());
        return;
    }
    run_cmd_in(&spartan2, &["cargo", "test", "-q", "--test", "setting_smoke"]);
}

#[test]
#[ignore = "runs external ref repo tests; opt-in validation only"]
fn external_ref_lcpc_brakedown_col_opens_passes() {
    let root = ref_root();
    let lcpc = repo_dir(&root, "lcpc");
    if !lcpc.exists() {
        eprintln!("lcpc ref repo not found at {}", lcpc.display());
        return;
    }
    run_cmd_in(
        &lcpc,
        &["cargo", "test", "-q", "-p", "lcpc-brakedown-pc", "--lib", "col_opens"],
    );
}
