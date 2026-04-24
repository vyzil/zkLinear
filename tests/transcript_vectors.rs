use std::{fs, path::PathBuf};

use serde::{Deserialize, Serialize};
use zk_linear::{
    bridge::prove_bridge_from_dir,
    nizk::spartan_brakedown::prove_from_dir,
    protocol::spec_v1::{
        BRIDGE_TRANSCRIPT_LABEL, INNER_SUMCHECK_JOINT_LABEL, NIZK_TRANSCRIPT_LABEL,
        OUTER_SUMCHECK_LABEL, TRANSCRIPT_DOMAIN,
    },
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BridgeTranscriptVector {
    spec_domain: String,
    transcript_label: String,
    outer_label: String,
    inner_label: String,
    rows: usize,
    cols: usize,
    field_profile: String,
    reference_profile: String,
    case_digest_hex: String,
    context_fingerprint_hex: String,
    gamma: u64,
    claimed_value: u64,
    outer_challenges: Vec<u64>,
    inner_challenges: Vec<u64>,
    pcs_root_hex: String,
    pcs_open_col_indices: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct NizkTranscriptVector {
    spec_domain: String,
    transcript_label: String,
    outer_label: String,
    inner_label: String,
    rows: usize,
    cols: usize,
    case_digest_hex: String,
    field_profile: String,
    reference_profile: String,
    gamma: u64,
    inner_claim_initial: u64,
    outer_challenges: Vec<u64>,
    inner_challenges: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TranscriptVectorSnapshot {
    case_id: String,
    bridge: BridgeTranscriptVector,
    nizk: NizkTranscriptVector,
}

fn case_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/inner_sumcheck_spartan")
}

fn ref_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/reference_vectors/transcript_case_01.json")
}

fn as_utf8(bytes: &'static [u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("label should be utf8")
}

fn build_snapshot() -> TranscriptVectorSnapshot {
    let bridge = prove_bridge_from_dir(&case_dir()).expect("bridge prove should succeed");
    let nizk = prove_from_dir(&case_dir()).expect("nizk prove should succeed");

    let bridge_vec = BridgeTranscriptVector {
        spec_domain: as_utf8(TRANSCRIPT_DOMAIN),
        transcript_label: as_utf8(BRIDGE_TRANSCRIPT_LABEL),
        outer_label: as_utf8(OUTER_SUMCHECK_LABEL),
        inner_label: as_utf8(INNER_SUMCHECK_JOINT_LABEL),
        rows: bridge.verifier_query.rows,
        cols: bridge.verifier_query.cols,
        field_profile: format!("{:?}", bridge.bundle.verifier_commitment.field_profile),
        reference_profile: format!("{:?}", bridge.bundle.reference_profile),
        case_digest_hex: hex::encode(bridge.bundle.public_case_digest),
        context_fingerprint_hex: hex::encode(bridge.bundle.context_fingerprint),
        gamma: bridge.bundle.gamma.0,
        claimed_value: bridge.verifier_query.claimed_value.0,
        outer_challenges: bridge
            .bundle
            .outer_trace
            .rounds
            .iter()
            .map(|r| r.challenge_r.0)
            .collect(),
        inner_challenges: bridge
            .bundle
            .inner_trace
            .rounds
            .iter()
            .map(|r| r.challenge_r.0)
            .collect(),
        pcs_root_hex: hex::encode(bridge.bundle.verifier_commitment.root),
        pcs_open_col_indices: bridge
            .bundle
            .pcs_opening_proof
            .columns
            .iter()
            .map(|c| c.col_idx)
            .collect(),
    };

    let nizk_vec = NizkTranscriptVector {
        spec_domain: as_utf8(TRANSCRIPT_DOMAIN),
        transcript_label: as_utf8(NIZK_TRANSCRIPT_LABEL),
        outer_label: as_utf8(OUTER_SUMCHECK_LABEL),
        inner_label: as_utf8(INNER_SUMCHECK_JOINT_LABEL),
        rows: nizk.public.rows,
        cols: nizk.public.cols,
        case_digest_hex: hex::encode(nizk.public.case_digest),
        field_profile: format!("{:?}", nizk.public.field_profile),
        reference_profile: format!("{:?}", nizk.proof_meta.reference_profile),
        gamma: nizk.proof.gamma.0,
        inner_claim_initial: nizk.proof.inner_trace.claim_initial.0,
        outer_challenges: nizk
            .proof
            .outer_trace
            .rounds
            .iter()
            .map(|r| r.challenge_r.0)
            .collect(),
        inner_challenges: nizk
            .proof
            .inner_trace
            .rounds
            .iter()
            .map(|r| r.challenge_r.0)
            .collect(),
    };

    TranscriptVectorSnapshot {
        case_id: "inner_sumcheck_spartan".to_string(),
        bridge: bridge_vec,
        nizk: nizk_vec,
    }
}

#[test]
fn transcript_vectors_match_reference_snapshot() {
    let snapshot = build_snapshot();
    let path = ref_file();

    if std::env::var("ZKLINEAR_UPDATE_TRANSCRIPT_REF").as_deref() == Ok("1") {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create transcript ref vector dir");
        }
        let body = serde_json::to_string_pretty(&snapshot).expect("serialize transcript snapshot");
        fs::write(&path, body).expect("write transcript snapshot file");
        return;
    }

    let body = fs::read_to_string(&path).expect(
        "transcript reference vector missing; set ZKLINEAR_UPDATE_TRANSCRIPT_REF=1 and rerun this test once",
    );
    let expected: TranscriptVectorSnapshot =
        serde_json::from_str(&body).expect("parse transcript snapshot json");

    assert_eq!(
        snapshot, expected,
        "transcript snapshot mismatch; if intentional, regenerate with ZKLINEAR_UPDATE_TRANSCRIPT_REF=1",
    );
}
