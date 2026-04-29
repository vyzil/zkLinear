use std::path::PathBuf;

use zk_linear::{
    io::reference_compat::{
        decode_reference_compat_proof, decode_reference_compat_public,
        encode_reference_compat_proof, encode_reference_compat_public, REFERENCE_COMPAT_FORMAT,
    },
    nizk::spartan_brakedown::{prove, verify_public},
};

#[path = "testlog.rs"]
mod testlog;

macro_rules! run_instance {
    ($id:expr, $summary:expr, $io:expr, $settings:expr, $body:block) => {{
        testlog::run_instance($id, $summary, $io, $settings, || $body)
    }};
}

fn instance_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/inner_sumcheck_spartan")
}

#[test]
fn refcompat_001_roundtrip_proof_public_verify_succeeds() {
    run_instance!(
        "refcompat_001",
        "reference_compat proof/public roundtrip stays verifiable",
        "input: pipeline proof/public",
        "codec=reference_compat_v1",
        {
            let result = prove(&instance_dir()).expect("prove should succeed");
            let rc_pf = encode_reference_compat_proof(&result.proof);
            let rc_pub = encode_reference_compat_public(&result.public);
            testlog::data("proof_format", &rc_pf.format);
            testlog::data("public_format", &rc_pub.format);
            let proof2 = decode_reference_compat_proof(&rc_pf).expect("decode proof");
            let public2 = decode_reference_compat_public(&rc_pub).expect("decode public");
            verify_public(&proof2, &public2).expect("verify should succeed after roundtrip");
        }
    );
}

#[test]
fn refcompat_002_malformed_payloads_are_rejected() {
    run_instance!(
        "refcompat_002",
        "reference_compat rejects malformed format and payloads",
        "input: tampered reference_compat artifacts",
        "expect=rejection",
        {
            let result = prove(&instance_dir()).expect("prove should succeed");
            let mut rc_pf = encode_reference_compat_proof(&result.proof);
            let mut rc_pub = encode_reference_compat_public(&result.public);
            testlog::data("baseline_format", &rc_pf.format);

            rc_pf.format = "bad_format".to_string();
            let err = decode_reference_compat_proof(&rc_pf).expect_err("bad format must fail");
            assert!(err.to_string().contains("format mismatch"));

            let mut rc_pf = encode_reference_compat_proof(&result.proof);
            rc_pf.verifier_commitment_hex.push('0');
            let err = decode_reference_compat_proof(&rc_pf)
                .expect_err("malformed verifier commitment payload must fail");
            assert!(
                err.to_string().contains("bad verifier commitment hex")
                    || err.to_string().contains("wrong verifier commitment tag")
                    || err.to_string().contains("trailing bytes")
            );

            rc_pub.format = "bad_format".to_string();
            let err = decode_reference_compat_public(&rc_pub).expect_err("bad format must fail");
            assert!(err.to_string().contains("format mismatch"));

            let mut rc_pub = encode_reference_compat_public(&result.public);
            rc_pub.field_profile = "not_a_profile".to_string();
            let err =
                decode_reference_compat_public(&rc_pub).expect_err("bad field profile should fail");
            assert!(err.to_string().contains("bad field profile"));

            let mut rc_pub = encode_reference_compat_public(&result.public);
            rc_pub.instance_digest_hex = "aa".to_string();
            let err =
                decode_reference_compat_public(&rc_pub).expect_err("bad digest width should fail");
            assert!(err.to_string().contains("digest must be 32 bytes"));

            assert_eq!(REFERENCE_COMPAT_FORMAT, "reference_compat_v1");
        }
    );
}
