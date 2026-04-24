use std::path::PathBuf;

use merlin::Transcript;
use zk_linear::{
    api::spartan_like::build_spartan_like_report_data_from_dir,
    core::{
        field::{Fp, ModulusScope, MODULUS},
        transcript::{derive_round_challenge, derive_round_challenge_merlin},
    },
    protocol::{
        reference::{append_reference_profile_to_transcript, DUAL_REFERENCE_PROFILE},
        spec_v1::{append_spec_domain, BRIDGE_TRANSCRIPT_LABEL, OUTER_SUMCHECK_LABEL},
    },
    sumcheck::{
        inner::{inner_product, prove_inner_sumcheck, verify_inner_sumcheck_trace},
        outer::{prove_outer_sumcheck, verify_outer_sumcheck_trace},
    },
};
#[path = "testlog.rs"]
mod testlog;

macro_rules! run_case {
    ($id:expr, $summary:expr, $io:expr, $settings:expr, $body:block) => {{
        testlog::run_case($id, $summary, $io, $settings, || $body)
    }};
}

fn case_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/inner_sumcheck_spartan")
}

#[test]
fn spartan2_001_outer_sumcheck_round_trip_is_consistent() {
    run_case!(
        "spartan2_001",
        "outer sumcheck prove/verify round-trip",
        "input: values Vec<Fp>(len=8), output: outer trace + verify trace",
        "field=Fp(current modulus)",
        {
            let values: Vec<Fp> = (0..8).map(|i| Fp::new((i as u64) + 1)).collect();
            let trace = prove_outer_sumcheck(&values);
            let verify = verify_outer_sumcheck_trace(&trace);

            testlog::data("outer_rounds", trace.rounds.len());
            testlog::data("final_claim", trace.final_claim.0);

            assert_eq!(trace.rounds.len(), 3);
            assert!(verify.final_consistent);
            assert_eq!(verify.final_claim_from_trace, trace.final_claim);
        }
    );
}

#[test]
fn spartan2_002_outer_sumcheck_tamper_is_detected() {
    run_case!(
        "spartan2_002",
        "outer sumcheck tamper detection",
        "input: valid trace then mutate folded_values[0]",
        "expect=verify.final_consistent=false",
        {
            let values: Vec<Fp> = (0..8).map(|i| Fp::new((i as u64) + 1)).collect();
            let mut trace = prove_outer_sumcheck(&values);
            trace.rounds[0].folded_values[0] = trace.rounds[0].folded_values[0].add(Fp::new(1));

            let verify = verify_outer_sumcheck_trace(&trace);
            assert!(!verify.final_consistent);
        }
    );
}

#[test]
fn spartan2_003_inner_sumcheck_round_trip_is_consistent() {
    run_case!(
        "spartan2_003",
        "inner sumcheck prove/verify round-trip",
        "input: f/g Vec<Fp>(len=8), output: inner trace + verify trace",
        "field=Fp(current modulus)",
        {
            let f: Vec<Fp> = (0..8).map(|i| Fp::new((i as u64) * 3 + 2)).collect();
            let g: Vec<Fp> = (0..8).map(|i| Fp::new((i as u64) * 5 + 1)).collect();

            let trace = prove_inner_sumcheck(&f, &g);
            let verify = verify_inner_sumcheck_trace(&trace);

            testlog::data("inner_rounds", trace.rounds.len());
            testlog::data("final_f", trace.final_f.0);
            testlog::data("final_g", trace.final_g.0);

            assert_eq!(trace.rounds.len(), 3);
            assert!(verify.final_consistent);
            assert_eq!(trace.claim_initial, inner_product(&f, &g));
            assert_eq!(trace.final_claim, trace.final_f.mul(trace.final_g));
        }
    );
}

#[test]
fn spartan2_004_inner_sumcheck_tamper_is_detected() {
    run_case!(
        "spartan2_004",
        "inner sumcheck tamper detection",
        "input: valid trace then mutate h_at_2",
        "expect=verify.final_consistent=false",
        {
            let f: Vec<Fp> = (0..8).map(|i| Fp::new((i as u64) * 3 + 2)).collect();
            let g: Vec<Fp> = (0..8).map(|i| Fp::new((i as u64) * 5 + 1)).collect();

            let mut trace = prove_inner_sumcheck(&f, &g);
            trace.rounds[0].h_at_2 = trace.rounds[0].h_at_2.add(Fp::new(1));

            let verify = verify_inner_sumcheck_trace(&trace);
            assert!(!verify.final_consistent);
        }
    );
}

#[test]
fn spartan2_005_full_flow_is_consistent_on_fixture() {
    run_case!(
        "spartan2_005",
        "spartan2-like full flow consistency on fixture",
        "input: tests/inner_sumcheck_spartan, output: report data with traces",
        "modulus=m61",
        {
            let _scope = ModulusScope::enter((1u64 << 61) - 1);
            let data = build_spartan_like_report_data_from_dir(&case_dir())
                .expect("spartan-like flow should build");

            testlog::data("rows", data.case.a.len());
            testlog::data("cols", data.case.a[0].len());
            testlog::data("outer_rounds", data.outer_trace.rounds.len());
            testlog::data("inner_rounds", data.joint_trace.rounds.len());

            assert!(data.outer_verify.final_consistent);
            assert!(data.joint_verify.final_consistent);
            assert_eq!(
                data.outer_trace.rounds.len(),
                data.case.a.len().trailing_zeros() as usize
            );
            assert_eq!(
                data.joint_trace.rounds.len(),
                data.case.a[0].len().trailing_zeros() as usize
            );
            assert_eq!(
                data.joint_trace.claim_initial,
                inner_product(&data.joint_bound, &data.case.z)
            );
        }
    );
}

#[test]
fn spartan2_006_transcript_challenge_vectors_are_stable() {
    run_case!(
        "spartan2_006",
        "transcript challenge vectors stay pinned",
        "input: fixed (g0,g2,g3), output: SHA/Merlin challenge scalars",
        "spec=OUTER_SUMCHECK_LABEL round=0",
        {
            let g0 = Fp::new(25);
            let g2 = Fp::new(61);
            let g3 = Fp::new(72);

            let sha_chal = derive_round_challenge(OUTER_SUMCHECK_LABEL, 0, g0, g2, g3);

            let mut tr = Transcript::new(BRIDGE_TRANSCRIPT_LABEL);
            append_spec_domain(&mut tr);
            append_reference_profile_to_transcript(&mut tr, &DUAL_REFERENCE_PROFILE);
            let merlin_chal =
                derive_round_challenge_merlin(&mut tr, OUTER_SUMCHECK_LABEL, 0, g0, g2, g3);

            testlog::data("sha_chal", sha_chal.0);
            testlog::data("merlin_chal", merlin_chal.0);

            assert_eq!(sha_chal.0, 76);
            assert_eq!(merlin_chal.0, 31);
            assert!(sha_chal.0 < MODULUS);
            assert!(merlin_chal.0 < MODULUS);
        }
    );
}
