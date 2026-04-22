use std::path::Path;

use zk_linear::api::spartan_like::build_spartan_like_report_from_dir;

#[test]
fn inner_sumcheck_spartan_main_style() {
  let case_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/inner_sumcheck_spartan");
  let report = build_spartan_like_report_from_dir(&case_dir)
    .expect("failed to build spartan-like report");

  println!("{}", report);

  assert!(report.contains("Spartan-like R1CS Sumcheck Report"));
  assert!(report.contains("[Info]"));
  assert!(report.contains("[Claim]"));
  assert!(report.contains("[Outer Prove]"));
  assert!(report.contains("[Inner Prove: Spartan-like JOINT path]"));
  assert!(report.contains("[Proof Payload]"));
  assert!(report.contains("[Verify]"));
  assert!(report.contains("[Compare: Separate A/B/C Inner Paths]"));
}
