use std::path::Path;

use zk_linear::api::inner_sumcheck::build_inner_sumcheck_report_from_dir;

#[test]
fn inner_sumcheck_naive_main_like() {
  let case_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/inner_sumcheck_naive");

  let report =
    build_inner_sumcheck_report_from_dir(&case_dir).expect("failed to build inner_sumcheck_naive report");

  // main-like output
  println!("{}", report);

  // sanity check for CI
  assert!(report.contains("Expected A*y (direct):"));
  assert!(report.contains("round 0 ->"));
  assert!(report.contains("final check:"));
}
