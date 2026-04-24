use std::path::PathBuf;

use anyhow::{anyhow, Result};
use zk_linear::nizk::spartan_brakedown::{
    build_pipeline_report_from_dir_with_profile, parse_field_profile,
};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let profile_s = args.next().unwrap_or_else(|| "m61".to_string());
    let case_dir = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("tests/inner_sumcheck_spartan"));

    let profile = parse_field_profile(&profile_s).ok_or_else(|| {
        anyhow!(
            "unknown profile '{}'; use one of: toy | m61 | gold",
            profile_s
        )
    })?;

    let report = build_pipeline_report_from_dir_with_profile(&case_dir, profile)?;
    println!("{}", report);
    Ok(())
}
