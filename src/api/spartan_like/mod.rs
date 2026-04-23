use std::path::Path;

use anyhow::Result;

mod data;
mod report;

pub use data::{
    build_spartan_like_report_data_from_dir, build_spartan_like_report_data_from_dir_with_modulus,
    SpartanLikeReportData,
};
pub use report::format_spartan_like_report;

pub fn build_spartan_like_report_from_dir(case_dir: &Path) -> Result<String> {
    let data = build_spartan_like_report_data_from_dir(case_dir)?;
    Ok(format_spartan_like_report(&data))
}
