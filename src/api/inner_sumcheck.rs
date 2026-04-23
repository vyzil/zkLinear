use std::path::Path;

use anyhow::Result;

use crate::{
    io::case_format::load_matrix_vector_case_from_dir,
    spartan::{format_matrix_vector_inner_sumcheck_report, prove_matrix_vector_inner_sumcheck},
};

pub fn build_inner_sumcheck_report_from_dir(case_dir: &Path) -> Result<String> {
    let case = load_matrix_vector_case_from_dir(case_dir)?;
    let report = prove_matrix_vector_inner_sumcheck(&case.a, &case.y);
    Ok(format_matrix_vector_inner_sumcheck_report(&report))
}
