use anyhow::Result;
use zk_linear::{lcpc_trace, spartan};

fn main() -> Result<()> {
    spartan::demo_matrix_vector_trace();
    lcpc_trace::run_lcpc_brakedown_trace()?;
    Ok(())
}
