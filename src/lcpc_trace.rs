use anyhow::Result;

use crate::pcs::brakedown::demo::run_brakedown_trace;

// Backward-compatible entrypoint kept for callers using the old module path.
pub fn run_lcpc_brakedown_trace() -> Result<()> {
  run_brakedown_trace()
}
