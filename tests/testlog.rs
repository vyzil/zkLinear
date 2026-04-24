use std::{
    panic::{catch_unwind, resume_unwind, AssertUnwindSafe},
    time::Instant,
};

fn env_on(name: &str) -> bool {
    std::env::var(name).as_deref() == Ok("1")
}

pub fn enabled() -> bool {
    env_on("TEST_LOG")
}

pub fn data_enabled() -> bool {
    enabled() || env_on("TEST_LOG_DATA")
}

pub fn run_case<F>(id: &str, summary: &str, io: &str, settings: &str, f: F)
where
    F: FnOnce(),
{
    let start = Instant::now();
    if enabled() {
        eprintln!("[TEST][{}] START", id);
        eprintln!("  summary: {}", summary);
        eprintln!("  io: {}", io);
        eprintln!("  settings: {}", settings);
    }

    let result = catch_unwind(AssertUnwindSafe(f));
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

    match result {
        Ok(()) => {
            if enabled() {
                eprintln!("[TEST][{}] PASS elapsed_ms={:.3}", id, elapsed_ms);
            }
        }
        Err(payload) => {
            if enabled() {
                eprintln!("[TEST][{}] FAIL elapsed_ms={:.3}", id, elapsed_ms);
            }
            resume_unwind(payload);
        }
    }
}

pub fn data(label: &str, value: impl std::fmt::Display) {
    if data_enabled() {
        eprintln!("  data: {}={}", label, value);
    }
}
