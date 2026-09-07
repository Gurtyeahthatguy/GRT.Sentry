//! Test-only lock for the tests that change environment variables.
//!
//! Environment variables belong to the whole process and the harness runs
//! tests in parallel, so two tests redirecting `XDG_DATA_HOME` at once would
//! race. Every test that touches the environment holds this while it does.

use std::sync::{Mutex, MutexGuard, OnceLock};

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Held for as long as a test needs the environment to itself.
pub fn lock() -> MutexGuard<'static, ()> {
    // A panicking test poisons the mutex; the next one still wants the lock.
    match ENV_LOCK.get_or_init(|| Mutex::new(())).lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Points the data directory at a temporary place, on either system.
///
/// The returned lock must stay alive for the whole test.
pub fn isolated_data_dir(dir: &std::path::Path) -> MutexGuard<'static, ()> {
    let guard = lock();
    std::env::set_var("XDG_DATA_HOME", dir);
    std::env::set_var("LOCALAPPDATA", dir);
    guard
}
