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

/// Holds the lock and puts the variables back the way they were when dropped.
pub struct EnvGuard {
    saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
    _lock: MutexGuard<'static, ()>,
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (name, value) in &self.saved {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

fn redirect(names: [&'static str; 2], dir: &std::path::Path) -> EnvGuard {
    let lock = lock();
    let saved = names.iter().map(|n| (*n, std::env::var_os(n))).collect();
    for name in names {
        std::env::set_var(name, dir);
    }
    EnvGuard { saved, _lock: lock }
}

/// Points the data directory at a temporary place, on either system.
///
/// The returned guard must stay alive for the whole test.
pub fn isolated_data_dir(dir: &std::path::Path) -> EnvGuard {
    redirect(["XDG_DATA_HOME", "LOCALAPPDATA"], dir)
}

/// Points the configuration directory at a temporary place, on either system.
pub fn isolated_config_dir(dir: &std::path::Path) -> EnvGuard {
    redirect(["XDG_CONFIG_HOME", "APPDATA"], dir)
}
