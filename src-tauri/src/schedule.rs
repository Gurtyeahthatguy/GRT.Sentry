//! Running a scan on a schedule.
//!
//! No daemon of its own. The scheduler starts the same binary with `--scan`,
//! which works without a window and exits, so nothing is resident between
//! firings. A systemd user timer does it on Linux, a scheduled task on Windows.

pub use crate::platform::ScheduleStatus;

use crate::platform;

/// Writes the scheduler entry and turns it on.
pub fn install(frequency: &str) -> Result<(), String> {
    let frequency = match frequency.trim() {
        "" => "daily",
        other => other,
    };
    // Only the shapes the interface offers, so a typo cannot produce an entry
    // the scheduler refuses to load.
    if !["hourly", "daily", "weekly"].contains(&frequency) {
        return Err("The schedule can be hourly, daily or weekly.".to_string());
    }

    let executable = std::env::current_exe()
        .map_err(|e| format!("Cannot determine this program's own path: {e}"))?;

    platform::schedule_install(frequency, &executable)
}

pub fn remove() -> Result<(), String> {
    platform::schedule_remove()
}

pub fn status() -> ScheduleStatus {
    platform::schedule_status()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_three_offered_frequencies_are_accepted() {
        // Nothing is written for a rejected value, so this is safe to run.
        assert!(install("every other tuesday").is_err());
        assert!(install("OnCalendar=*-*-* 00:00:00\n[Service]\nExecStart=/bin/evil").is_err());
    }

    #[test]
    fn status_answers_without_anything_installed() {
        // With nothing installed, the answer is "not installed", not an error.
        let status = status();
        if !status.installed {
            assert!(!status.enabled);
            assert!(status.frequency.is_none());
        }
    }
}
