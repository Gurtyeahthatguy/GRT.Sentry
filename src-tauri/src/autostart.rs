//! What starts on its own when the machine does.
//!
//! Persistence is what turns a one-off execution into an infection. The catch
//! is that a normal desktop already has thirty or forty of these, all
//! legitimate, so the first run records what it finds as the baseline and
//! reports nothing. After that, only what is new gets mentioned.
//!
//! Where the entries come from is the system's business: desktop files, user
//! services and cron on Linux, the registry, the startup folder and the task
//! scheduler on Windows.

use rusqlite::Connection;

use crate::db;
pub use crate::platform::AutostartEntry;

use crate::platform;
use crate::state::{Action, Finding, Issue, IssueKind, IssueTarget, Severity};

/// Everything that will start by itself, sorted so two runs agree.
pub fn collect() -> Vec<AutostartEntry> {
    let mut entries = platform::autostart_entries();
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    entries.dedup_by(|a, b| a.key == b.key);
    entries
}

/// Compares what is there now against the baseline.
///
/// An empty baseline records everything and reports nothing, so whatever was
/// installed before the first run is taken as given. The interface says so.
pub fn findings(conn: &Connection) -> Vec<Finding> {
    let entries = collect();
    let first_run = db::autostart_baseline_is_empty(conn);
    let mut findings = Vec::new();

    for entry in &entries {
        let known = db::autostart_is_known(conn, &entry.key);
        if !known {
            let _ = db::remember_autostart(conn, &entry.key, &entry.source, &entry.name, &entry.command);
        }
        if known || first_run {
            continue;
        }

        findings.push(Finding::new(
            Issue {
                kind: IssueKind::UnknownAutostartEntry,
                severity: Severity::Warning,
                title: format!("New startup entry: {}", entry.name),
                location: format!("{}: {}", entry.source, entry.command),
                detail: Some({
                    let mut detail = format!(
                        "This was not in the list of things that start automatically the last time GRT Sentry looked.\n\n\
                         A recent installation explains it. Otherwise it is worth finding out what put it there.\n\n\
                         Identity: {}",
                        entry.key
                    );
                    if let Some(path) = platform::autostart_entry_path(&entry.key) {
                        detail.push_str(&format!("\nDeclared in: {}", path.display()));
                    }
                    detail
                }),
                actions: vec![Action::new("trust", "Expected", false), Action::ignore()],
                ..Default::default()
            },
            IssueTarget::Autostart { key: entry.key.clone(), name: entry.name.clone() },
        ));
    }

    if first_run && !entries.is_empty() {
        findings.push(Finding::note(Issue {
            kind: IssueKind::ModuleUnavailable,
            severity: Severity::Info,
            title: format!("{} startup entries recorded as the baseline", entries.len()),
            location: "Autostart".to_string(),
            detail: Some(
                "This is the first scan, so what starts automatically now has been taken as normal. From the next scan onwards, only new entries are reported."
                    .to_string(),
            ),
            actions: vec![Action::ignore()],
            ..Default::default()
        }));
    }

    findings
}

/// The full list, for the interface to show on request.
pub fn list() -> Vec<AutostartEntry> {
    collect()
}

/// Remembers an entry, so the "Expected" action stops it being new.
pub fn accept(conn: &Connection, key: &str, name: &str) -> Result<(), String> {
    db::remember_autostart(conn, key, "accepted", name, "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_run_records_everything_and_alarms_about_nothing() {
        let conn = crate::db::open_memory();
        let found = findings(&conn);
        assert!(
            found.iter().all(|f| f.issue.severity == Severity::Info),
            "a first scan must not report the machine's existing setup as suspicious"
        );
    }

    #[test]
    fn an_entry_that_appears_later_is_reported_once() {
        let conn = crate::db::open_memory();
        // Pretend a first run already happened and recorded one entry.
        db::remember_autostart(&conn, "user desktop entry:old.desktop", "user", "Old", "/bin/old").unwrap();

        // A newly discovered key is new; asking again after it is recorded is not.
        assert!(!db::autostart_is_known(&conn, "user desktop entry:new.desktop"));
        db::remember_autostart(&conn, "user desktop entry:new.desktop", "user", "New", "/bin/new").unwrap();
        assert!(db::autostart_is_known(&conn, "user desktop entry:new.desktop"));
    }

    #[test]
    fn accepting_an_entry_stops_it_being_new() {
        let conn = crate::db::open_memory();
        accept(&conn, "user desktop entry:thing.desktop", "Thing").unwrap();
        assert!(db::autostart_is_known(&conn, "user desktop entry:thing.desktop"));
    }

    #[test]
    fn collecting_from_this_machine_produces_plausible_entries() {
        // The assertion is only that whatever comes back is well formed.
        for entry in collect() {
            assert!(entry.key.contains(':'));
            assert!(!entry.source.is_empty());
        }
    }
}
