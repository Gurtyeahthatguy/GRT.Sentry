//! Whether the system files that matter are still the ones that were there.
//!
//! A step after a machine is compromised is to edit something small and
//! central: a line in `/etc/hosts`, an account in `/etc/passwd`, a rule in
//! `/etc/sudoers`. None of that arrives as a download.
//!
//! A hash of each is recorded the first time and compared afterwards. It is
//! about ten small files.
//!
//! A system update changes several of them legitimately, so a changed hash is
//! a question rather than a verdict, and every issue offers to accept the new
//! contents as the reference.

use std::path::{Path, PathBuf};

use rusqlite::Connection;

use crate::actionlog;
use crate::db;
use crate::scanner;
use crate::state::{Action, Finding, Issue, IssueKind, IssueTarget, Severity};

/// Expands the configured list, where a trailing `*` means each file in a
/// directory.
fn expand(patterns: &[String]) -> Vec<PathBuf> {
    let mut out = Vec::new();

    for pattern in patterns {
        let expanded = crate::paths::expand_tilde(pattern);
        let text = expanded.to_string_lossy().into_owned();

        if let Some(dir) = text.strip_suffix("/*") {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    if entry.path().is_file() {
                        out.push(entry.path());
                    }
                }
            }
            continue;
        }

        out.push(expanded);
    }

    out.sort();
    out.dedup();
    out
}

/// Compares every watched file against its recorded hash.
pub fn findings(conn: &Connection, patterns: &[String]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut recorded = 0usize;

    for path in expand(patterns) {
        let display = path.to_string_lossy().into_owned();
        let baseline = db::baseline_hash(conn, &display);

        let current = match scanner::hash_file(&path) {
            Ok(hash) => hash,
            Err(e) => {
                // A file that was here and is gone is worth saying. One that
                // cannot be read at all, such as /etc/shadow, is dropped.
                if baseline.is_some() && e.kind() == std::io::ErrorKind::NotFound {
                    findings.push(missing_file_finding(&display));
                }
                continue;
            }
        };

        match baseline {
            None => {
                let _ = db::set_baseline(conn, &display, &current);
                recorded += 1;
            }
            Some(old) if old != current => {
                findings.push(changed_file_finding(&display, &current));
            }
            _ => {}
        }
    }

    // This file forces a library into every program that starts, and has
    // almost no legitimate use on a desktop.
    if let Some(finding) = preload_finding() {
        findings.push(finding);
    }

    if recorded > 0 && findings.is_empty() {
        findings.push(Finding::note(Issue {
            kind: IssueKind::ModuleUnavailable,
            severity: Severity::Info,
            title: format!("{recorded} system files recorded for comparison"),
            location: "System integrity".to_string(),
            detail: Some(
                "Their current contents are now the reference, and a change to any of them is reported from the next scan onwards.\n\nThis assumes the system is sound today. If it was already tampered with, the tampered version is what gets recorded."
                    .to_string(),
            ),
            actions: vec![Action::ignore()],
            ..Default::default()
        }));
    }

    findings
}

fn changed_file_finding(path: &str, current_hash: &str) -> Finding {
    Finding::new(
        Issue {
            kind: IssueKind::IntegrityChanged,
            severity: Severity::Warning,
            title: format!("System file changed: {path}"),
            location: path.to_string(),
            detail: Some(format!(
                "The contents of {path} are not what they were at the last check.\n\n\
                 A system update changes some of these files legitimately, and so does editing one by hand. \
                 After a recent update this is expected: confirm it, and the new contents become the reference.\n\n\
                 Otherwise it is worth reading what changed first:\n\n    sudo cat {path}"
            )),
            actions: vec![
                Action::new("update_baseline", "This was expected", false),
                Action::ignore(),
            ],
            ..Default::default()
        },
        IssueTarget::Integrity { path: path.to_string(), current_hash: current_hash.to_string() },
    )
}

fn missing_file_finding(path: &str) -> Finding {
    Finding::new(
        Issue {
            kind: IssueKind::IntegrityChanged,
            severity: Severity::Warning,
            title: format!("System file gone: {path}"),
            location: path.to_string(),
            detail: Some(format!(
                "{path} was there at the last check and is not now, which is unusual for a file at this level."
            )),
            actions: vec![Action::new("update_baseline", "This was expected", false), Action::ignore()],
            ..Default::default()
        },
        IssueTarget::Integrity { path: path.to_string(), current_hash: String::new() },
    )
}

/// Libraries the system has been told to load into every process.
fn preload_finding() -> Option<Finding> {
    let (source, listed) = crate::platform::injected_libraries()?;
    if listed.is_empty() {
        return None;
    }

    Some(Finding::new(
        Issue {
            kind: IssueKind::IntegrityChanged,
            severity: Severity::Critical,
            title: "A library is being forced into every program that starts".to_string(),
            location: source.clone(),
            detail: Some(format!(
                "This file makes the loader insert a library into every process on the system, before that process runs any of its own code. It is how a rootkit hides files and connections from the tools used to look for it.\n\n\
                 It is listing: {}\n\n\
                 A few legitimate tools use this. If it was not installed on purpose, treat the machine as compromised and investigate from outside it, booted from a live USB.",
                listed.join(", ")
            )),
            actions: vec![Action::ignore()],
            ..Default::default()
        },
        IssueTarget::Integrity { path: source, current_hash: String::new() },
    ))
}

/// Accepts the current contents of a file as the new reference.
pub fn accept_current(conn: &Connection, path: &str, current_hash: &str) -> Result<(), String> {
    // Recomputed rather than trusted, since the file may have changed again.
    let hash = match scanner::hash_file(Path::new(path)) {
        Ok(hash) => hash,
        Err(_) if !current_hash.is_empty() => current_hash.to_string(),
        Err(e) => return Err(format!("Cannot read {path}: {e}")),
    };

    db::set_baseline(conn, path, &hash)?;
    actionlog::record(conn, actionlog::kind::UPDATE_BASELINE, path, Some("confirmed by the user"), false);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_pattern_becomes_the_files_inside_it() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a"), b"1").unwrap();
        std::fs::write(dir.path().join("b"), b"2").unwrap();

        let pattern = format!("{}/*", dir.path().to_string_lossy());
        let expanded = expand(&[pattern]);
        assert_eq!(expanded.len(), 2);
    }

    #[test]
    fn the_first_look_records_and_the_second_stays_quiet() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("hosts");
        std::fs::write(&file, b"127.0.0.1 localhost\n").unwrap();
        let watched = vec![file.to_string_lossy().into_owned()];

        let conn = crate::db::open_memory();
        let first = findings(&conn, &watched);
        assert!(first.iter().all(|f| f.issue.severity == Severity::Info));

        let second = findings(&conn, &watched);
        assert!(second.is_empty(), "an unchanged file must produce nothing at all");
    }

    #[test]
    fn a_changed_file_is_reported_with_a_way_to_accept_it() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("hosts");
        std::fs::write(&file, b"127.0.0.1 localhost\n").unwrap();
        let watched = vec![file.to_string_lossy().into_owned()];

        let conn = crate::db::open_memory();
        findings(&conn, &watched);

        std::fs::write(&file, b"127.0.0.1 localhost\n1.2.3.4 my-bank.example\n").unwrap();
        let found = findings(&conn, &watched);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].issue.kind, IssueKind::IntegrityChanged);
        assert_eq!(found[0].issue.severity, Severity::Warning);
        assert!(found[0].issue.actions.iter().any(|a| a.id == "update_baseline"));

        // Accepting it makes the new contents the reference, and the next
        // scan is quiet again.
        accept_current(&conn, &file.to_string_lossy(), "").unwrap();
        assert!(findings(&conn, &watched).is_empty());
    }

    #[test]
    fn a_file_that_disappears_after_being_recorded_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("crontab");
        std::fs::write(&file, b"# nothing\n").unwrap();
        let watched = vec![file.to_string_lossy().into_owned()];

        let conn = crate::db::open_memory();
        findings(&conn, &watched);
        std::fs::remove_file(&file).unwrap();

        let found = findings(&conn, &watched);
        assert_eq!(found.len(), 1);
        assert!(found[0].issue.title.contains("gone"));
    }

    #[test]
    fn a_file_that_was_never_readable_is_passed_over_in_silence() {
        let conn = crate::db::open_memory();
        let watched = vec!["/etc/shadow".to_string(), "/nonexistent/thing".to_string()];
        // Neither is readable by an ordinary user, and neither has a baseline:
        // nothing to say about either.
        assert!(findings(&conn, &watched).iter().all(|f| f.issue.kind == IssueKind::ModuleUnavailable));
    }

    #[test]
    fn accepting_uses_what_is_on_disk_now_rather_than_what_it_was_told() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("passwd");
        std::fs::write(&file, b"root:x:0:0\n").unwrap();

        let conn = crate::db::open_memory();
        accept_current(&conn, &file.to_string_lossy(), "a-stale-hash").unwrap();

        let stored = db::baseline_hash(&conn, &file.to_string_lossy()).unwrap();
        assert_eq!(stored, scanner::hash_file(&file).unwrap());
        assert_ne!(stored, "a-stale-hash");
    }
}
