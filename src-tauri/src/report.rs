//! A scan written out as plain text, and what changed between two scans.
//!
//! Plain text because it opens everywhere, prints, and goes into a ticket or
//! an email as it is. Nothing in it is about the person: paths and addresses
//! from the scan, the version, the time.

use std::collections::HashSet;

use chrono::TimeZone;
use serde::Serialize;

use rusqlite::Connection;

use crate::db::{self, ScanRecord, StoredIssue};

pub fn local_time(timestamp: i64) -> String {
    chrono::Local
        .timestamp_opt(timestamp, 0)
        .single()
        .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| timestamp.to_string())
}

fn mark(severity: &str) -> &'static str {
    match severity {
        "critical" => "CRITICAL",
        "warning" => "WARNING ",
        _ => "NOTE    ",
    }
}

fn counts(issue: &StoredIssue) -> bool {
    issue.severity != "info" && !issue.set_aside
}

fn seen(issue: &StoredIssue) -> String {
    if issue.times_seen <= 1 {
        "new in this scan".to_string()
    } else {
        format!("seen {} times since {}", issue.times_seen, local_time(issue.first_seen))
    }
}

fn write_issue(out: &mut String, issue: &StoredIssue, history: bool) {
    out.push_str(&format!("{}  {}\n", mark(&issue.severity), issue.title));
    out.push_str(&format!("          {}\n", issue.location));
    if history {
        out.push_str(&format!("          {}\n", seen(issue)));
    }
    if let Some(detail) = &issue.detail {
        for line in detail.lines() {
            if line.trim().is_empty() {
                out.push('\n');
            } else {
                out.push_str(&format!("          {line}\n"));
            }
        }
    }
    out.push('\n');
}

fn section(out: &mut String, heading: &str, issues: &[&StoredIssue], history: bool) {
    if issues.is_empty() {
        return;
    }
    out.push_str(&format!("{heading}\n{}\n\n", "-".repeat(heading.chars().count())));
    for issue in issues {
        write_issue(out, issue, history);
    }
}

/// Said of a scan that has counts and no stored issues.
const COUNTS_ONLY: &str = "This scan is from before GRT Sentry kept what each scan found, or older than the last hundred; only its counts remain.";

/// One scan, worst first, with what was set aside and the notes at the end.
pub fn render(scan: &ScanRecord, issues: &[StoredIssue]) -> String {
    if issues.is_empty() && scan.issues_found > 0 {
        return format!(
            "GRT Sentry {}, scan of {}\n\n{} files checked, {} things needed attention.\n\n{COUNTS_ONLY}\n",
            env!("CARGO_PKG_VERSION"),
            local_time(scan.timestamp),
            scan.files_checked,
            scan.issues_found
        );
    }
    let serious: Vec<&StoredIssue> = issues.iter().filter(|i| counts(i)).collect();
    let aside: Vec<&StoredIssue> = issues.iter().filter(|i| i.set_aside).collect();
    let notes: Vec<&StoredIssue> = issues.iter().filter(|i| i.severity == "info" && !i.set_aside).collect();
    let new = serious.iter().filter(|i| i.times_seen <= 1).count();

    let mut out = format!(
        "GRT Sentry {}, scan of {}\n\n{} files checked. ",
        env!("CARGO_PKG_VERSION"),
        local_time(scan.timestamp),
        scan.files_checked
    );
    out.push_str(&match serious.len() {
        0 => "Nothing needs attention".to_string(),
        1 => "1 thing needs attention".to_string(),
        n => format!("{n} things need attention"),
    });
    if new > 0 {
        out.push_str(&format!(", {new} of them new"));
    }
    out.push_str(&format!(". {} set aside, {} notes.\n\n", aside.len(), notes.len()));

    section(&mut out, "Needs attention", &serious, true);
    section(&mut out, "Set aside", &aside, true);
    section(&mut out, "Notes", &notes, false);
    out
}

/// What one scan reported that the other did not.
#[derive(Serialize, Debug)]
pub struct Comparison {
    pub older: ScanRecord,
    pub newer: ScanRecord,
    pub appeared: Vec<StoredIssue>,
    pub gone: Vec<StoredIssue>,
    pub unchanged: usize,
    /// What changed on the machine in between, whether or not it was a problem.
    pub changes: Vec<crate::timeline::Group>,
}

pub fn compare(older: ScanRecord, old: Vec<StoredIssue>, newer: ScanRecord, new: Vec<StoredIssue>) -> Comparison {
    let before: HashSet<&str> = old.iter().map(|i| i.fingerprint.as_str()).collect();
    let after: HashSet<&str> = new.iter().map(|i| i.fingerprint.as_str()).collect();
    let unchanged = after.intersection(&before).count();
    let appeared = new.iter().filter(|i| !before.contains(i.fingerprint.as_str())).cloned().collect();
    let gone = old.iter().filter(|i| !after.contains(i.fingerprint.as_str())).cloned().collect();
    Comparison { older, newer, appeared, gone, unchanged, changes: Vec::new() }
}

pub fn render_comparison(comparison: &Comparison) -> String {
    let mut out = format!(
        "GRT Sentry {}, scan of {} compared with {}\n\n{} appeared, {} gone, {} in both.\n\n",
        env!("CARGO_PKG_VERSION"),
        local_time(comparison.newer.timestamp),
        local_time(comparison.older.timestamp),
        comparison.appeared.len(),
        comparison.gone.len(),
        comparison.unchanged
    );
    let appeared: Vec<&StoredIssue> = comparison.appeared.iter().collect();
    let gone: Vec<&StoredIssue> = comparison.gone.iter().collect();
    section(&mut out, "Appeared", &appeared, false);
    section(&mut out, "Gone", &gone, false);
    let partial = [(&comparison.older, comparison.gone.len() + comparison.unchanged), (&comparison.newer, comparison.appeared.len() + comparison.unchanged)]
        .iter()
        .any(|(scan, stored)| *stored == 0 && scan.issues_found > 0);
    if partial {
        out.push_str(&format!("One of the two has counts only. {COUNTS_ONLY}\n"));
    } else if appeared.is_empty() && gone.is_empty() {
        out.push_str("The two scans reported the same things.\n\n");
    }
    render_changes(&mut out, &comparison.changes);
    out
}

fn render_changes(out: &mut String, groups: &[crate::timeline::Group]) {
    let heading = "Changes on the machine";
    out.push_str(&format!("{heading}\n{}\n\n", "-".repeat(heading.len())));
    if groups.is_empty() {
        out.push_str("Nothing that is recorded changed: startup entries, accounts, packages and the files in the scan folders are as they were.\n");
        return;
    }
    for group in groups {
        out.push_str(&format!("{}\n", group.heading));
        for line in &group.lines {
            out.push_str(&format!("  {line}\n"));
        }
        out.push('\n');
    }
}

fn scan_or_latest(conn: &Connection, id: Option<i64>, skip: usize) -> Result<ScanRecord, String> {
    let found = match id {
        Some(id) => db::get_scan(conn, id)?,
        None => db::recent_scans(conn, skip as u32 + 1)?.into_iter().nth(skip),
    };
    found.ok_or_else(|| "There is no such scan in the history.".to_string())
}

/// The report for a scan, the latest when none is named.
pub fn scan_text(conn: &Connection, id: Option<i64>) -> Result<String, String> {
    let scan = scan_or_latest(conn, id, 0)?;
    let issues = db::scan_issues(conn, scan.id)?;
    Ok(render(&scan, &issues))
}

/// Two scans compared, the latest two when none are named.
pub fn comparison(conn: &Connection, older: Option<i64>, newer: Option<i64>) -> Result<Comparison, String> {
    let newer = scan_or_latest(conn, newer, 0)?;
    let older = scan_or_latest(conn, older, 1)?;
    let (older, newer) = if older.timestamp > newer.timestamp { (newer, older) } else { (older, newer) };
    let old = db::scan_issues(conn, older.id)?;
    let new = db::scan_issues(conn, newer.id)?;
    let changes = crate::timeline::collapse(db::machine_changes(conn, older.id, newer.id)?);
    let mut comparison = compare(older, old, newer, new);
    comparison.changes = crate::timeline::grouped(&changes);
    Ok(comparison)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(id: i64) -> ScanRecord {
        ScanRecord { id, timestamp: 1_787_000_000 + id, files_checked: 10, issues_found: 1 }
    }

    fn issue(fingerprint: &str, severity: &str, times_seen: u32, set_aside: bool) -> StoredIssue {
        StoredIssue {
            fingerprint: fingerprint.into(),
            kind: "rule_match".into(),
            severity: severity.into(),
            title: format!("title {fingerprint}"),
            location: "/tmp/x".into(),
            detail: Some("first line\n\nsecond line".into()),
            first_seen: 1_787_000_000,
            times_seen,
            set_aside,
        }
    }

    #[test]
    fn a_report_puts_what_counts_first_and_says_what_is_new() {
        let text = render(
            &scan(1),
            &[issue("a", "info", 1, false), issue("b", "warning", 1, false), issue("c", "critical", 3, true)],
        );
        assert!(text.contains("1 thing needs attention, 1 of them new. 1 set aside, 1 notes."));
        let attention = text.find("Needs attention").unwrap();
        let aside = text.find("Set aside\n").unwrap();
        let notes = text.find("Notes\n").unwrap();
        assert!(attention < aside && aside < notes);
        assert!(text.contains("seen 3 times since"));
        assert!(text.contains("          second line"));
    }

    #[test]
    fn a_comparison_names_what_came_and_what_went() {
        let comparison = compare(
            scan(1),
            vec![issue("a", "warning", 1, false), issue("b", "warning", 1, false)],
            scan(2),
            vec![issue("b", "warning", 2, false), issue("c", "critical", 1, false)],
        );
        assert_eq!(comparison.unchanged, 1);
        assert_eq!(comparison.appeared[0].fingerprint, "c");
        assert_eq!(comparison.gone[0].fingerprint, "a");
        let text = render_comparison(&comparison);
        assert!(text.contains("1 appeared, 1 gone, 1 in both."));
        assert!(text.contains("title c") && text.contains("title a"));
    }

    #[test]
    fn a_scan_with_only_counts_does_not_pass_for_clean() {
        let text = render(&scan(1), &[]);
        assert!(text.contains("only its counts remain"), "{text}");
        let clean = ScanRecord { issues_found: 0, ..scan(2) };
        assert!(render(&clean, &[]).contains("Nothing needs attention"));
    }

    #[test]
    fn a_comparison_lists_what_changed_on_the_machine() {
        let conn = db::open_memory();
        let one = db::record_scan(&conn, 0, 0).unwrap();
        let mut accounts = std::collections::BTreeMap::new();
        accounts.insert("me".to_string(), "uid 1000, /bin/bash".to_string());
        crate::timeline::record(&conn, one, crate::timeline::ACCOUNTS, &accounts).unwrap();
        let two = db::record_scan(&conn, 0, 0).unwrap();
        accounts.insert("toor".to_string(), "uid 0, /bin/bash".to_string());
        crate::timeline::record(&conn, two, crate::timeline::ACCOUNTS, &accounts).unwrap();

        let text = render_comparison(&comparison(&conn, None, None).unwrap());
        assert!(text.contains("Accounts\n  added: toor (uid 0, /bin/bash)"), "{text}");
    }

    #[test]
    fn two_scans_that_agree_say_so() {
        let comparison = compare(scan(1), vec![issue("a", "info", 1, false)], scan(2), vec![issue("a", "info", 2, false)]);
        assert!(render_comparison(&comparison).contains("reported the same things"));
    }
}
