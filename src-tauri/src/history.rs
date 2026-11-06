//! What a problem was before this scan: new, seen before, or set aside.
//!
//! Each issue gets a fingerprint from what stays the same about it between
//! scans: a file's path and contents, an address, a baseline key. Counts and
//! process ids change and are left out, so the fifth scan of the same thing
//! says so instead of announcing it as news.

use std::collections::HashMap;

use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::db::{self, StoredIssue};
use crate::state::{Finding, Issue, IssueTarget};

/// The name a kind is stored under, the same as the interface sees.
pub fn kind_name(issue: &Issue) -> String {
    serde_json::to_value(issue.kind).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

fn severity_name(issue: &Issue) -> String {
    serde_json::to_value(issue.severity).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

/// A title without its numbers, for issues that only have a title to go by.
fn without_digits(text: &str) -> String {
    text.chars().filter(|c| !c.is_ascii_digit()).collect()
}

/// What stays the same about an issue from one scan to the next.
pub fn fingerprint(issue: &Issue, target: &IssueTarget) -> String {
    let what = match target {
        IssueTarget::File { path, sha256 } => format!("{path}|{sha256}"),
        IssueTarget::Connection { ip, process, .. } => format!("{ip}|{}", process.as_deref().unwrap_or("")),
        IssueTarget::Integrity { path, current_hash } => format!("{path}|{current_hash}"),
        IssueTarget::Package { path, digest } => format!("{path}|{digest}"),
        // The pid changes on every start, the program and its file do not.
        IssueTarget::Process { name, .. } => format!("{name}|{}", issue.detail.as_deref().unwrap_or("")),
        IssueTarget::Baseline { kind, key, value } => format!("{kind}|{key}|{value}"),
        IssueTarget::Autostart { key, .. } => key.clone(),
        IssueTarget::Packages { names } | IssueTarget::BlockProposal { ips: names } => {
            let mut sorted = names.clone();
            sorted.sort();
            sorted.join(",")
        }
        IssueTarget::LoginAttempts { ip, .. } => ip.clone(),
        IssueTarget::Informational => format!("{}|{}", issue.location, without_digits(&issue.title)),
    };
    let digest = Sha256::digest(format!("{}|{what}", kind_name(issue)).as_bytes());
    digest.iter().take(16).map(|b| format!("{b:02x}")).collect()
}

/// Fingerprints the findings and fills in what the history knows.
///
/// The same fingerprint twice in one scan counts once.
pub fn apply(conn: &Connection, findings: &mut [Finding], at: i64) {
    let mut seen: HashMap<String, db::Sighting> = HashMap::new();
    for finding in findings.iter_mut() {
        let print = fingerprint(&finding.issue, &finding.target);
        let sighting = match seen.get(&print) {
            Some(known) => known.clone(),
            None => match db::observe_issue(conn, &print, &kind_name(&finding.issue), at) {
                Ok(sighting) => {
                    seen.insert(print.clone(), sighting.clone());
                    sighting
                }
                Err(e) => {
                    eprintln!("grt-sentry: the issue history could not be written: {e}");
                    db::Sighting { first_seen: at, times_seen: 1, set_aside: false }
                }
            },
        };
        let issue = &mut finding.issue;
        issue.fingerprint = print;
        issue.first_seen = sighting.first_seen;
        issue.times_seen = sighting.times_seen;
        issue.set_aside = sighting.set_aside;
    }
}

/// The issue as the scan history keeps it.
pub fn stored(issue: &Issue) -> StoredIssue {
    StoredIssue {
        fingerprint: issue.fingerprint.clone(),
        kind: kind_name(issue),
        severity: severity_name(issue),
        title: issue.title.clone(),
        location: issue.location.clone(),
        detail: issue.detail.clone(),
        first_seen: issue.first_seen,
        times_seen: issue.times_seen,
        set_aside: issue.set_aside,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{IssueKind, Severity};

    fn file(path: &str, sha: &str) -> Finding {
        Finding::new(
            Issue { kind: IssueKind::RuleMatch, severity: Severity::Warning, location: path.into(), ..Default::default() },
            IssueTarget::File { path: path.into(), sha256: sha.into() },
        )
    }

    #[test]
    fn the_second_scan_of_the_same_thing_is_not_news() {
        let conn = db::open_memory();
        let mut first = vec![file("/tmp/a", "h1")];
        apply(&conn, &mut first, 100);
        assert!(first[0].issue.is_new());

        let mut second = vec![file("/tmp/a", "h1")];
        apply(&conn, &mut second, 200);
        assert_eq!(second[0].issue.times_seen, 2);
        assert_eq!(second[0].issue.first_seen, 100);
        assert!(!second[0].issue.is_new());
    }

    #[test]
    fn an_issue_set_aside_does_not_come_back_as_new() {
        let conn = db::open_memory();
        let mut first = vec![file("/tmp/a", "h1")];
        apply(&conn, &mut first, 100);
        db::set_issue_aside(&conn, &first[0].issue.fingerprint, "rule_match", true).unwrap();

        let mut later = vec![file("/tmp/a", "h1")];
        apply(&conn, &mut later, 200);
        assert!(later[0].issue.set_aside);
        assert!(!later[0].issue.counts());
        assert!(!later[0].issue.is_new());
    }

    #[test]
    fn new_contents_are_a_new_problem_even_after_setting_the_old_ones_aside() {
        let conn = db::open_memory();
        let mut first = vec![file("/tmp/a", "h1")];
        apply(&conn, &mut first, 100);
        db::set_issue_aside(&conn, &first[0].issue.fingerprint, "rule_match", true).unwrap();

        let mut changed = vec![file("/tmp/a", "h2")];
        apply(&conn, &mut changed, 200);
        assert!(changed[0].issue.is_new());
    }

    #[test]
    fn counts_in_a_title_and_a_new_pid_change_nothing() {
        let note = |title: &str| Issue { title: title.into(), location: "Local".into(), ..Default::default() };
        assert_eq!(
            fingerprint(&note("12 failed authentications"), &IssueTarget::Informational),
            fingerprint(&note("14 failed authentications"), &IssueTarget::Informational)
        );

        let process = |pid| IssueTarget::Process { pid, name: "x".into() };
        let issue = Issue { kind: IssueKind::SuspiciousProcess, detail: Some("from /tmp/x".into()), ..Default::default() };
        assert_eq!(fingerprint(&issue, &process(10)), fingerprint(&issue, &process(20)));
    }

    #[test]
    fn the_same_thing_twice_in_one_scan_counts_once() {
        let conn = db::open_memory();
        let mut both = vec![file("/tmp/a", "h1"), file("/tmp/a", "h1")];
        apply(&conn, &mut both, 100);
        assert_eq!(both[1].issue.times_seen, 1);
    }
}
