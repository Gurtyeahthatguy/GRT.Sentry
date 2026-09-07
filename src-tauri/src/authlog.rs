//! Failed logins, read from the authentication log.
//!
//! On a desktop with no SSH server this module finds nothing, which is the
//! correct answer. On a reachable machine, repeated failures from one address
//! are the clearest sign that somebody is trying the door.
//!
//! Only the tail of the record is read, since everything older than a day is
//! irrelevant to what is happening now. Where that record lives is the
//! system's business: a log file on Linux, the Security event log on Windows.

use std::collections::HashMap;

use chrono::{Datelike, NaiveDateTime, TimeZone};
use rusqlite::Connection;

use crate::platform::{self, LogAccess};
use crate::state::{Action, Finding, Issue, IssueKind, IssueTarget, Severity};

/// How far back a count reaches.
const WINDOW: i64 = 24 * 60 * 60;

/// Reads the record with administrator rights.
///
/// Never called by a scan, only by the button on the issue that says it could
/// not be read.
pub fn read_privileged(path: &str) -> Result<String, String> {
    platform::read_auth_log_privileged(path)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Failure {
    pub timestamp: i64,
    /// `None` for a local failure, such as a mistyped sudo password.
    pub address: Option<String>,
    pub user: Option<String>,
}

/// The phrasings that mean a login did not succeed.
fn is_failure(line: &str) -> bool {
    line.contains("Failed password")
        || line.contains("Failed publickey")
        || line.contains("authentication failure")
        || line.contains("Invalid user")
        || line.contains("Failed keyboard-interactive")
}

/// Reads one line into a failure, when it is one.
pub fn parse_line(line: &str, now: i64) -> Option<Failure> {
    if !is_failure(line) {
        return None;
    }

    let timestamp = parse_timestamp(line, now).unwrap_or(now);
    Some(Failure { timestamp, address: extract_address(line), user: extract_user(line) })
}

/// Handles both timestamp styles found in the wild.
///
/// Modern rsyslog writes RFC 3339. Traditional syslog carries no year, so the
/// current one is assumed and a date in the future is read as last year's.
fn parse_timestamp(line: &str, now: i64) -> Option<i64> {
    let first = line.split_whitespace().next()?;

    if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(first) {
        return Some(parsed.timestamp());
    }

    let mut parts = line.split_whitespace();
    let month = parts.next()?;
    let day = parts.next()?;
    let time = parts.next()?;

    let reference = chrono::Local.timestamp_opt(now, 0).single()?;
    let year = reference.year();
    let text = format!("{year} {month} {day} {time}");
    let naive = NaiveDateTime::parse_from_str(&text, "%Y %b %e %H:%M:%S").ok()?;
    let local = chrono::Local.from_local_datetime(&naive).single()?;

    // A line dated later than now belongs to the previous year.
    if local.timestamp() > now + 86_400 {
        let text = format!("{} {month} {day} {time}", year - 1);
        let naive = NaiveDateTime::parse_from_str(&text, "%Y %b %e %H:%M:%S").ok()?;
        return chrono::Local.from_local_datetime(&naive).single().map(|d| d.timestamp());
    }

    Some(local.timestamp())
}

/// The remote address, written as `from 1.2.3.4` or `rhost=1.2.3.4`.
fn extract_address(line: &str) -> Option<String> {
    let start = line
        .find("rhost=")
        .map(|index| index + 6)
        .or_else(|| line.find(" from ").map(|index| index + 6))?;
    let candidate = line[start..].split_whitespace().next()?;

    // Parsed rather than pattern-matched, since it goes on to the firewall.
    candidate.parse::<std::net::IpAddr>().ok().map(|ip| ip.to_string())
}

fn extract_user(line: &str) -> Option<String> {
    if let Some(index) = line.find("Invalid user ") {
        return line[index + 13..].split_whitespace().next().map(|s| s.to_string());
    }
    if let Some(index) = line.find(" for ") {
        let candidate = line[index + 5..].split_whitespace().next()?;
        if candidate != "invalid" {
            return Some(candidate.to_string());
        }
    }
    if let Some(index) = line.find("user=") {
        return line[index + 5..].split_whitespace().next().map(|s| s.to_string());
    }
    None
}

/// Counts failures per address inside the window.
pub fn summarise(text: &str, now: i64) -> (HashMap<String, Vec<Failure>>, usize) {
    let mut by_address: HashMap<String, Vec<Failure>> = HashMap::new();
    let mut local = 0usize;

    for line in text.lines() {
        let Some(failure) = parse_line(line, now) else { continue };
        if now - failure.timestamp > WINDOW {
            continue;
        }
        match &failure.address {
            Some(address) => by_address.entry(address.clone()).or_default().push(failure),
            None => local += 1,
        }
    }

    (by_address, local)
}

/// Issues for the addresses that went over the threshold.
pub fn findings(_conn: &Connection, log_path: &str, threshold: u32) -> Vec<Finding> {
    let text = match platform::read_auth_log(log_path) {
        LogAccess::Ok(text) => text,
        LogAccess::Denied => {
            return vec![Finding::new(
                Issue {
                    kind: IssueKind::ModuleUnavailable,
                    severity: Severity::Info,
                    title: "The record of failed logins cannot be read".to_string(),
                    location: log_path.to_string(),
                    detail: Some(platform::auth_log_denied_detail(log_path)),
                    actions: vec![Action::new("read_authlog", "Read with administrator rights", false), Action::ignore()],
                    ..Default::default()
                },
                IssueTarget::Informational,
            )];
        }
        LogAccess::Missing => {
            return vec![Finding::note(Issue {
                kind: IssueKind::ModuleUnavailable,
                severity: Severity::Info,
                title: "No record of failed logins on this system".to_string(),
                location: log_path.to_string(),
                detail: Some(platform::auth_log_missing_detail(log_path)),
                actions: vec![Action::ignore()],
                ..Default::default()
            })];
        }
    };

    findings_from_text(&text, threshold, crate::db::now())
}

/// The part that does not touch the filesystem, so it can be tested.
pub fn findings_from_text(text: &str, threshold: u32, now: i64) -> Vec<Finding> {
    let (by_address, local) = summarise(text, now);
    let mut findings = Vec::new();

    let mut addresses: Vec<_> = by_address.into_iter().collect();
    addresses.sort_by_key(|(_, failures)| std::cmp::Reverse(failures.len()));

    for (address, failures) in addresses {
        let count = failures.len() as u32;
        if count < threshold {
            continue;
        }

        // A handful is a fumbled password. Fifty is a program.
        let severity = if count >= 50 { Severity::Critical } else { Severity::Warning };

        let mut users: Vec<String> = failures.iter().filter_map(|f| f.user.clone()).collect();
        users.sort();
        users.dedup();
        let users_line = if users.is_empty() {
            String::new()
        } else {
            format!("\n\nAccounts tried: {}", users.iter().take(8).cloned().collect::<Vec<_>>().join(", "))
        };

        findings.push(Finding::new(
            Issue {
                kind: IssueKind::FailedLoginAttempts,
                severity,
                title: format!("{count} failed login attempts from {address}"),
                location: address.clone(),
                detail: Some(format!(
                    "In the last 24 hours, {count} authentication failures came from {address}.{users_line}\n\n\
                     With no SSH server running, or no reason to expect that address, blocking it costs nothing."
                )),
                actions: vec![
                    Action::new("block_ip", "Block address", true),
                    Action::new("trust", "Expected", false),
                    Action::ignore(),
                ],
                ..Default::default()
            },
            IssueTarget::LoginAttempts { ip: address },
        ));
    }

    // Local failures are usually a mistyped sudo password.
    if local >= 10 {
        findings.push(Finding::note(Issue {
            kind: IssueKind::FailedLoginAttempts,
            severity: Severity::Info,
            title: format!("{local} failed authentications at this machine"),
            location: "Local".to_string(),
            detail: Some(
                "These have no remote address, so they were typed at this computer, most often as a mistyped sudo or screen-lock password."
                    .to_string(),
            ),
            actions: vec![Action::ignore()],
            ..Default::default()
        }));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_787_000_000; // a fixed point in time

    #[test]
    fn the_three_wordings_of_failure_are_all_recognised() {
        assert!(is_failure("Failed password for root from 1.2.3.4 port 22 ssh2"));
        assert!(is_failure("pam_unix(sshd:auth): authentication failure; rhost=1.2.3.4"));
        assert!(is_failure("Invalid user admin from 1.2.3.4"));
        assert!(!is_failure("Accepted password for user from 192.168.1.5 port 22 ssh2"));
        assert!(!is_failure("session opened for user root"));
    }

    #[test]
    fn an_address_is_found_in_either_spelling_and_validated() {
        assert_eq!(
            extract_address("Failed password for root from 185.220.101.7 port 22 ssh2").as_deref(),
            Some("185.220.101.7")
        );
        assert_eq!(
            extract_address("authentication failure; logname= uid=0 rhost=10.0.0.9 user=root").as_deref(),
            Some("10.0.0.9")
        );
        // A hostname where an address was expected is not passed on.
        assert_eq!(extract_address("Failed password for root from evil.example.com port 22"), None);
        assert_eq!(extract_address("Failed password for root"), None);
    }

    #[test]
    fn the_account_being_tried_is_extracted() {
        assert_eq!(extract_user("Invalid user admin from 1.2.3.4").as_deref(), Some("admin"));
        assert_eq!(
            extract_user("Failed password for root from 1.2.3.4 port 22 ssh2").as_deref(),
            Some("root")
        );
        assert_eq!(
            extract_user("authentication failure; logname= uid=0 rhost=1.2.3.4 user=admin").as_deref(),
            Some("admin")
        );
    }

    #[test]
    fn both_timestamp_formats_are_understood() {
        let rfc = "2026-08-25T05:31:48.147017+02:00 host sshd[1]: Failed password for root from 1.2.3.4";
        assert_eq!(parse_timestamp(rfc, NOW), Some(1_787_628_708));

        // No year in this format, so the result depends on the reference.
        let syslog = "Aug 25 05:31:48 host sshd[1]: Failed password for root from 1.2.3.4";
        let parsed = parse_timestamp(syslog, NOW).expect("syslog format must parse");
        assert!((parsed - NOW).abs() < 400 * 86_400);
    }

    #[test]
    fn only_the_last_day_is_counted() {
        let recent = format!(
            "{} host sshd[1]: Failed password for root from 1.2.3.4 port 22\n",
            chrono::Utc.timestamp_opt(NOW - 60, 0).unwrap().to_rfc3339()
        );
        let old = format!(
            "{} host sshd[1]: Failed password for root from 1.2.3.4 port 22\n",
            chrono::Utc.timestamp_opt(NOW - 3 * 86_400, 0).unwrap().to_rfc3339()
        );

        let (by_address, _) = summarise(&format!("{recent}{old}"), NOW);
        assert_eq!(by_address["1.2.3.4"].len(), 1);
    }

    #[test]
    fn an_address_over_the_threshold_becomes_an_issue_that_offers_the_firewall() {
        let stamp = chrono::Utc.timestamp_opt(NOW - 300, 0).unwrap().to_rfc3339();
        let text: String = (0..6)
            .map(|_| format!("{stamp} host sshd[1]: Failed password for root from 185.220.101.7 port 22 ssh2\n"))
            .collect();

        let found = findings_from_text(&text, 5, NOW);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].issue.severity, Severity::Warning);
        assert!(found[0].issue.title.contains("6 failed login attempts"));
        assert!(found[0].issue.actions.iter().any(|a| a.id == "block_ip"));
    }

    #[test]
    fn a_sustained_run_of_attempts_is_treated_as_more_than_a_warning() {
        let stamp = chrono::Utc.timestamp_opt(NOW - 300, 0).unwrap().to_rfc3339();
        let text: String = (0..60)
            .map(|_| format!("{stamp} host sshd[1]: Failed password for root from 185.220.101.7 port 22\n"))
            .collect();

        assert_eq!(findings_from_text(&text, 5, NOW)[0].issue.severity, Severity::Critical);
    }

    #[test]
    fn staying_under_the_threshold_says_nothing() {
        let stamp = chrono::Utc.timestamp_opt(NOW - 300, 0).unwrap().to_rfc3339();
        let text = format!("{stamp} host sshd[1]: Failed password for root from 1.2.3.4 port 22\n");
        assert!(findings_from_text(&text, 5, NOW).is_empty());
    }

    #[test]
    fn mistyped_local_passwords_are_never_an_alarm() {
        let stamp = chrono::Utc.timestamp_opt(NOW - 300, 0).unwrap().to_rfc3339();
        let text: String = (0..12)
            .map(|_| format!("{stamp} host sudo: pam_unix(sudo:auth): authentication failure; logname=user uid=1000\n"))
            .collect();

        let found = findings_from_text(&text, 5, NOW);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].issue.severity, Severity::Info);
    }

    // Windows reads the event log and ignores the path, so a missing file is
    // a question that only means something here.
    #[cfg(not(windows))]
    #[test]
    fn a_log_that_is_not_there_is_reported_as_a_fact_not_a_failure() {
        let conn = crate::db::open_memory();
        let found = findings(&conn, "/nonexistent/auth.log", 5);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].issue.severity, Severity::Info);
        assert_eq!(found[0].issue.kind, IssueKind::ModuleUnavailable);
    }
}
