//! Who can log in, who uses sudo, and when.
//!
//! Three short rules on top of the count of failed logins. A second account
//! with user ID 0 is a second root. An account that appears between two scans,
//! or a user who starts using sudo, is the shape of someone making themselves
//! at home. A remote login at an hour when this machine has never seen one is
//! worth a look once there is enough history to say what usual is.
//!
//! Each rule is a few lines. The first scan records what it finds and reports
//! nothing it would have to guess about.

use chrono::{Local, TimeZone, Timelike};
use rusqlite::Connection;

use crate::db;
use crate::platform::Account;
use crate::state::{Action, Finding, Issue, IssueKind, IssueTarget, Severity};

const ACCOUNTS: &str = "account";
const SUDO_USERS: &str = "sudo-user";
const LOGIN_HOURS: &str = "login-hour";
const LOGIN_CURSOR: &str = "login-cursor";

/// Logins it takes before an hour with none counts as unusual.
const HISTORY_NEEDED: u64 = 20;

/// Shells that mean an account cannot log in.
fn can_log_in(shell: &str) -> bool {
    !(shell.ends_with("/nologin") || shell.ends_with("/false") || shell.is_empty() || shell.ends_with("/sync"))
}

pub fn account_findings(conn: &Connection, accounts: &[Account]) -> Vec<Finding> {
    let first_run = !db::baseline_started(conn, ACCOUNTS);
    let mut out = Vec::new();

    for account in accounts {
        let value = format!("{}:{}", account.uid, account.shell);
        let known = db::baseline_value(conn, ACCOUNTS, &account.name);
        if known.as_deref() == Some(value.as_str()) {
            continue;
        }

        if account.uid == 0 && account.name != "root" {
            out.push(account_finding(
                Severity::Critical,
                format!("A second root account: {}", account.name),
                format!(
                    "{} has user ID 0, which makes it root under another name. Distributions do not create one; it is a classic way to keep root access that survives a change of root's password.",
                    account.name
                ),
                &account.name,
                value,
            ));
            continue;
        }
        if first_run {
            let _ = db::set_baseline_value(conn, ACCOUNTS, &account.name, &value);
            continue;
        }
        if !can_log_in(&account.shell) {
            let _ = db::set_baseline_value(conn, ACCOUNTS, &account.name, &value);
            continue;
        }
        out.push(account_finding(
            Severity::Warning,
            format!("{} account that can log in: {}", if known.is_some() { "Changed" } else { "New" }, account.name),
            format!(
                "{} (user ID {}, shell {}) {} since the last scan. Installing a program that runs as its own user explains it; an account nobody created on purpose is someone making a way back in.",
                account.name,
                account.uid,
                account.shell,
                if known.is_some() { "was given a login shell" } else { "appeared" }
            ),
            &account.name,
            value,
        ));
    }

    if first_run {
        let _ = db::mark_baseline_started(conn, ACCOUNTS);
    }
    out
}

fn account_finding(severity: Severity, title: String, detail: String, name: &str, value: String) -> Finding {
    Finding::new(
        Issue {
            kind: IssueKind::AccountActivity,
            severity,
            title,
            location: "/etc/passwd".to_string(),
            detail: Some(detail),
            actions: vec![Action::new("trust", "Expected", false), Action::ignore()],
            ..Default::default()
        },
        IssueTarget::Baseline { kind: ACCOUNTS.to_string(), key: name.to_string(), value },
    )
}

/// One line of the authentication record that a rule cares about.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    RemoteLogin { timestamp: i64, user: String, address: String },
    Sudo { user: String },
    SudoRefused { user: String },
}

pub fn parse_event(line: &str, now: i64) -> Option<Event> {
    if let Some(index) = line.find("Accepted ") {
        if !line.contains("sshd") {
            return None;
        }
        let rest = &line[index..];
        let user = rest.split(" for ").nth(1)?.split_whitespace().next()?.to_string();
        let address = rest.split(" from ").nth(1)?.split_whitespace().next()?.to_string();
        let timestamp = crate::authlog::timestamp_of(line, now).unwrap_or(now);
        return Some(Event::RemoteLogin { timestamp, user, address });
    }

    // sudo writes "sudo:   user : TTY=... ; COMMAND=..." for each use.
    let index = line.find("sudo:").or_else(|| line.find("sudo["))?;
    let rest = line[index..].split_once(':')?.1;
    let (user, what) = rest.split_once(" : ")?;
    let user = user.trim().to_string();
    if user.is_empty() || user.contains(' ') {
        return None;
    }
    if what.contains("NOT in sudoers") || what.contains("command not allowed") {
        return Some(Event::SudoRefused { user });
    }
    what.contains("COMMAND=").then_some(Event::Sudo { user })
}

pub fn login_findings(conn: &Connection, text: &str, now: i64) -> Vec<Finding> {
    let events: Vec<Event> = text.lines().filter_map(|l| parse_event(l, now)).collect();
    let mut out = Vec::new();

    // sudo, by user.
    let first_sudo = !db::baseline_started(conn, SUDO_USERS);
    let mut refused: Vec<String> = Vec::new();
    for event in &events {
        match event {
            Event::Sudo { user } if db::baseline_value(conn, SUDO_USERS, user).is_none() => {
                if !first_sudo {
                    out.push(Finding::new(
                        Issue {
                            kind: IssueKind::AccountActivity,
                            severity: Severity::Warning,
                            title: format!("{user} used sudo for the first time"),
                            location: "sudo".to_string(),
                            detail: Some(format!(
                                "{user} ran a command as root through sudo, and had not in the time GRT Sentry has been watching. A new administrator explains it; a compromised account trying its new rights looks the same."
                            )),
                            actions: vec![Action::new("trust", "Expected", false), Action::ignore()],
                            ..Default::default()
                        },
                        IssueTarget::Baseline { kind: SUDO_USERS.to_string(), key: user.clone(), value: "seen".to_string() },
                    ));
                }
                let _ = db::set_baseline_value(conn, SUDO_USERS, user, "seen");
            }
            Event::SudoRefused { user } => refused.push(user.clone()),
            _ => {}
        }
    }
    if first_sudo {
        let _ = db::mark_baseline_started(conn, SUDO_USERS);
    }
    refused.sort();
    let mut counted: Vec<(String, usize)> = Vec::new();
    for user in refused {
        match counted.last_mut() {
            Some((last, n)) if *last == user => *n += 1,
            _ => counted.push((user, 1)),
        }
    }
    for (user, count) in counted {
        out.push(Finding::note(Issue {
            kind: IssueKind::AccountActivity,
            severity: Severity::Warning,
            title: format!("{user} tried sudo without the right to"),
            location: "sudo".to_string(),
            detail: Some(format!(
                "In the last day {user} was refused by sudo {count} {}. Someone trying commands they are not allowed is exploring what this account can reach.",
                if count == 1 { "time" } else { "times" }
            )),
            actions: vec![Action::ignore()],
            ..Default::default()
        }));
    }

    // Remote logins, by hour of day.
    let cursor: i64 = db::baseline_value(conn, LOGIN_CURSOR, "").and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut latest = cursor;
    for event in &events {
        let Event::RemoteLogin { timestamp, user, address } = event else { continue };
        if *timestamp <= cursor {
            continue;
        }
        latest = latest.max(*timestamp);
        let Some(local) = Local.timestamp_opt(*timestamp, 0).single() else { continue };
        let hour = local.hour().to_string();

        let counts: Vec<u64> = (0..24)
            .map(|h| db::baseline_value(conn, LOGIN_HOURS, &h.to_string()).and_then(|v| v.parse().ok()).unwrap_or(0))
            .collect();
        let total: u64 = counts.iter().sum();
        let this_hour = counts[local.hour() as usize];
        if total >= HISTORY_NEEDED && this_hour == 0 {
            out.push(Finding::note(Issue {
                kind: IssueKind::AccountActivity,
                severity: Severity::Warning,
                title: format!("SSH login at an unusual hour: {user} from {address}"),
                location: address.clone(),
                detail: Some(format!(
                    "{user} logged in over SSH from {address} at {}. In the {total} remote logins GRT Sentry has seen, none happened at this hour of the day.",
                    local.format("%H:%M on %d %B")
                )),
                actions: vec![Action::ignore()],
                ..Default::default()
            }));
        }
        let _ = db::set_baseline_value(conn, LOGIN_HOURS, &hour, &(this_hour + 1).to_string());
    }
    if latest > cursor {
        let _ = db::set_baseline_value(conn, LOGIN_CURSOR, "", &latest.to_string());
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(name: &str, uid: u32, shell: &str) -> Account {
        Account { name: name.into(), uid, shell: shell.into() }
    }

    #[test]
    fn a_second_uid_zero_is_critical_even_on_the_first_scan() {
        let conn = crate::db::open_memory();
        let found = account_findings(&conn, &[account("root", 0, "/bin/bash"), account("toor", 0, "/bin/sh")]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].issue.severity, Severity::Critical);
    }

    #[test]
    fn new_accounts_that_can_log_in_are_reported_and_service_accounts_are_not() {
        let conn = crate::db::open_memory();
        let before = [account("root", 0, "/bin/bash"), account("me", 1000, "/bin/bash")];
        assert!(account_findings(&conn, &before).is_empty());

        let after = [
            account("root", 0, "/bin/bash"),
            account("me", 1000, "/bin/bash"),
            account("postgres", 118, "/usr/sbin/nologin"),
            account("support", 1001, "/bin/bash"),
        ];
        let found = account_findings(&conn, &after);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].issue.title, "New account that can log in: support");
    }

    #[test]
    fn the_lines_rules_need_are_read_from_both_log_styles() {
        let now = 1_787_000_000;
        let login = parse_event("2026-10-30T03:12:00+01:00 host sshd[912]: Accepted publickey for me from 203.0.113.4 port 5122 ssh2: ED25519 SHA256:x", now);
        let expected = chrono::DateTime::parse_from_rfc3339("2026-10-30T03:12:00+01:00").unwrap().timestamp();
        assert_eq!(login, Some(Event::RemoteLogin { timestamp: expected, user: "me".into(), address: "203.0.113.4".into() }));
        assert_eq!(
            parse_event("Oct 30 10:00:01 host sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update", now),
            Some(Event::Sudo { user: "alice".into() })
        );
        assert_eq!(
            parse_event("2026-10-30T10:00:01+01:00 host sudo[4401]:    mallory : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh", now),
            Some(Event::SudoRefused { user: "mallory".into() })
        );
        assert_eq!(parse_event("Oct 30 10:00:01 host sudo: pam_unix(sudo:session): session opened for user root", now), None);
        assert_eq!(parse_event("Oct 30 10:00:01 host CRON[1]: pam_unix(cron:session): session opened", now), None);
    }

    #[test]
    fn a_new_sudo_user_is_reported_after_the_first_scan() {
        let conn = crate::db::open_memory();
        let now = 1_787_000_000;
        let day_one = "Oct 30 10:00:01 host sudo:   me : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/true\n";
        assert!(login_findings(&conn, day_one, now).is_empty());
        let day_two = "Oct 30 10:00:01 host sudo:   me : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/true\n\
                       Oct 30 11:00:01 host sudo:   www : TTY=pts/2 ; PWD=/ ; USER=root ; COMMAND=/bin/bash\n\
                       Oct 30 11:00:02 host sudo:   guest : user NOT in sudoers ; TTY=pts/3 ; PWD=/ ; USER=root ; COMMAND=/bin/sh\n";
        let found = login_findings(&conn, day_two, now);
        let titles: Vec<_> = found.iter().map(|f| f.issue.title.clone()).collect();
        assert!(titles.contains(&"www used sudo for the first time".to_string()), "{titles:?}");
        assert!(titles.contains(&"guest tried sudo without the right to".to_string()));
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn an_unusual_hour_needs_history_and_each_login_counts_once() {
        let conn = crate::db::open_memory();
        let line = |ts: i64| {
            let t = Local.timestamp_opt(ts, 0).single().unwrap().to_rfc3339();
            format!("{t} host sshd[1]: Accepted publickey for me from 198.51.100.7 port 1 ssh2\n")
        };
        // Twenty logins at ten in the morning, on twenty days.
        let ten = Local.with_ymd_and_hms(2026, 9, 1, 10, 0, 0).single().unwrap().timestamp();
        let history: String = (0..20).map(|d| line(ten + d * 86_400)).collect();
        assert!(login_findings(&conn, &history, ten + 20 * 86_400).is_empty(), "no history yet when these happened");
        assert!(login_findings(&conn, &history, ten + 20 * 86_400).is_empty(), "already counted");

        let three = Local.with_ymd_and_hms(2026, 9, 25, 3, 0, 0).single().unwrap().timestamp();
        let found = login_findings(&conn, &line(three), three + 60);
        assert_eq!(found.len(), 1);
        assert!(found[0].issue.title.contains("unusual hour"));
    }
}
