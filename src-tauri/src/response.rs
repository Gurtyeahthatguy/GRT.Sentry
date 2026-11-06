//! The automatic response: blocking addresses that keep trying to log in.
//!
//! Off by default. When it is on, a scan run as root blocks by itself, and any
//! other scan offers one button for all the addresses over the limit, because
//! blocking needs the administrator's password. Automatic blocks lift after a
//! day, so a dynamic address does not stay blocked for whoever gets it next.

use std::net::IpAddr;

use rusqlite::Connection;

use crate::state::{Action, Finding, Issue, IssueKind, IssueTarget, Severity};
use crate::{actionlog, db, geoip, platform};

pub const BLOCK_HOURS: i64 = 24;

/// Forgets automatic blocks whose day is over.
///
/// nftables drops them by itself; a Windows firewall rule has no timeout, so
/// it is removed here when there are the rights to.
pub fn lift_expired(conn: &Connection, at: i64) {
    let Ok(expired) = db::expired_blocks(conn, at) else { return };
    for ip in expired {
        if !platform::BLOCKS_EXPIRE {
            let Ok(parsed) = ip.parse::<IpAddr>() else { continue };
            if !platform::is_elevated() || platform::unblock_for(&parsed).is_err() {
                continue;
            }
        }
        let _ = db::remove_block(conn, &ip);
    }
}

/// Login findings for addresses already blocked become notes.
pub fn mark_blocked(conn: &Connection, findings: &mut [Finding], at: i64) {
    for finding in findings.iter_mut() {
        let IssueTarget::LoginAttempts { ip, .. } = &finding.target else { continue };
        let Some(expiry) = db::block_expiry(conn, ip) else { continue };
        if expiry.is_some_and(|t| t <= at) {
            continue;
        }
        let until = match expiry {
            Some(t) => format!(" until {}", crate::report::local_time(t)),
            None => String::new(),
        };
        let issue = &mut finding.issue;
        issue.severity = Severity::Info;
        issue.title = format!("{}, blocked", issue.title);
        let detail = issue.detail.take().unwrap_or_default();
        issue.detail = Some(format!("{detail}\n\nThe address is blocked{until}, and these are the attempts from before."));
        issue.actions = vec![Action::ignore()];
    }
}

/// The addresses over the limit that may be blocked.
fn candidates(conn: &Connection, findings: &[Finding], after: u32) -> Vec<(String, u32)> {
    findings
        .iter()
        .filter(|f| f.issue.severity != Severity::Info)
        .filter_map(|f| match &f.target {
            IssueTarget::LoginAttempts { ip, failures } if *failures >= after => Some((ip.clone(), *failures)),
            _ => None,
        })
        .filter(|(ip, _)| ip.parse::<IpAddr>().is_ok_and(|parsed| !geoip::is_private(&parsed)))
        .filter(|(ip, _)| !db::ip_trusted(conn, ip))
        .collect()
}

/// Blocks or offers to block every address over the limit.
pub fn respond(conn: &Connection, findings: &mut Vec<Finding>, after: u32, at: i64) {
    let over = candidates(conn, findings, after);
    if over.is_empty() {
        return;
    }
    let ips: Vec<String> = over.iter().map(|(ip, _)| ip.clone()).collect();

    // Root needs no password, so the block happens now.
    if platform::is_elevated() {
        match block_all(conn, &ips, after) {
            Ok(_) => {
                mark_blocked(conn, findings, at);
                return;
            }
            Err(e) => findings.push(Finding::note(Issue {
                kind: IssueKind::ModuleUnavailable,
                severity: Severity::Info,
                title: "The automatic block did not work".to_string(),
                location: "Automatic response".to_string(),
                detail: Some(e),
                actions: vec![Action::ignore()],
                ..Default::default()
            })),
        }
    }

    let list: Vec<String> = over.iter().map(|(ip, n)| format!("  {ip}, {n} failures")).collect();
    let count = ips.len();
    findings.push(Finding::new(
        Issue {
            kind: IssueKind::FailedLoginAttempts,
            severity: Severity::Warning,
            title: if count == 1 {
                "Block the address that keeps trying to log in".to_string()
            } else {
                format!("Block the {count} addresses that keep trying to log in")
            },
            location: "Automatic response".to_string(),
            detail: Some(format!(
                "These went over {after} failed logins in the last 24 hours:\n{}\n\n\
                 One button blocks them all, with one password. Each block lifts after {BLOCK_HOURS} hours, \
                 or sooner from the action log.",
                list.join("\n")
            )),
            actions: vec![Action::new("block_all", &format!("Block for {BLOCK_HOURS} hours"), false), Action::ignore()],
            ..Default::default()
        },
        IssueTarget::BlockProposal { ips },
    ));
}

/// Blocks a list of addresses for a day, in one call to the firewall.
pub fn block_all(conn: &Connection, ips: &[String], after: u32) -> Result<usize, String> {
    let mut parsed = Vec::new();
    for raw in ips {
        let ip: IpAddr = raw.trim().parse().map_err(|_| format!("{raw} is not an IP address."))?;
        if geoip::is_private(&ip) {
            return Err(format!("{ip} is on your own network, so it is not blocked."));
        }
        parsed.push(ip);
    }
    if parsed.is_empty() {
        return Err("There is no address to block.".to_string());
    }

    platform::block_for(&parsed, BLOCK_HOURS)?;

    let expires = db::now() + BLOCK_HOURS * 3600;
    let reason = format!("over {after} failed logins; lifts after {BLOCK_HOURS} hours");
    for ip in &parsed {
        let ip = ip.to_string();
        let _ = db::put_block(conn, &ip, Some(expires));
        actionlog::record(conn, actionlog::kind::AUTO_BLOCK, &ip, Some(&reason), true);
    }
    Ok(parsed.len())
}

/// Takes an automatic block back before its day is over.
pub fn lift(conn: &Connection, raw: &str) -> Result<String, String> {
    let ip: IpAddr = raw.trim().parse().map_err(|_| format!("{raw} is not an IP address."))?;
    let text = ip.to_string();
    if let Some(Some(expires)) = db::block_expiry(conn, &text) {
        if expires <= db::now() && platform::BLOCKS_EXPIRE {
            let _ = db::remove_block(conn, &text);
            return Ok(format!("The block on {text} had already lifted."));
        }
    }
    platform::unblock_for(&ip)?;
    let _ = db::remove_block(conn, &text);
    actionlog::record(conn, actionlog::kind::UNBLOCK_IP, &text, Some("automatic block lifted"), false);
    Ok(format!("{text} is no longer blocked."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempts(ip: &str, failures: u32) -> Finding {
        Finding::new(
            Issue {
                kind: IssueKind::FailedLoginAttempts,
                severity: Severity::Warning,
                title: format!("{failures} failed login attempts from {ip}"),
                ..Default::default()
            },
            IssueTarget::LoginAttempts { ip: ip.into(), failures },
        )
    }

    #[test]
    fn only_strangers_over_the_limit_are_offered() {
        let conn = db::open_memory();
        db::set_ip_trust(&conn, "185.220.101.9", true, None).unwrap();
        let findings = vec![
            attempts("185.220.101.1", 30),
            attempts("185.220.101.2", 3),
            attempts("185.220.101.9", 40),
            attempts("192.168.1.9", 99),
        ];
        let over = candidates(&conn, &findings, 10);
        assert_eq!(over, vec![("185.220.101.1".to_string(), 30)]);
    }

    #[test]
    fn a_blocked_address_is_a_note_until_its_block_lifts() {
        let conn = db::open_memory();
        db::put_block(&conn, "185.220.101.1", Some(5_000)).unwrap();

        let mut before = vec![attempts("185.220.101.1", 30)];
        mark_blocked(&conn, &mut before, 4_000);
        assert_eq!(before[0].issue.severity, Severity::Info);
        assert!(candidates(&conn, &before, 10).is_empty(), "a blocked address is not offered again");

        let mut after = vec![attempts("185.220.101.1", 30)];
        mark_blocked(&conn, &mut after, 5_000);
        assert_eq!(after[0].issue.severity, Severity::Warning);
    }

    #[test]
    fn the_offer_is_one_issue_for_every_address() {
        if platform::is_elevated() {
            return;
        }
        let conn = db::open_memory();
        let mut findings = vec![attempts("185.220.101.1", 30), attempts("185.220.101.2", 12)];
        respond(&conn, &mut findings, 10, 1_000);
        let IssueTarget::BlockProposal { ips } = &findings.last().unwrap().target else {
            panic!("no offer to block");
        };
        assert_eq!(ips.len(), 2);
        assert!(actionlog::list(&conn, 10).unwrap().is_empty(), "nothing is blocked without asking");
    }

    #[test]
    fn nothing_on_the_own_network_reaches_the_firewall() {
        let conn = db::open_memory();
        assert!(block_all(&conn, &["10.0.0.4".into()], 10).unwrap_err().contains("own network"));
        assert!(block_all(&conn, &["1.2.3.4; reboot".into()], 10).unwrap_err().contains("not an IP"));
        assert!(block_all(&conn, &[], 10).is_err());
    }
}
