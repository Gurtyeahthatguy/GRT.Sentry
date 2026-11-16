//! Windows security events, from `wevtutil qe Security /f:xml`.
//!
//! The XML is read rather than the text rendering, because the text is
//! translated into the system's language and the field names in the XML are
//! not. Three events matter here: 4625, a failed logon; 4720, an account
//! created; 4732, a member added to a local group.

use rusqlite::Connection;

use crate::authlog::Failure;
use crate::db;
use crate::state::{Action, Finding, Issue, IssueKind, IssueTarget, Severity};

/// What one event said.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    FailedLogon { timestamp: i64, address: Option<String>, user: Option<String> },
    AccountCreated { timestamp: i64, name: String, sid: String },
    AddedToGroup { timestamp: i64, member: String, group: String, group_sid: String },
}

/// The groups whose members hold the machine.
const POWERFUL: &[(&str, &str)] = &[
    ("S-1-5-32-544", "Administrators"),
    ("S-1-5-32-555", "Remote Desktop Users"),
    ("S-1-5-32-551", "Backup Operators"),
    ("S-1-5-32-580", "Remote Management Users"),
];

/// How far back account events are read: they are rare and worth a week.
const ACCOUNT_WINDOW: i64 = 7 * 24 * 60 * 60;

fn unescape(text: &str) -> String {
    text.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

/// The text of `<Data Name='field'>`, with either quote.
fn data(event: &str, field: &str) -> Option<String> {
    for quote in ['\'', '"'] {
        let open = format!("<Data Name={quote}{field}{quote}>");
        if let Some(start) = event.find(&open) {
            let rest = &event[start + open.len()..];
            let end = rest.find("</Data>")?;
            let value = unescape(rest[..end].trim());
            return (!value.is_empty() && value != "-").then_some(value);
        }
    }
    None
}

fn event_id(event: &str) -> Option<u32> {
    let start = event.find("<EventID")?;
    let rest = &event[start..];
    let open_end = rest.find('>')?;
    let close = rest.find("</EventID>")?;
    rest.get(open_end + 1..close)?.trim().parse().ok()
}

fn timestamp(event: &str) -> Option<i64> {
    let start = event.find("SystemTime=")? + "SystemTime=".len();
    let quote = event[start..].chars().next().filter(|c| *c == '\'' || *c == '"')?;
    let rest = &event[start + 1..];
    let end = rest.find(quote)?;
    chrono::DateTime::parse_from_rfc3339(&rest[..end]).ok().map(|t| t.timestamp())
}

/// Every event in the output, in the order given.
pub fn parse(xml: &str, now: i64) -> Vec<Event> {
    xml.split("<Event ")
        .skip(1)
        .filter_map(|event| {
            let at = timestamp(event).unwrap_or(now);
            match event_id(event)? {
                4625 => Some(Event::FailedLogon {
                    timestamp: at,
                    address: data(event, "IpAddress").and_then(|a| a.parse::<std::net::IpAddr>().ok()).map(|a| a.to_string()),
                    user: data(event, "TargetUserName"),
                }),
                4720 => Some(Event::AccountCreated {
                    timestamp: at,
                    name: data(event, "TargetUserName")?,
                    sid: data(event, "TargetSid").unwrap_or_default(),
                }),
                4732 => Some(Event::AddedToGroup {
                    timestamp: at,
                    member: data(event, "MemberName").or_else(|| data(event, "MemberSid"))?,
                    group: data(event, "TargetUserName").unwrap_or_default(),
                    group_sid: data(event, "TargetSid").unwrap_or_default(),
                }),
                _ => None,
            }
        })
        .collect()
}

/// Whether a record is the event log's XML rather than a Linux log.
pub fn is_event_xml(text: &str) -> bool {
    text.trim_start().starts_with("<Event")
}

/// The failed logons, in the shape the Linux log gives them.
pub fn failures(events: &[Event]) -> Vec<Failure> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::FailedLogon { timestamp, address, user } => {
                Some(Failure { timestamp: *timestamp, address: address.clone(), user: user.clone() })
            }
            _ => None,
        })
        .collect()
}

/// New accounts and new members of the groups that matter, until accepted.
pub fn account_findings(conn: &Connection, events: &[Event], now: i64) -> Vec<Finding> {
    let mut out = Vec::new();
    for event in events {
        match event {
            Event::AccountCreated { timestamp, name, sid } if now - timestamp <= ACCOUNT_WINDOW => {
                let key = if sid.is_empty() { name.clone() } else { sid.clone() };
                if db::baseline_value(conn, "win_account", &key).is_some() {
                    continue;
                }
                out.push(Finding::new(
                    Issue {
                        kind: IssueKind::AccountActivity,
                        severity: Severity::Warning,
                        title: format!("New account: {name}"),
                        location: "Security event 4720".to_string(),
                        detail: Some(format!(
                            "The account {name} was created on {}. A new user set up on purpose explains it; an account nobody made is how an intruder keeps a way back in.",
                            crate::report::local_time(*timestamp)
                        )),
                        actions: vec![Action::new("trust", "Expected", false), Action::ignore()],
                        ..Default::default()
                    },
                    IssueTarget::Baseline { kind: "win_account".into(), key, value: name.clone() },
                ));
            }
            Event::AddedToGroup { timestamp, member, group, group_sid } if now - timestamp <= ACCOUNT_WINDOW => {
                let key = format!("{group_sid}|{member}");
                if db::baseline_value(conn, "win_group_member", &key).is_some() {
                    continue;
                }
                let powerful = POWERFUL.iter().find(|(sid, _)| sid == group_sid);
                let group_name = powerful.map(|(_, name)| name.to_string()).unwrap_or_else(|| group.clone());
                out.push(Finding::new(
                    Issue {
                        kind: IssueKind::AccountActivity,
                        severity: if powerful.is_some() { Severity::Critical } else { Severity::Info },
                        title: format!("{member} was added to {group_name}"),
                        location: "Security event 4732".to_string(),
                        detail: Some(format!(
                            "On {}, {member} became a member of {group_name}.{}",
                            crate::report::local_time(*timestamp),
                            if powerful.is_some() {
                                " Members of this group control the machine, so it is either a deliberate change or the step an intruder takes right after getting in."
                            } else {
                                ""
                            }
                        )),
                        actions: vec![Action::new("trust", "Expected", false), Action::ignore()],
                        ..Default::default()
                    },
                    IssueTarget::Baseline { kind: "win_group_member".into(), key, value: "seen".into() },
                ));
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_787_000_000;

    fn event(id: u32, fields: &[(&str, &str)]) -> String {
        let time = chrono::DateTime::from_timestamp(NOW - 600, 0).unwrap().to_rfc3339();
        let data: String = fields.iter().map(|(k, v)| format!("<Data Name='{k}'>{v}</Data>")).collect();
        format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/>\
             <EventID>{id}</EventID><TimeCreated SystemTime='{time}'/></System><EventData>{data}</EventData></Event>"
        )
    }

    #[test]
    fn the_three_events_are_read_whatever_the_language() {
        let xml = [
            event(4625, &[("TargetUserName", "administrator"), ("IpAddress", "185.220.101.7"), ("IpPort", "0")]),
            event(4625, &[("TargetUserName", "bob"), ("IpAddress", "-")]),
            event(4720, &[("TargetUserName", "helper"), ("TargetSid", "S-1-5-21-1-2-3-1009")]),
            event(4732, &[("MemberName", "-"), ("MemberSid", "S-1-5-21-1-2-3-1009"), ("TargetUserName", "Administratoren"), ("TargetSid", "S-1-5-32-544")]),
            event(4624, &[("TargetUserName", "me")]),
        ]
        .join("\r\n");
        let events = parse(&xml, NOW);
        assert_eq!(events.len(), 4);
        assert_eq!(
            events[0],
            Event::FailedLogon { timestamp: NOW - 600, address: Some("185.220.101.7".into()), user: Some("administrator".into()) }
        );
        assert_eq!(failures(&events)[1].address, None, "a local failure has no address");

        let conn = db::open_memory();
        let found = account_findings(&conn, &events, NOW);
        let titles: Vec<_> = found.iter().map(|f| f.issue.title.clone()).collect();
        assert_eq!(titles, vec!["New account: helper", "S-1-5-21-1-2-3-1009 was added to Administrators"]);
        assert_eq!(found[1].issue.severity, Severity::Critical, "the group is known by its SID, not its translated name");

        crate::resolve::accept_baseline(&conn, "win_account", "S-1-5-21-1-2-3-1009", "helper").unwrap();
        assert_eq!(account_findings(&conn, &events, NOW).len(), 1);
    }

    #[test]
    fn damaged_xml_is_skipped_without_a_panic() {
        for broken in ["<Event <EventID</EventID>", "<Event x SystemTime=é", "<Event <EventID>4625", "<Event <Data Name='IpAddress'>"] {
            assert!(parse(broken, NOW).is_empty() || matches!(parse(broken, NOW)[0], Event::FailedLogon { .. }));
        }
    }

    #[test]
    fn the_failures_feed_the_same_count_as_on_linux() {
        let xml: String = (0..6).map(|_| event(4625, &[("IpAddress", "185.220.101.7")])).collect();
        let found = crate::authlog::findings_from_text(&xml, 5, NOW);
        assert_eq!(found.len(), 1);
        assert!(found[0].issue.title.contains("6 failed login attempts from 185.220.101.7"));
    }
}
