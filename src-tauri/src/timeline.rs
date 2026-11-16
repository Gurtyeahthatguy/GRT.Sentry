//! What changed on the machine between two scans: files in the scan folders,
//! what starts by itself, accounts and installed packages.
//!
//! Each scan records what it found per kind and keeps the difference from the
//! scan before. The first scan of a kind only records, since everything would
//! otherwise be new. Changes are facts, not problems: they answer "what is
//! different since Tuesday" after a suspicion, and raise no alarm.

use std::collections::{BTreeMap, HashMap};

use rusqlite::Connection;
use serde::Serialize;

use crate::db::{self, MachineChange};

/// Changes kept per kind and scan; a folder that was emptied says so in one line.
const MAX_CHANGES: usize = 2000;

pub const FILES: &str = "file";
pub const STARTUP: &str = "startup";
pub const ACCOUNTS: &str = "account";
pub const PACKAGES: &str = "package";

/// The difference between what was recorded and what is there now.
pub fn diff(kind: &str, before: &BTreeMap<String, String>, now: &BTreeMap<String, String>) -> Vec<MachineChange> {
    let mut changes = Vec::new();
    for (key, value) in now {
        match before.get(key) {
            None => changes.push(MachineChange { kind: kind.into(), key: key.clone(), before: None, after: Some(value.clone()) }),
            Some(old) if old != value => changes.push(MachineChange {
                kind: kind.into(),
                key: key.clone(),
                before: Some(old.clone()),
                after: Some(value.clone()),
            }),
            _ => {}
        }
    }
    for (key, value) in before {
        if !now.contains_key(key) {
            changes.push(MachineChange { kind: kind.into(), key: key.clone(), before: Some(value.clone()), after: None });
        }
    }
    if changes.len() > MAX_CHANGES {
        let extra = changes.len() - MAX_CHANGES;
        changes.truncate(MAX_CHANGES);
        changes.push(MachineChange {
            kind: kind.into(),
            key: format!("and {extra} more"),
            before: None,
            after: None,
        });
    }
    changes
}

/// Records one kind for a scan, and says how many changes it found.
pub fn record(conn: &Connection, scan_id: i64, kind: &str, now: &BTreeMap<String, String>) -> Result<usize, String> {
    let changes = match db::machine_state(conn, kind)? {
        Some(before) => diff(kind, &before, now),
        None => Vec::new(),
    };
    db::put_machine_state(conn, scan_id, kind, now, &changes)?;
    Ok(changes.len())
}

/// What a scan saw, gathered so it can be recorded in one go.
#[derive(Default)]
pub struct Seen {
    /// `None` when the scan walked other folders than the configured ones, or
    /// was stopped, so a missing file would not mean a removed one.
    pub files: Option<BTreeMap<String, String>>,
    pub startup: Option<BTreeMap<String, String>>,
    pub accounts: Option<BTreeMap<String, String>>,
    pub packages: Option<BTreeMap<String, String>>,
}

/// Reads what is not already in hand: startup entries, accounts, packages.
pub fn gather(files: Option<BTreeMap<String, String>>) -> Seen {
    let startup = crate::autostart::list().into_iter().map(|e| (e.key, e.command)).collect();
    Seen {
        files,
        startup: Some(startup),
        accounts: crate::platform::account_list(),
        packages: crate::platform::installed_packages(),
    }
}

/// Records everything a scan saw, and says how many changes there were.
pub fn record_all(conn: &Connection, scan_id: i64, seen: &Seen) -> usize {
    let mut total = 0;
    for (kind, now) in [(FILES, &seen.files), (STARTUP, &seen.startup), (ACCOUNTS, &seen.accounts), (PACKAGES, &seen.packages)] {
        let Some(now) = now else { continue };
        match record(conn, scan_id, kind, now) {
            Ok(n) => total += n,
            Err(e) => eprintln!("grt-sentry: the record of {kind}s could not be kept: {e}"),
        }
    }
    total
}

/// The net effect of the changes over a range of scans, per key.
///
/// Something added and removed again in between is left out; something changed
/// twice shows where it started and where it ended.
pub fn collapse(changes: Vec<MachineChange>) -> Vec<MachineChange> {
    let mut order: Vec<(String, String)> = Vec::new();
    let mut net: HashMap<(String, String), MachineChange> = HashMap::new();
    for change in changes {
        let id = (change.kind.clone(), change.key.clone());
        match net.get_mut(&id) {
            Some(first) => first.after = change.after,
            None => {
                order.push(id.clone());
                net.insert(id, change);
            }
        }
    }
    order
        .into_iter()
        .filter_map(|id| net.remove(&id))
        .filter(|c| c.before != c.after || c.key.starts_with("and "))
        .collect()
}

/// A heading for each kind, in the order a report lists them.
pub fn heading(kind: &str) -> &'static str {
    match kind {
        STARTUP => "What starts by itself",
        ACCOUNTS => "Accounts",
        PACKAGES => "Installed packages",
        FILES => "Files in the scan folders",
        _ => "Other",
    }
}

pub const ORDER: [&str; 4] = [STARTUP, ACCOUNTS, PACKAGES, FILES];

/// One line for a change, as the report and the interface say it.
pub fn sentence(change: &MachineChange) -> String {
    let short = |value: &str| -> String {
        if change.kind == FILES {
            format!("contents {}", value.chars().take(12).collect::<String>())
        } else {
            value.chars().take(160).collect()
        }
    };
    match (&change.before, &change.after) {
        (None, None) => change.key.clone(),
        (None, Some(after)) => format!("added: {} ({})", change.key, short(after)),
        (Some(_), None) => format!("removed: {}", change.key),
        (Some(before), Some(after)) => format!("changed: {} ({} before, {} now)", change.key, short(before), short(after)),
    }
}

/// Changes grouped for the interface.
#[derive(Serialize, Debug)]
pub struct Group {
    pub kind: String,
    pub heading: String,
    pub lines: Vec<String>,
}

pub fn grouped(changes: &[MachineChange]) -> Vec<Group> {
    ORDER
        .iter()
        .filter_map(|kind| {
            let lines: Vec<String> = changes.iter().filter(|c| c.kind == *kind).map(sentence).collect();
            (!lines.is_empty()).then(|| Group { kind: kind.to_string(), heading: heading(kind).to_string(), lines })
        })
        .collect()
}

// --- readers the platforms share --------------------------------------------

/// Installed packages from dpkg's status file, name to version.
#[cfg_attr(windows, allow(dead_code))]
pub fn parse_dpkg_status(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for stanza in text.split("\n\n") {
        let field = |name: &str| {
            stanza.lines().find_map(|l| l.strip_prefix(name).map(|v| v.trim().to_string()))
        };
        let (Some(name), Some(status), Some(version)) = (field("Package:"), field("Status:"), field("Version:")) else {
            continue;
        };
        if !status.ends_with(" installed") {
            continue;
        }
        let arch = field("Architecture:").unwrap_or_default();
        let key = if out.contains_key(&name) { format!("{name}:{arch}") } else { name };
        out.insert(key, version);
    }
    out
}

/// `rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n'`, name to version.
#[cfg_attr(windows, allow(dead_code))]
pub fn parse_rpm_list(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| l.split_once('\t'))
        .map(|(name, version)| (name.trim().to_string(), version.trim().to_string()))
        .filter(|(name, _)| !name.is_empty())
        .collect()
}

/// `reg query ...\Uninstall /s`, display name to display version.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn parse_uninstall_keys(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for block in text.split("\nHKEY_").skip(1).chain(text.starts_with("HKEY_").then_some(text)) {
        let value = |name: &str| {
            block.lines().find_map(|l| {
                let mut parts = l.trim().splitn(3, "    ");
                (parts.next()? == name).then(|| parts.nth(1).map(|v| v.trim().to_string())).flatten()
            })
        };
        if let Some(name) = value("DisplayName") {
            out.insert(name, value("DisplayVersion").unwrap_or_default());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn the_first_scan_records_and_the_second_names_what_changed() {
        let conn = db::open_memory();
        let one = db::record_scan(&conn, 0, 0).unwrap();
        assert_eq!(record(&conn, one, PACKAGES, &map(&[("bash", "5.2"), ("curl", "8.5")])).unwrap(), 0);

        let two = db::record_scan(&conn, 0, 0).unwrap();
        let n = record(&conn, two, PACKAGES, &map(&[("bash", "5.3"), ("nmap", "7.9")])).unwrap();
        assert_eq!(n, 3);
        let changes = db::machine_changes(&conn, one, two).unwrap();
        let lines: Vec<String> = changes.iter().map(sentence).collect();
        assert!(lines.contains(&"changed: bash (5.2 before, 5.3 now)".to_string()), "{lines:?}");
        assert!(lines.contains(&"added: nmap (7.9)".to_string()));
        assert!(lines.contains(&"removed: curl".to_string()));
    }

    #[test]
    fn over_several_scans_only_the_net_change_is_told() {
        let change = |key: &str, before: Option<&str>, after: Option<&str>| MachineChange {
            kind: STARTUP.into(),
            key: key.into(),
            before: before.map(str::to_string),
            after: after.map(str::to_string),
        };
        let net = collapse(vec![
            change("tmp", None, Some("x")),
            change("svc", Some("a"), Some("b")),
            change("tmp", Some("x"), None),
            change("svc", Some("b"), Some("c")),
            change("flip", Some("a"), Some("b")),
            change("flip", Some("b"), Some("a")),
        ]);
        assert_eq!(net, vec![change("svc", Some("a"), Some("c"))]);
    }

    #[test]
    fn a_flood_of_changes_is_capped_and_says_so() {
        let before = BTreeMap::new();
        let now: BTreeMap<String, String> = (0..MAX_CHANGES + 5).map(|n| (format!("/f{n}"), "h".into())).collect();
        let changes = diff(FILES, &before, &now);
        assert_eq!(changes.len(), MAX_CHANGES + 1);
        assert_eq!(changes.last().unwrap().key, "and 5 more");
    }

    #[test]
    fn package_lists_are_read_from_each_system() {
        let dpkg = "Package: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 5.2-1\n\n\
                    Package: old\nStatus: deinstall ok config-files\nVersion: 1\n\n\
                    Package: libc6\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.40\n\n\
                    Package: libc6\nStatus: install ok installed\nArchitecture: i386\nVersion: 2.40\n";
        let packages = parse_dpkg_status(dpkg);
        assert_eq!(packages.get("bash").map(String::as_str), Some("5.2-1"));
        assert!(!packages.contains_key("old"));
        assert!(packages.contains_key("libc6") && packages.contains_key("libc6:i386"));

        assert_eq!(parse_rpm_list("bash\t5.2-3.fc40\n").get("bash").map(String::as_str), Some("5.2-3.fc40"));

        let reg = "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\7-Zip\r\n    DisplayName    REG_SZ    7-Zip 23.01 (x64)\r\n    DisplayVersion    REG_SZ    23.01\r\n\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Empty\r\n    NoRemove    REG_DWORD    0x1\r\n";
        let windows = parse_uninstall_keys(&reg.replace("\r\n", "\n"));
        assert_eq!(windows.get("7-Zip 23.01 (x64)").map(String::as_str), Some("23.01"));
        assert_eq!(windows.len(), 1);
    }
}
