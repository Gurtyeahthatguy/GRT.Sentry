//! What this machine is talking to, right now.
//!
//! The socket list comes from `platform`, which reads it from `/proc` on Linux
//! and from the Win32 socket table on Windows. What this module adds is the
//! history and the location: whether the address has been seen before, whether
//! it is trusted, and where the network announcing it is registered.
//!
//! Nothing here polls. A refresh happens on request, or on the interval set in
//! the settings, which is off by default.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::db;
use crate::geoip::{self, GeoDb, GeoInfo};
use crate::platform::{self, TargetSocket};
use crate::state::{Action, Finding, Issue, IssueKind, IssueTarget, Severity};

/// One socket, named by the four values that identify it to the kernel.
///
/// It travels to the frontend and comes back when Close is pressed, so
/// `resolve.rs` parses every field again on the way in.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SocketRef {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
}

impl SocketRef {
    /// "185.220.101.7:443"
    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.remote_addr, self.remote_port)
    }

    /// Checks every field and produces the form the system call needs.
    ///
    /// The interface is given these values by this program, so in ordinary use
    /// they are already right. Parsing them again means the addresses that
    /// reach the kernel, or a firewall command, cannot be anything else.
    pub fn validated(&self) -> Result<TargetSocket, String> {
        let tcp = match self.protocol.as_str() {
            "tcp" | "tcp6" => true,
            "udp" | "udp6" => false,
            other => return Err(format!("{other} is not a protocol this can close.")),
        };

        if self.local_port == 0 || self.remote_port == 0 {
            return Err("A socket with no port is not a connection.".to_string());
        }

        Ok(TargetSocket {
            tcp,
            local: self
                .local_addr
                .parse()
                .map_err(|_| format!("{} is not an IP address.", self.local_addr))?,
            local_port: self.local_port,
            remote: self
                .remote_addr
                .parse()
                .map_err(|_| format!("{} is not an IP address.", self.remote_addr))?,
            remote_port: self.remote_port,
        })
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct Connection {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: Option<i32>,
    pub process_name: Option<String>,
    /// `None` for private addresses, and when GeoLite2 is not installed.
    pub location: Option<GeoInfo>,
    /// The address had never been seen before this snapshot.
    pub is_new: bool,
    /// Marked as expected by the user.
    pub trusted: bool,
    /// A machine on the local network, or this one.
    pub private: bool,
    /// The note attached to the address.
    pub label: Option<String>,
}

impl Connection {
    /// The four values that identify this socket to the kernel.
    pub fn socket(&self) -> SocketRef {
        SocketRef {
            protocol: self.protocol.clone(),
            local_addr: self.local_addr.clone(),
            local_port: self.local_port,
            remote_addr: self.remote_addr.clone(),
            remote_port: self.remote_port,
        }
    }

    /// "firefox (pid 4821) to 185.220.101.7:443"
    pub fn describe(&self) -> String {
        let who = match (&self.process_name, self.pid) {
            (Some(name), Some(pid)) => format!("{name} (pid {pid})"),
            (None, Some(pid)) => format!("pid {pid}"),
            _ => "unidentified process".to_string(),
        };
        format!("{who} to {}:{}", self.remote_addr, self.remote_port)
    }
}

/// One row per socket, enriched with process, location and history.
pub fn snapshot(conn: &rusqlite::Connection, geo: Option<&GeoDb>) -> Result<Vec<Connection>, String> {
    let mut out = Vec::new();

    for raw in platform::sockets()? {
        let remote_ip = platform::normalise(raw.remote_addr);
        let private = geoip::is_private(&remote_ip);
        let remote_addr = remote_ip.to_string();

        // Private addresses are not recorded as seen.
        let (is_new, trusted, label) = if private {
            (false, true, None)
        } else {
            match db::observe_ip(conn, &remote_addr) {
                Ok(record) => (record.is_new, record.trusted, record.label),
                Err(_) => (false, false, None),
            }
        };

        out.push(Connection {
            protocol: raw.protocol.to_string(),
            local_addr: platform::normalise(raw.local_addr).to_string(),
            local_port: raw.local_port,
            remote_addr: remote_addr.clone(),
            remote_port: raw.remote_port,
            state: raw.state,
            pid: raw.pid,
            process_name: raw.process,
            location: if private { None } else { geo.and_then(|g| g.lookup(&remote_addr)) },
            is_new,
            trusted,
            private,
            label,
        });
    }

    Ok(out)
}

/// The sockets in a snapshot belonging to one address and one process.
///
/// An issue stands for a group of sockets, so acting on it acts on all.
pub fn sockets_for(connections: &[Connection], ip: &str, pid: Option<i32>) -> Vec<SocketRef> {
    connections
        .iter()
        .filter(|c| c.remote_addr == ip && (pid.is_none() || c.pid == pid))
        .map(|c| c.socket())
        .collect()
}

/// Ports that ordinary software uses.
///
/// Not a list of safe ports. It only decides whether a first sighting is
/// mentioned quietly or loudly.
fn is_common_port(port: u16) -> bool {
    matches!(
        port,
        20 | 21 | 22 | 25 | 53 | 80 | 110 | 143 | 123 | 443 | 465 | 587 | 853 | 993 | 995
            | 1900 | 3478 | 5222 | 5223 | 5228 | 5349 | 8080 | 8443
    )
}

/// The connections worth mentioning, grouped by address and owning process.
///
/// The number of sockets in a group goes in the detail line.
pub fn findings(connections: &[Connection]) -> Vec<Finding> {
    let mut grouped: Vec<(String, Option<i32>)> = Vec::new();
    let mut counts: HashMap<(String, Option<i32>), usize> = HashMap::new();

    for c in connections {
        if c.private || c.trusted {
            continue;
        }
        let key = (c.remote_addr.clone(), c.pid);
        if !counts.contains_key(&key) {
            grouped.push(key.clone());
        }
        *counts.entry(key).or_insert(0) += 1;
    }

    let mut findings = Vec::new();

    for key in grouped {
        let (ip, pid) = key.clone();
        let sockets = counts[&key];
        let sample = connections
            .iter()
            .find(|c| c.remote_addr == ip && c.pid == pid)
            .expect("the group came from this list");

        let unidentified = sample.process_name.is_none();
        let unusual_port = !is_common_port(sample.remote_port);

        // Nothing to say about a familiar address on a familiar port.
        if !sample.is_new && !unidentified {
            continue;
        }

        // Never Critical: the only claim being made is that this is new.
        let severity = if unidentified || (sample.is_new && unusual_port) {
            Severity::Warning
        } else {
            Severity::Info
        };

        let title = if unidentified {
            "Connection from an unidentified process".to_string()
        } else {
            "Connection to an address seen for the first time".to_string()
        };

        let mut detail = String::new();
        if let Some(location) = &sample.location {
            detail.push_str(&format!(
                "The address is announced from {} ({:.2}, {:.2}). That is where the network routing the connection is registered, not where a person is.\n",
                location.label(),
                location.lat,
                location.lon
            ));
        } else if sample.location.is_none() {
            detail.push_str("No location available for this address.\n");
        }
        if unidentified {
            detail.push_str(
                "The socket could not be traced to a process. Usually this means it belongs to another user or to a system service, which an unprivileged program cannot inspect.\n",
            );
        }
        if unusual_port {
            detail.push_str(&format!(
                "Port {} is not one of the ports everyday software normally uses.\n",
                sample.remote_port
            ));
        }
        if sockets > 1 {
            detail.push_str(&format!("{sockets} sockets are open to this address.\n"));
        }
        detail.push_str("A first sighting is not by itself a problem: every site is new once.");

        // Three degrees of force, in order: close the sockets, block the
        // address, stop the process.
        let mut actions = vec![
            Action::new("close_connection", "Close connection", true),
            Action::new("block_ip", "Block address", true),
            Action::new("trust", "Trust", false),
        ];
        if pid.is_some() {
            actions.insert(2, Action::new("kill_process", "Stop process", true));
        }
        actions.push(Action::ignore());

        findings.push(Finding::new(
            Issue {
                kind: IssueKind::SuspiciousConnection,
                severity,
                title,
                location: sample.describe(),
                detail: Some(detail),
                actions,
                ..Default::default()
            },
            IssueTarget::Connection { ip, pid, process: sample.process_name.clone() },
        ));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(ip: &str, port: u16, pid: Option<i32>, name: Option<&str>, is_new: bool) -> Connection {
        Connection {
            protocol: "tcp".into(),
            local_addr: "192.168.1.20".into(),
            local_port: 44321,
            remote_addr: ip.into(),
            remote_port: port,
            state: "Established".into(),
            pid,
            process_name: name.map(|s| s.to_string()),
            location: None,
            is_new,
            trusted: false,
            private: crate::geoip::is_private(&ip.parse().unwrap()),
            label: None,
        }
    }

    #[test]
    fn a_known_address_with_a_known_process_says_nothing() {
        let found = findings(&[conn("8.8.8.8", 443, Some(10), Some("firefox"), false)]);
        assert!(found.is_empty());
    }

    #[test]
    fn a_first_sighting_on_a_normal_port_is_only_information() {
        let found = findings(&[conn("8.8.8.8", 443, Some(10), Some("firefox"), true)]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].issue.severity, Severity::Info);
    }

    #[test]
    fn a_first_sighting_on_an_odd_port_is_worth_a_warning() {
        let found = findings(&[conn("185.220.101.7", 9001, Some(10), Some("node"), true)]);
        assert_eq!(found[0].issue.severity, Severity::Warning);
        assert!(found[0].issue.location.contains("node (pid 10)"));
    }

    #[test]
    fn a_socket_with_no_owner_is_reported_even_when_the_address_is_familiar() {
        let found = findings(&[conn("8.8.8.8", 443, None, None, false)]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].issue.severity, Severity::Warning);
    }

    #[test]
    fn the_local_network_is_never_reported() {
        let found = findings(&[
            conn("192.168.1.1", 53, Some(1), Some("systemd-resolve"), true),
            conn("127.0.0.1", 631, None, None, true),
        ]);
        assert!(found.is_empty());
    }

    #[test]
    fn a_trusted_address_stays_quiet() {
        let mut c = conn("185.220.101.7", 9001, Some(10), Some("node"), true);
        c.trusted = true;
        assert!(findings(&[c]).is_empty());
    }

    #[test]
    fn many_sockets_to_one_address_are_one_issue() {
        let found = findings(&[
            conn("185.220.101.7", 443, Some(10), Some("node"), true),
            conn("185.220.101.7", 443, Some(10), Some("node"), true),
            conn("185.220.101.7", 443, Some(10), Some("node"), true),
        ]);
        assert_eq!(found.len(), 1);
        assert!(found[0].issue.detail.as_ref().unwrap().contains("3 sockets"));
    }

    #[test]
    fn the_same_address_reached_by_two_processes_is_two_issues() {
        let found = findings(&[
            conn("185.220.101.7", 443, Some(10), Some("node"), true),
            conn("185.220.101.7", 443, Some(11), Some("curl"), true),
        ]);
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn a_real_snapshot_of_this_machine_is_readable() {
        // No assertion about the contents, since a quiet machine is a
        // legitimate outcome. The walk itself must work.
        let db = crate::db::open_memory();
        let list = snapshot(&db, None).expect("reading /proc/net must not fail");
        for c in &list {
            assert!(!(c.private && c.is_new), "a private address must not be treated as a stranger");
        }
    }
}
