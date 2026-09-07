//! Everything GRT Sentry did, and when.
//!
//! The log is what makes an action repairable: a blocked address that turned
//! out to be wanted is found and undone from here. Every function in
//! `quarantine.rs` and `resolve.rs` records after the action succeeded, so
//! the log says what happened rather than what was attempted.

use rusqlite::Connection;

use crate::db::{self, ActionRecord};

/// The action names used in the log.
pub mod kind {
    pub const QUARANTINE: &str = "quarantine";
    pub const RESTORE: &str = "restore";
    pub const DELETE: &str = "delete";
    pub const BLOCK_IP: &str = "block_ip";
    pub const UNBLOCK_IP: &str = "unblock_ip";
    pub const KILL_PROCESS: &str = "kill_process";
    pub const CLOSE_CONNECTION: &str = "close_connection";
    pub const TRUST_FILE: &str = "trust_file";
    pub const UNTRUST_FILE: &str = "untrust_file";
    pub const TRUST_IP: &str = "trust_ip";
    pub const UPDATE_BASELINE: &str = "update_baseline";
    pub const UPLOAD_VT: &str = "upload_vt";
}

/// Writes one line.
///
/// A log that cannot be written is reported to the console and nothing more:
/// the action itself already succeeded.
pub fn record(conn: &Connection, action: &str, target: &str, reason: Option<&str>, reversible: bool) -> i64 {
    match db::record_action(conn, action, target, reason, reversible) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("grt-sentry: could not write to the action log: {e}");
            -1
        }
    }
}

pub fn list(conn: &Connection, limit: u32) -> Result<Vec<ActionRecord>, String> {
    db::list_actions(conn, limit.clamp(1, 5000))
}

/// Marks an entry as undone, after the owning module has undone it.
pub fn mark_reverted(conn: &Connection, id: i64) -> Result<(), String> {
    db::mark_action_reverted(conn, id)
}

/// The sentence the interface shows for an entry.
pub fn describe(record: &ActionRecord) -> String {
    let what = match record.action.as_str() {
        kind::QUARANTINE => "Quarantined",
        kind::RESTORE => "Restored",
        kind::DELETE => "Deleted",
        kind::BLOCK_IP => "Blocked",
        kind::UNBLOCK_IP => "Unblocked",
        kind::KILL_PROCESS => "Stopped",
        kind::CLOSE_CONNECTION => "Closed the connection to",
        kind::TRUST_FILE => "Trusted",
        kind::UNTRUST_FILE => "Stopped trusting",
        kind::TRUST_IP => "Trusted",
        kind::UPDATE_BASELINE => "Updated the reference hash for",
        kind::UPLOAD_VT => "Sent for analysis",
        other => other,
    };
    format!("{what} {}", record.target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recorded_action_can_be_found_and_undone() {
        let conn = crate::db::open_memory();
        let id = record(&conn, kind::BLOCK_IP, "185.220.101.7", Some("first sighting"), true);
        assert!(id > 0);

        let entries = list(&conn, 10).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].reversible);
        assert!(!entries[0].reverted);
        assert_eq!(describe(&entries[0]), "Blocked 185.220.101.7");

        mark_reverted(&conn, id).unwrap();
        assert!(list(&conn, 10).unwrap()[0].reverted);
    }

    #[test]
    fn closing_a_connection_reads_as_a_sentence() {
        let conn = crate::db::open_memory();
        record(&conn, kind::CLOSE_CONNECTION, "185.220.101.7:443", None, false);
        let entries = list(&conn, 10).unwrap();
        assert_eq!(describe(&entries[0]), "Closed the connection to 185.220.101.7:443");
        assert!(!entries[0].reversible, "a closed socket cannot be reopened");
    }

    #[test]
    fn an_unknown_action_still_produces_a_line_rather_than_nothing() {
        let conn = crate::db::open_memory();
        record(&conn, "something_new", "/tmp/x", None, false);
        let entries = list(&conn, 10).unwrap();
        assert_eq!(describe(&entries[0]), "something_new /tmp/x");
    }
}
