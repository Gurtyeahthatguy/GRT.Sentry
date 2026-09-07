//! The actions: close, block, stop, delete, undo.
//!
//! Where GRT Sentry stops describing the machine and starts changing it. Every
//! function here is small and ends by writing to the action log.
//!
//! The firewall is the system's own: an nftables set on Linux, a Windows
//! Defender Firewall rule on Windows. There is no packet engine and no driver
//! here, so removing GRT Sentry leaves a firewall that still works.

use std::net::IpAddr;
use std::path::Path;

use rusqlite::Connection;

use crate::actionlog;
use crate::db;
use crate::geoip;
use crate::netmon::SocketRef;
use crate::platform;

/// Adds an address to the set the system firewall drops traffic to.
///
/// What reaches the firewall is the parsed address printed back out, never the
/// string that arrived.
pub fn block_ip(conn: &Connection, raw: &str) -> Result<(), String> {
    let ip: IpAddr = raw.trim().parse().map_err(|_| format!("{raw} is not an IP address."))?;

    // Blocking the router or this machine itself would cut off its own user.
    if geoip::is_private(&ip) {
        return Err(format!(
            "{ip} is on your own network. Blocking it would cut off your own machines rather than a stranger."
        ));
    }

    platform::block_address(&ip)?;
    actionlog::record(conn, actionlog::kind::BLOCK_IP, &ip.to_string(), Some("blocked from the dashboard"), true);
    Ok(())
}

/// Takes an address back out of the blocked set.
pub fn unblock_ip(conn: &Connection, raw: &str) -> Result<(), String> {
    let ip: IpAddr = raw.trim().parse().map_err(|_| format!("{raw} is not an IP address."))?;
    platform::unblock_address(&ip)?;
    actionlog::record(conn, actionlog::kind::UNBLOCK_IP, &ip.to_string(), Some("unblocked"), false);
    Ok(())
}

/// Asks a process to stop, with SIGTERM rather than SIGKILL.
///
/// Pids are reused, so the pid must still exist and, when the scan recorded a
/// name, the process must still carry it.
pub fn kill_process(conn: &Connection, pid: i32, expected_name: Option<&str>) -> Result<(), String> {
    if pid <= 1 {
        return Err("That is not a process this program will signal.".to_string());
    }

    if !platform::process_exists(pid) {
        return Err(format!("Process {pid} has already ended."));
    }

    if let Some(expected) = expected_name {
        if let Some(current) = platform::process_name(pid) {
            if !current.is_empty() && !names_match(&current, expected) {
                return Err(format!(
                    "Process {pid} is now {current}, not {expected}. It ended and the number was reused, so nothing was signalled."
                ));
            }
        }
    }

    platform::stop_process(pid)?;
    actionlog::record(
        conn,
        actionlog::kind::KILL_PROCESS,
        &format!("{} (pid {pid})", expected_name.unwrap_or("process")),
        Some("stopped from the dashboard"),
        false,
    );
    Ok(())
}

/// Closes connections without touching the process that opened them.
///
/// The program stays running and can open another connection a second later,
/// which is what blocking the address is for.
///
/// The system does the work: `ss --kill` on Linux, `SetTcpEntry` on Windows.
/// Neither reliably says whether it succeeded, so the result is confirmed by
/// reading the socket table back.
pub fn close_connections(conn: &Connection, sockets: &[SocketRef]) -> Result<usize, String> {
    if sockets.is_empty() {
        return Err("There is no connection to close.".to_string());
    }

    let validated: Vec<platform::TargetSocket> =
        sockets.iter().map(|s| s.validated()).collect::<Result<Vec<_>, _>>()?;

    // Checked first, so an authentication prompt only appears for a socket
    // that is still open.
    let open: Vec<&platform::TargetSocket> =
        validated.iter().filter(|target| platform::socket_exists(target)).collect();

    if open.is_empty() {
        return Err("Those connections have already ended.".to_string());
    }

    let targets: Vec<platform::TargetSocket> = open.into_iter().cloned().collect();
    let complaint = platform::close_sockets(&targets)?;

    let closed = targets.iter().filter(|target| !platform::socket_exists(target)).count();
    if closed == 0 {
        return Err(platform::explain_close_failure(&complaint));
    }

    let target = match sockets {
        [single] => single.endpoint(),
        many => format!("{} connections to {}", many.len(), many[0].remote_addr),
    };
    actionlog::record(conn, actionlog::kind::CLOSE_CONNECTION, &target, Some("closed from the dashboard"), false);

    Ok(closed)
}

/// Whether two process names refer to the same program.
///
/// Windows reports `firefox.exe` where the scan recorded `firefox.exe` too,
/// but a name that arrives without its extension should still match.
fn names_match(current: &str, expected: &str) -> bool {
    let strip = |name: &str| {
        name.strip_suffix(".exe")
            .or_else(|| name.strip_suffix(".EXE"))
            .unwrap_or(name)
            .to_ascii_lowercase()
    };
    strip(current) == strip(expected)
}

/// Deletes a file outright, with no undo.
pub fn delete_file(conn: &Connection, path: &str, reason: &str) -> Result<(), String> {
    let target = Path::new(path);
    if !target.is_file() {
        return Err(format!("{path} is not a file."));
    }

    std::fs::remove_file(target).map_err(|e| format!("Cannot delete {path}: {e}"))?;
    let _ = db::forget_file(conn, path);
    actionlog::record(conn, actionlog::kind::DELETE, path, Some(reason), false);
    Ok(())
}

/// Undoes a logged action, where that is possible.
///
/// A deleted file cannot come back, so that kind is refused rather than
/// reported as done.
pub fn revert(conn: &Connection, action_id: i64) -> Result<String, String> {
    let record = db::get_action(conn, action_id)?
        .ok_or_else(|| "That entry is not in the log.".to_string())?;

    if record.reverted {
        return Err("That action has already been undone.".to_string());
    }
    if !record.reversible {
        return Err("That action cannot be undone.".to_string());
    }

    let message = match record.action.as_str() {
        actionlog::kind::BLOCK_IP => {
            unblock_ip(conn, &record.target)?;
            format!("{} is no longer blocked.", record.target)
        }
        actionlog::kind::QUARANTINE => {
            // The log stores where the file came from, the quarantine table
            // where it went.
            let entry = db::list_quarantine(conn)?
                .into_iter()
                .find(|e| e.original_path == record.target)
                .ok_or_else(|| "That file is no longer in quarantine.".to_string())?;
            let restored = crate::quarantine::restore(conn, &entry.id)?;
            format!("Restored to {restored}.")
        }
        actionlog::kind::TRUST_FILE => {
            crate::allowlist::remove(conn, &record.target)?;
            "That file is no longer trusted.".to_string()
        }
        actionlog::kind::TRUST_IP => {
            db::set_ip_trust(conn, &record.target, false, None)?;
            format!("{} is no longer trusted.", record.target)
        }
        other => return Err(format!("There is no way to undo {other}.")),
    };

    actionlog::mark_reverted(conn, action_id)?;
    Ok(message)
}

/// Marks an address as expected, so it stops being reported.
pub fn trust_ip(conn: &Connection, raw: &str, label: Option<&str>) -> Result<(), String> {
    let ip: IpAddr = raw.trim().parse().map_err(|_| format!("{raw} is not an IP address."))?;
    db::set_ip_trust(conn, &ip.to_string(), true, label)?;
    actionlog::record(conn, actionlog::kind::TRUST_IP, &ip.to_string(), label, true);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn something_that_is_not_an_address_never_reaches_the_firewall() {
        let conn = crate::db::open_memory();
        // Without validation this string would be handed to nft.
        let error = block_ip(&conn, "1.2.3.4; rm -rf /").unwrap_err();
        assert!(error.contains("not an IP address"));
        assert!(actionlog::list(&conn, 10).unwrap().is_empty());
    }

    #[test]
    fn the_local_network_cannot_be_blocked_by_accident() {
        let conn = crate::db::open_memory();
        assert!(block_ip(&conn, "192.168.1.1").unwrap_err().contains("your own network"));
        assert!(block_ip(&conn, "127.0.0.1").is_err());
    }

    #[test]
    fn init_and_impossible_pids_are_refused_before_anything_is_signalled() {
        let conn = crate::db::open_memory();
        assert!(kill_process(&conn, 1, None).is_err());
        assert!(kill_process(&conn, 0, None).is_err());
        assert!(kill_process(&conn, -5, None).is_err());
    }

    #[test]
    fn a_reused_pid_is_noticed_by_comparing_the_name() {
        let conn = crate::db::open_memory();
        // This test process exists, and is not called "node".
        let mine = std::process::id() as i32;
        let error = kill_process(&conn, mine, Some("node")).unwrap_err();
        assert!(error.contains("not node"), "got: {error}");
    }

    #[test]
    fn a_process_that_already_ended_is_reported_rather_than_signalled() {
        let conn = crate::db::open_memory();
        // Above the usual maximum, so nothing is there.
        assert!(kill_process(&conn, 4_194_303, None).unwrap_err().contains("already ended"));
    }

    fn socket(protocol: &str, remote: &str, remote_port: u16, local_port: u16) -> SocketRef {
        SocketRef {
            protocol: protocol.into(),
            local_addr: "192.168.1.20".into(),
            local_port,
            remote_addr: remote.into(),
            remote_port,
        }
    }

    #[test]
    fn nothing_that_is_not_an_address_or_a_protocol_becomes_a_target() {
        let mut bad_address = socket("tcp", "not-an-address", 443, 1);
        assert!(bad_address.validated().unwrap_err().contains("not an IP address"));

        bad_address.remote_addr = "1.2.3.4; ss -K".into();
        assert!(bad_address.validated().is_err());

        assert!(socket("carrier-pigeon", "1.2.3.4", 443, 1).validated().unwrap_err().contains("not a protocol"));
        assert!(socket("tcp", "1.2.3.4", 0, 1).validated().unwrap_err().contains("no port"));
    }

    #[test]
    fn a_valid_socket_keeps_its_four_values() {
        let target = socket("tcp", "185.220.101.7", 443, 44321).validated().unwrap();
        assert!(target.tcp);
        assert_eq!(target.remote.to_string(), "185.220.101.7");
        assert_eq!(target.remote_port, 443);
        assert_eq!(target.local_port, 44321);

        assert!(!socket("udp", "185.220.101.7", 53, 1).validated().unwrap().tcp);
    }

    #[test]
    fn closing_nothing_is_refused_rather_than_reported_as_success() {
        let conn = crate::db::open_memory();
        assert!(close_connections(&conn, &[]).unwrap_err().contains("no connection"));
    }

    #[test]
    fn a_connection_that_has_already_ended_never_asks_for_a_password() {
        let conn = crate::db::open_memory();
        // A four-tuple that does not exist. Without the check for an open
        // socket, this test would hang on an authentication dialog.
        let gone = socket("tcp", "192.0.2.123", 9, 9);

        let error = close_connections(&conn, &[gone]).unwrap_err();
        assert!(error.contains("already ended"), "got: {error}");
        assert!(actionlog::list(&conn, 10).unwrap().is_empty(), "nothing happened, so nothing is logged");
    }

    #[test]
    fn a_process_name_matches_with_or_without_the_windows_extension() {
        assert!(names_match("firefox", "firefox"));
        assert!(names_match("firefox.exe", "firefox"));
        assert!(names_match("firefox", "firefox.exe"));
        assert!(!names_match("firefox", "node"));
    }

    #[test]
    fn deleting_a_file_removes_it_and_leaves_a_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.sh");
        std::fs::write(&path, b"x").unwrap();

        let conn = crate::db::open_memory();
        delete_file(&conn, path.to_str().unwrap(), "confirmed malicious").unwrap();

        assert!(!path.exists());
        let log = actionlog::list(&conn, 10).unwrap();
        assert_eq!(log[0].action, actionlog::kind::DELETE);
        assert!(!log[0].reversible, "a deletion must not claim to be undoable");
    }

    #[test]
    fn trusting_an_address_is_recorded_and_can_be_undone() {
        let conn = crate::db::open_memory();
        trust_ip(&conn, "185.220.101.7", Some("my server")).unwrap();
        assert!(db::observe_ip(&conn, "185.220.101.7").unwrap().trusted);

        let id = actionlog::list(&conn, 10).unwrap()[0].id;
        revert(&conn, id).unwrap();
        assert!(!db::observe_ip(&conn, "185.220.101.7").unwrap().trusted);
    }

    #[test]
    fn an_action_cannot_be_undone_twice() {
        let conn = crate::db::open_memory();
        trust_ip(&conn, "8.8.8.8", None).unwrap();
        let id = actionlog::list(&conn, 10).unwrap()[0].id;

        revert(&conn, id).unwrap();
        assert!(revert(&conn, id).unwrap_err().contains("already been undone"));
    }

    #[test]
    fn a_deletion_refuses_to_pretend_it_can_be_undone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gone.sh");
        std::fs::write(&path, b"x").unwrap();

        let conn = crate::db::open_memory();
        delete_file(&conn, path.to_str().unwrap(), "test").unwrap();
        let id = actionlog::list(&conn, 10).unwrap()[0].id;

        assert!(revert(&conn, id).unwrap_err().contains("cannot be undone"));
    }

    #[test]
    fn undoing_a_quarantine_puts_the_file_back() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = crate::testenv::isolated_data_dir(&tmp.path().join("data"));

        let victim = tmp.path().join("thing.run");
        std::fs::write(&victim, b"contents").unwrap();

        let conn = crate::db::open_memory();
        crate::quarantine::quarantine_file(&conn, victim.to_str().unwrap(), "test").unwrap();
        assert!(!victim.exists());

        let id = actionlog::list(&conn, 10).unwrap()[0].id;
        revert(&conn, id).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"contents");
    }
}
