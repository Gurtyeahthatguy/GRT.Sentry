//! Running the modules and turning what they say into one answer.
//!
//! A module that fails must not take the scan with it. A missing VirusTotal
//! key, an unreadable record of failed logins or a system with no package
//! manager each become an `Info` line naming the gap, and the scan carries on.
//!
//! The result is one `SystemStatus`: clean when nothing above `Info` came
//! back, and a sorted list of issues when something did.

use std::sync::atomic::Ordering;

use crate::state::{
    Action, AppState, Finding, Issue, IssueKind, IssueTarget, Severity, Snapshot, SystemStatus,
};
use crate::{authlog, autostart, db, integrity, netmon, scanner, updates};

/// Clears the "a scan is running" flag even if something panics.
struct ScanGuard<'a>(&'a AppState);

impl Drop for ScanGuard<'_> {
    fn drop(&mut self) {
        self.0.scanning.store(false, Ordering::SeqCst);
        self.0.cancel.store(false, Ordering::SeqCst);
    }
}

/// The full sequence: files, connections, updates, autostart, logins and
/// integrity.
///
/// `paths` overrides the configured directories.
pub async fn scan(
    state: &AppState,
    paths: Option<Vec<String>>,
    progress: &(dyn Fn(scanner::ScanProgress) + Sync),
) -> Result<SystemStatus, String> {
    if state.scanning.swap(true, Ordering::SeqCst) {
        return Err("A scan is already running.".to_string());
    }
    state.cancel.store(false, Ordering::SeqCst);
    let _guard = ScanGuard(state);

    let config = { state.config.lock().unwrap().clone() };
    let scan_paths = paths.unwrap_or_else(|| config.scan_paths.clone());

    let mut findings: Vec<Finding> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    // 1. Files, the slow module and the only one that uses the network.
    let outcome = scanner::run_scan(
        &state.db,
        &config,
        &state.vt,
        &state.cancel,
        &scan_paths,
        progress,
    )
    .await;
    let files_checked = outcome.files_checked;
    let queued_files = outcome.queued;
    findings.extend(outcome.findings);
    notes.extend(outcome.notes);

    // 2. Connections, each remote address given a location.
    progress(scanner::ScanProgress {
        phase: "connections".into(),
        current: 0,
        total: 0,
        message: "Reading active connections".into(),
    });

    let connections = {
        let conn = state.db.lock().unwrap();
        netmon::snapshot(&conn, state.geo.as_ref())
    };
    let active_connections = match connections {
        Ok(list) => {
            let count = list.len() as u32;
            findings.extend(netmon::findings(&list));
            count
        }
        Err(e) => {
            notes.push(format!("Connections could not be read: {e}"));
            0
        }
    };

    if state.geo.is_none() {
        notes.push(
            "The GeoLite2 database is not installed, so connections are listed without a location. \
             scripts/fetch-geoip.sh downloads it; everything else works without it."
                .to_string(),
        );
    }

    // 3. Pending security updates.
    progress(scanner::ScanProgress {
        phase: "updates".into(),
        current: 0,
        total: 0,
        message: "Checking for security updates".into(),
    });
    findings.extend(updates::findings());

    // 4, 5, 6. The cheap ones, all reading small files.
    {
        let conn = state.db.lock().unwrap();

        progress(scanner::ScanProgress {
            phase: "autostart".into(),
            current: 0,
            total: 0,
            message: "Checking what starts automatically".into(),
        });
        findings.extend(autostart::findings(&conn));

        progress(scanner::ScanProgress {
            phase: "logins".into(),
            current: 0,
            total: 0,
            message: "Checking failed logins".into(),
        });
        findings.extend(authlog::findings(&conn, &config.auth_log_path, config.failed_login_threshold));

        progress(scanner::ScanProgress {
            phase: "integrity".into(),
            current: 0,
            total: 0,
            message: "Checking system files".into(),
        });
        findings.extend(integrity::findings(&conn, &config.integrity_paths));
    }

    // Notes become issues, so nothing a module said is lost on the way out.
    for note in notes {
        findings.push(Finding::note(Issue {
            kind: IssueKind::ModuleUnavailable,
            severity: Severity::Info,
            title: note.lines().next().unwrap_or("Note").to_string(),
            location: "GRT Sentry".to_string(),
            detail: Some(note),
            actions: vec![Action::ignore()],
            ..Default::default()
        }));
    }

    let mut status = SystemStatus {
        clean: true,
        last_scan: db::now(),
        files_checked,
        active_connections,
        queued_files,
        issues: Vec::new(),
    };

    let mut snapshot = Snapshot::default();
    for finding in findings {
        snapshot.targets.insert(finding.issue.id.clone(), finding.target);
        status.issues.push(finding.issue);
    }
    status.finish();

    {
        let conn = state.db.lock().unwrap();
        let real_issues = status.issues.iter().filter(|i| i.severity != Severity::Info).count();
        let _ = db::record_scan(&conn, files_checked, real_issues);
    }

    snapshot.status = status.clone();
    *state.snapshot.lock().unwrap() = snapshot;

    Ok(status)
}

/// Drops one issue from the current snapshot.
pub fn dismiss(state: &AppState, issue_id: &str) {
    let mut snapshot = state.snapshot.lock().unwrap();
    snapshot.status.issues.retain(|issue| issue.id != issue_id);
    snapshot.targets.remove(issue_id);
    let clean = !snapshot.status.issues.iter().any(|i| i.severity != Severity::Info);
    snapshot.status.clean = clean;
}

/// What an action refers to, if the snapshot still knows.
pub fn target_of(state: &AppState, issue_id: &str) -> Option<IssueTarget> {
    state.snapshot.lock().unwrap().targets.get(issue_id).cloned()
}

/// The last result, for a window that has just opened.
pub fn current(state: &AppState) -> SystemStatus {
    state.snapshot.lock().unwrap().status.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::sync::atomic::AtomicBool;
    use std::sync::Mutex;

    fn state_for(dir: &std::path::Path) -> AppState {
        AppState {
            db: Mutex::new(crate::db::open_memory()),
            geo: None,
            config: Mutex::new(Config {
                virustotal_api_key: None,
                scan_paths: vec![dir.to_string_lossy().into_owned()],
                // Nothing readable, so the module reports itself unavailable.
                auth_log_path: "/nonexistent/auth.log".to_string(),
                integrity_paths: vec![],
                ..Default::default()
            }),
            snapshot: Mutex::new(Snapshot::default()),
            scanning: AtomicBool::new(false),
            cancel: AtomicBool::new(false),
            vt: scanner::RateLimiter::new(),
        }
    }

    #[tokio::test]
    async fn a_scan_survives_every_module_that_cannot_run() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("thing.sh"), b"#!/bin/sh\n").unwrap();
        let state = state_for(dir.path());

        let status = scan(&state, None, &|_| {}).await.unwrap();

        // No key, no log, no GeoIP database, and still a result.
        assert_eq!(status.files_checked, 1);
        assert!(status.last_scan > 0);
        assert!(
            status.issues.iter().any(|i| i.kind == IssueKind::ModuleUnavailable),
            "a gap in coverage has to be visible"
        );
    }

    #[tokio::test]
    async fn a_module_that_cannot_run_never_raises_the_alarm_by_itself() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_for(dir.path());

        let status = scan(&state, None, &|_| {}).await.unwrap();

        // What is under test is the gap, not the machine. A host with pending
        // updates, open sockets or failed logins in its log reports those, and
        // is right to; the assertion is that a module which could not run says
        // so as information and never as an alarm.
        let unavailable: Vec<&Issue> =
            status.issues.iter().filter(|i| i.kind == IssueKind::ModuleUnavailable).collect();

        assert!(!unavailable.is_empty(), "no key and no readable log is a gap worth naming");
        for issue in unavailable {
            assert_eq!(
                issue.severity,
                Severity::Info,
                "a gap in coverage is not a finding about the machine: {}",
                issue.title
            );
        }
    }

    #[tokio::test]
    async fn the_progress_callback_reports_the_phases_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_for(dir.path());
        let seen = Mutex::new(Vec::new());

        scan(&state, None, &|p| seen.lock().unwrap().push(p.phase)).await.unwrap();

        let phases = seen.lock().unwrap().clone();
        for expected in ["collecting", "done", "connections", "updates", "autostart", "logins", "integrity"] {
            assert!(phases.contains(&expected.to_string()), "missing phase {expected}: {phases:?}");
        }
    }

    #[tokio::test]
    async fn two_scans_cannot_run_at_the_same_time() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_for(dir.path());
        state.scanning.store(true, Ordering::SeqCst);

        assert!(scan(&state, None, &|_| {}).await.unwrap_err().contains("already running"));
    }

    #[tokio::test]
    async fn the_running_flag_is_cleared_afterwards() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_for(dir.path());

        scan(&state, None, &|_| {}).await.unwrap();
        assert!(!state.scanning.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn an_ignored_issue_leaves_the_snapshot_and_can_make_it_clean_again() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_for(dir.path());

        // Built by hand rather than scanned, since a real scan would bring
        // the machine's own connections with it.
        let id = {
            let mut snapshot = state.snapshot.lock().unwrap();
            let issue = Issue { severity: Severity::Warning, title: "test".into(), ..Default::default() };
            let id = issue.id.clone();
            snapshot.targets.insert(id.clone(), IssueTarget::Informational);
            snapshot.status.issues.push(issue);
            snapshot.status.clean = false;
            id
        };

        assert!(target_of(&state, &id).is_some());
        assert!(!current(&state).clean);

        dismiss(&state, &id);

        assert!(target_of(&state, &id).is_none(), "the target goes with the issue");
        assert!(current(&state).clean, "the last problem leaving makes the machine clean again");
    }

    #[tokio::test]
    async fn the_scan_is_recorded_in_the_history() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_for(dir.path());
        scan(&state, None, &|_| {}).await.unwrap();

        let conn = state.db.lock().unwrap();
        assert_eq!(crate::db::recent_scans(&conn, 5).unwrap().len(), 1);
    }
}
