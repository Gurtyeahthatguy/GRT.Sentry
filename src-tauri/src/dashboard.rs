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
use crate::{
    accounts, actionlog, audit, authlog, autostart, db, extensions, folders, history, indicators, integrity, netmon,
    packages, platform, privilege, processes, response, rootkit, scanner, updates,
};

fn phase(name: &str, message: &str) -> scanner::ScanProgress {
    scanner::ScanProgress { phase: name.into(), current: 0, total: 0, message: message.into() }
}

/// Clears the "a scan is running" flag even if something panics.
struct ScanGuard<'a>(&'a AppState);

impl Drop for ScanGuard<'_> {
    fn drop(&mut self) {
        self.0.scanning.store(false, Ordering::SeqCst);
        self.0.cancel.store(false, Ordering::SeqCst);
    }
}

/// The full sequence: files, connections, updates, autostart, logins,
/// integrity and packages.
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
    let own_indicators = indicators::Indicators::load();
    {
        let conn = state.db.lock().unwrap();
        response::lift_expired(&conn, db::now());
    }

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
            findings.extend(netmon::indicator_findings(&list, &own_indicators));
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
        let mut logins = authlog::findings(&conn, &config.auth_log_path, config.failed_login_threshold);
        response::mark_blocked(&conn, &mut logins, db::now());
        if config.auto_block {
            response::respond(&conn, &mut logins, config.auto_block_after, db::now());
        }
        findings.extend(logins);

        progress(scanner::ScanProgress {
            phase: "integrity".into(),
            current: 0,
            total: 0,
            message: "Checking system files".into(),
        });
        findings.extend(integrity::findings(&conn, &config.integrity_paths));

        if let Some(list) = platform::accounts() {
            findings.extend(accounts::account_findings(&conn, &list));
        }

        progress(phase("processes", "Checking where running programs come from"));
        findings.extend(processes::findings(&own_indicators));

        progress(phase("extensions", "Checking browser extensions"));
        findings.extend(extensions::findings(&conn));
    }

    // The deeper system checks, each a walk or a probe of its own.
    if config.check_system {
        progress(phase("rootkits", "Looking for hidden processes, ports and modules"));
        {
            let conn = state.db.lock().unwrap();
            findings.extend(rootkit::findings(&conn));
        }

        progress(phase("privileges", "Looking for files that hand out privilege"));
        {
            let conn = state.db.lock().unwrap();
            findings.extend(privilege::findings(&conn, &config.skip_folders));
        }

        progress(phase("folders", "Comparing system folders with what was there"));
        {
            let conn = state.db.lock().unwrap();
            findings.extend(folders::findings(&conn));
        }

        progress(phase("settings", "Checking SSH, sudo and the search path"));
        findings.extend(audit::findings());
    }

    // Packaged programs. Slow the first time, so the database is locked
    // per file rather than for the whole pass.
    if config.check_packages {
        progress(scanner::ScanProgress {
            phase: "packages".into(),
            current: 0,
            total: 0,
            message: "Comparing system programs with their packages".into(),
        });
        findings.extend(packages::findings(&state.db, &state.cancel, progress));
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
        ..Default::default()
    };

    {
        let conn = state.db.lock().unwrap();
        history::apply(&conn, &mut findings, status.last_scan);
    }

    let mut snapshot = Snapshot::default();
    for finding in findings {
        snapshot.targets.insert(finding.issue.id.clone(), finding.target);
        status.issues.push(finding.issue);
    }
    status.finish();

    {
        let conn = state.db.lock().unwrap();
        let real_issues = status.issues.iter().filter(|i| i.counts()).count();
        match db::record_scan(&conn, files_checked, real_issues) {
            Ok(id) => {
                status.scan_id = id;
                let stored: Vec<_> = status.issues.iter().map(history::stored).collect();
                if let Err(e) = db::record_scan_issues(&conn, id, &stored) {
                    eprintln!("grt-sentry: the scan's issues could not be kept: {e}");
                }
            }
            Err(e) => eprintln!("grt-sentry: the scan could not be recorded: {e}"),
        }
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
    snapshot.status.finish();
}

/// Drops every issue whose target matches, after one action resolved them all.
pub fn dismiss_where(state: &AppState, matches: impl Fn(&IssueTarget) -> bool) {
    let mut snapshot = state.snapshot.lock().unwrap();
    let gone: Vec<String> =
        snapshot.targets.iter().filter(|(_, target)| matches(target)).map(|(id, _)| id.clone()).collect();
    for id in &gone {
        snapshot.targets.remove(id);
    }
    snapshot.status.issues.retain(|issue| !gone.contains(&issue.id));
    snapshot.status.finish();
}

/// Sets an issue aside, or brings it back, in the snapshot and in the history.
///
/// Later scans keep it aside for as long as its fingerprint stays the same.
pub fn set_aside(state: &AppState, issue_id: &str, aside: bool) -> Result<(), String> {
    let mut snapshot = state.snapshot.lock().unwrap();
    let issue = snapshot
        .status
        .issues
        .iter_mut()
        .find(|issue| issue.id == issue_id)
        .ok_or_else(|| "That issue is not in the current results. Run a scan again.".to_string())?;
    issue.set_aside = aside;
    let (print, kind, title) = (issue.fingerprint.clone(), history::kind_name(issue), issue.title.clone());
    snapshot.status.finish();
    drop(snapshot);

    if print.is_empty() {
        return Ok(());
    }
    let conn = state.db.lock().unwrap();
    db::set_issue_aside(&conn, &print, &kind, aside)?;
    let what = if aside { actionlog::kind::SET_ASIDE } else { actionlog::kind::BRING_BACK };
    actionlog::record(&conn, what, &title, None, false);
    Ok(())
}

/// Puts findings that came after the scan, from a privileged read or a
/// capture, into the current results.
pub fn add_findings(state: &AppState, mut findings: Vec<Finding>) -> usize {
    {
        let conn = state.db.lock().unwrap();
        history::apply(&conn, &mut findings, db::now());
    }
    let count = findings.len();
    let mut snapshot = state.snapshot.lock().unwrap();
    for finding in findings {
        snapshot.targets.insert(finding.issue.id.clone(), finding.target);
        snapshot.status.issues.push(finding.issue);
    }
    snapshot.status.finish();
    count
}

/// An issue and its target, for exporting it.
pub fn issue_of(state: &AppState, issue_id: &str) -> Option<(Issue, IssueTarget)> {
    let snapshot = state.snapshot.lock().unwrap();
    let issue = snapshot.status.issues.iter().find(|i| i.id == issue_id)?.clone();
    let target = snapshot.targets.get(issue_id)?.clone();
    Some((issue, target))
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
                // Hashing every system program belongs to its own tests.
                check_packages: false,
                check_system: false,
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
    async fn an_issue_set_aside_stays_aside_in_the_next_scan() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("eicar.com"), crate::rules::samples::eicar()).unwrap();
        let state = state_for(dir.path());

        let first = scan(&state, None, &|_| {}).await.unwrap();
        let eicar = first.issues.iter().find(|i| i.kind == IssueKind::RuleMatch).expect("EICAR is found");
        assert!(eicar.is_new());
        set_aside(&state, &eicar.id, true).unwrap();
        assert!(current(&state).issues.iter().any(|i| i.set_aside));

        let second = scan(&state, None, &|_| {}).await.unwrap();
        let again = second.issues.iter().find(|i| i.kind == IssueKind::RuleMatch).unwrap();
        assert!(again.set_aside, "set aside stays aside");
        assert!(!again.is_new(), "and does not come back as new");
        assert_eq!(again.times_seen, 2);
        assert!(second.scan_id > first.scan_id);

        let conn = state.db.lock().unwrap();
        let stored = crate::db::scan_issues(&conn, second.scan_id).unwrap();
        assert!(stored.iter().any(|i| i.set_aside && i.kind == "rule_match"));
    }

    /// Run by scripts/check-false-positives.sh, not by `cargo test`.
    ///
    /// Every system check on this machine, twice: the first scan records,
    /// and the second must find nothing to alarm about and nothing new.
    /// Connections come and go between two scans and are left out of the
    /// count; pending updates and failed logins are in it, and pass when the
    /// history knows them already.
    #[tokio::test]
    #[ignore]
    async fn system_false_positive_budget() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_for(dir.path());
        {
            let mut config = state.config.lock().unwrap();
            config.check_packages = true;
            config.check_system = true;
            config.auth_log_path = crate::platform::default_auth_log();
        }
        scan(&state, None, &|_| {}).await.unwrap();
        let started = std::time::Instant::now();
        let status = scan(&state, None, &|_| {}).await.unwrap();

        let live = [IssueKind::SuspiciousConnection, IssueKind::OutdatedSecurityPackage, IssueKind::FailedLoginAttempts];
        let alarms: Vec<String> = status
            .issues
            .iter()
            .filter(|i| i.counts() && (i.is_new() || !live.contains(&i.kind)))
            .filter(|i| i.kind != IssueKind::SuspiciousConnection)
            .map(|i| format!("{:?} {}", i.kind, i.title))
            .collect();
        println!("second scan: {:.1} s, {} issues, {} alarms", started.elapsed().as_secs_f64(), status.issues.len(), alarms.len());
        for alarm in &alarms {
            println!("  {alarm}");
        }
        assert!(alarms.is_empty(), "{} alarms on a clean machine", alarms.len());
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
