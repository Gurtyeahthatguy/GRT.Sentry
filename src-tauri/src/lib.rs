//! The surface the window talks to.
//!
//! Every command the interface can call is here, and each one validates what
//! arrived and hands it to a module. The interface holds issue ids and never a
//! path or a pid: the mapping from an id to something real stays in the
//! backend snapshot.
//!
//! The VirusTotal key is treated the same way. It is read from a file this
//! process owns and used from Rust, and the settings tab is told only whether
//! a key is set and how it ends.

mod actionlog;
mod allowlist;
mod authlog;
mod autostart;
mod cli;
mod config;
mod dashboard;
mod db;
mod geoip;
mod integrity;
mod netmon;
mod paths;
mod platform;
mod quarantine;
mod resolve;
mod scanner;
mod schedule;
mod state;
#[cfg(test)]
mod testenv;
mod updates;
mod watcher;

use std::sync::Mutex;
use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::config::{ConfigUpdate, ConfigView};
use crate::db::{ActionRecord, AllowEntry, IpRecord, QuarantineEntry, ScanRecord};
use crate::netmon::Connection;
use crate::state::{AppState, Issue, IssueTarget, SystemStatus};

/// Holds the optional folder watcher, so switching it off drops it.
struct WatcherState(Mutex<Option<watcher::FolderWatcher>>);

// --- scanning -------------------------------------------------------------

#[tauri::command]
async fn quick_scan(app: AppHandle, state: State<'_, AppState>) -> Result<SystemStatus, String> {
    let emitter = app.clone();
    dashboard::scan(&state, None, &move |progress| {
        let _ = emitter.emit("scan-progress", progress);
    })
    .await
}

#[tauri::command]
async fn full_scan(
    app: AppHandle,
    state: State<'_, AppState>,
    paths: Vec<String>,
) -> Result<SystemStatus, String> {
    let paths = if paths.is_empty() { None } else { Some(paths) };
    let emitter = app.clone();
    dashboard::scan(&state, paths, &move |progress| {
        let _ = emitter.emit("scan-progress", progress);
    })
    .await
}

#[tauri::command]
fn cancel_scan(state: State<'_, AppState>) {
    cli::cancel(&state);
}

#[tauri::command]
fn current_status(state: State<'_, AppState>) -> SystemStatus {
    dashboard::current(&state)
}

/// What came back about one chosen file.
#[derive(Serialize)]
struct FileReport {
    path: String,
    sha256: String,
    size: u64,
    /// Engines flagging it, when there is an answer.
    malicious: Option<u32>,
    total: Option<u32>,
    known: bool,
    trusted: bool,
    /// Present when the file is worth reporting, and carries the actions.
    issue: Option<Issue>,
}

/// Checks a single file on demand, ignoring the extension filters.
#[tauri::command]
async fn scan_file(state: State<'_, AppState>, path: String) -> Result<FileReport, String> {
    let target = std::path::PathBuf::from(&path);
    if !target.is_file() {
        return Err(format!("{path} is not a file."));
    }

    let metadata = std::fs::metadata(&target).map_err(|e| format!("Cannot read {path}: {e}"))?;
    let size = metadata.len();

    let hash_path = target.clone();
    let sha256 = tokio::task::spawn_blocking(move || scanner::hash_file(&hash_path))
        .await
        .map_err(|e| format!("The hash could not be computed: {e}"))?
        .map_err(|e| format!("Cannot read {path}: {e}"))?;

    let (trusted, cached) = {
        let conn = state.db.lock().unwrap();
        let _ = db::put_file(&conn, &path, &sha256, size, scanner::modified_at(&metadata));
        (db::is_allowed(&conn, &sha256), db::verdict_for_hash(&conn, &sha256, 0))
    };

    let (api_key, interval) = {
        let config = state.config.lock().unwrap();
        (config.api_key(), config.vt_interval_seconds)
    };

    let verdict = match (cached, api_key) {
        (Some(malicious), _) => scanner::VtVerdict {
            malicious: malicious.max(0) as u32,
            suspicious: 0,
            total: 0,
            known: true,
        },
        (None, Some(key)) => {
            let client = scanner::VtClient::new(key, &state.vt, Duration::from_secs(interval))?;
            let verdict = client.lookup(&sha256).await?;
            let conn = state.db.lock().unwrap();
            let _ = db::put_verdict(&conn, &sha256, verdict.malicious as i64);
            verdict
        }
        (None, None) => {
            return Err(
                "No VirusTotal API key is set, so there is nothing to compare this file against. The key goes in Settings."
                    .to_string(),
            )
        }
    };

    let issue = if trusted {
        None
    } else {
        scanner::file_finding(&path, &sha256, &verdict, false).map(|finding| {
            let mut snapshot = state.snapshot.lock().unwrap();
            snapshot.targets.insert(finding.issue.id.clone(), finding.target);
            finding.issue
        })
    };

    Ok(FileReport {
        path,
        sha256,
        size,
        malicious: verdict.known.then_some(verdict.malicious),
        total: (verdict.total > 0).then_some(verdict.total),
        known: verdict.known,
        trusted,
        issue,
    })
}

// --- connections ----------------------------------------------------------

#[tauri::command]
fn list_connections(state: State<'_, AppState>) -> Result<Vec<Connection>, String> {
    let conn = state.db.lock().unwrap();
    netmon::snapshot(&conn, state.geo.as_ref())
}

// --- acting on an issue ---------------------------------------------------

/// Carries out an action on an issue from the current snapshot.
///
/// The match is on the pair of target and action, so an action that makes no
/// sense for a target is refused rather than silently ignored.
#[tauri::command]
async fn resolve_issue(
    state: State<'_, AppState>,
    issue_id: String,
    action: String,
    note: Option<String>,
) -> Result<String, String> {
    let target = dashboard::target_of(&state, &issue_id)
        .ok_or_else(|| "That issue is not in the current results. Run a scan again.".to_string())?;

    if action == "ignore" {
        dashboard::dismiss(&state, &issue_id);
        return Ok("Set aside for now.".to_string());
    }

    // The only action that sends anything other than a hash.
    if action == "upload_vt" {
        let IssueTarget::File { path, sha256 } = &target else {
            return Err("Only a file can be sent for analysis.".to_string());
        };

        let (api_key, interval) = {
            let config = state.config.lock().unwrap();
            (config.api_key(), config.vt_interval_seconds)
        };
        let key = api_key.ok_or_else(|| "No VirusTotal API key is set.".to_string())?;
        let client = scanner::VtClient::new(key, &state.vt, Duration::from_secs(interval))?;
        let verdict = client.upload_file(std::path::Path::new(path)).await?;

        let conn = state.db.lock().unwrap();
        let _ = db::put_verdict(&conn, sha256, verdict.malicious as i64);
        actionlog::record(&conn, actionlog::kind::UPLOAD_VT, path, Some("sent by the user"), false);
        dashboard::dismiss(&state, &issue_id);

        return Ok(if verdict.malicious > 0 {
            format!("{} of {} engines flag it. Scan again to see the issue with its actions.", verdict.malicious, verdict.total)
        } else {
            format!("No engine flagged it, out of {}.", verdict.total)
        });
    }

    let conn = state.db.lock().unwrap();

    let message = match (&target, action.as_str()) {
        (IssueTarget::File { path, .. }, "quarantine") => {
            quarantine::quarantine_file(&conn, path, note.as_deref().unwrap_or("quarantined from the dashboard"))?;
            format!("{path} is in quarantine.")
        }
        (IssueTarget::File { path, .. }, "delete") => {
            resolve::delete_file(&conn, path, note.as_deref().unwrap_or("deleted from the dashboard"))?;
            format!("{path} is gone.")
        }
        (IssueTarget::File { sha256, path }, "trust") => {
            allowlist::add(&conn, sha256, note.as_deref().or(Some(path)))?;
            "That file will not be reported again unless its contents change.".to_string()
        }
        (IssueTarget::File { path, .. }, "restore") => {
            let entry = db::list_quarantine(&conn)?
                .into_iter()
                .find(|e| &e.original_path == path)
                .ok_or_else(|| "That file is not in quarantine.".to_string())?;
            let restored = quarantine::restore(&conn, &entry.id)?;
            format!("Put back at {restored}.")
        }

        (IssueTarget::Connection { ip, .. }, "block_ip")
        | (IssueTarget::LoginAttempts { ip }, "block_ip") => {
            resolve::block_ip(&conn, ip)?;
            format!("{ip} is blocked.")
        }
        (IssueTarget::Connection { ip, .. }, "trust") | (IssueTarget::LoginAttempts { ip }, "trust") => {
            resolve::trust_ip(&conn, ip, note.as_deref())?;
            format!("{ip} will not be reported again.")
        }
        (IssueTarget::Connection { ip, pid, .. }, "close_connection") => {
            // The list on screen is a moment old, so the sockets are looked
            // up again rather than remembered from the scan.
            let connections = netmon::snapshot(&conn, state.geo.as_ref())?;
            let sockets = netmon::sockets_for(&connections, ip, *pid);
            let closed = resolve::close_connections(&conn, &sockets)?;
            format!("{closed} {} closed.", if closed == 1 { "connection" } else { "connections" })
        }

        (IssueTarget::Connection { pid, process, .. }, "kill_process") => {
            let pid = pid.ok_or_else(|| "That connection has no process to stop.".to_string())?;
            resolve::kill_process(&conn, pid, process.as_deref())?;
            format!("Asked process {pid} to stop.")
        }

        (IssueTarget::Integrity { path, current_hash }, "update_baseline") => {
            integrity::accept_current(&conn, path, current_hash)?;
            format!("The current contents of {path} are the new reference.")
        }

        (IssueTarget::Autostart { key, name }, "trust") => {
            autostart::accept(&conn, key, name)?;
            format!("{name} is expected from now on.")
        }

        (IssueTarget::Packages { names }, "list_packages") => names.join(", "),

        (IssueTarget::Informational, "read_authlog") => {
            let path = { state.config.lock().unwrap().auth_log_path.clone() };
            let text = authlog::read_privileged(&path)?;
            let threshold = { state.config.lock().unwrap().failed_login_threshold };
            let found = authlog::findings_from_text(&text, threshold, db::now());

            let count = found.len();
            let mut snapshot = state.snapshot.lock().unwrap();
            for finding in found {
                snapshot.targets.insert(finding.issue.id.clone(), finding.target);
                snapshot.status.issues.push(finding.issue);
            }
            snapshot.status.finish();

            if count == 0 {
                "The log was read: no repeated failures in the last 24 hours.".to_string()
            } else {
                format!("The log was read: {count} thing(s) worth seeing were added to the list.")
            }
        }

        (_, other) => return Err(format!("\"{other}\" cannot be done to this kind of issue.")),
    };

    drop(conn);

    // Showing a list resolves nothing, so that issue stays where it is.
    if action != "list_packages" {
        dashboard::dismiss(&state, &issue_id);
    }
    Ok(message)
}

/// Closes one socket from the connections table.
///
/// Asynchronous because it waits for an authentication dialog, which on the
/// main thread would freeze the window.
#[tauri::command]
async fn close_connection(
    state: State<'_, AppState>,
    socket: netmon::SocketRef,
) -> Result<String, String> {
    let endpoint = socket.endpoint();
    let conn = state.db.lock().unwrap();
    resolve::close_connections(&conn, std::slice::from_ref(&socket))?;
    Ok(format!("The connection to {endpoint} is closed."))
}

// --- quarantine -----------------------------------------------------------

#[tauri::command]
fn list_quarantine(state: State<'_, AppState>) -> Result<Vec<QuarantineEntry>, String> {
    let conn = state.db.lock().unwrap();
    quarantine::list(&conn)
}

#[tauri::command]
fn restore_from_quarantine(state: State<'_, AppState>, id: String) -> Result<String, String> {
    let conn = state.db.lock().unwrap();
    quarantine::restore(&conn, &id)
}

#[tauri::command]
fn delete_from_quarantine(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let conn = state.db.lock().unwrap();
    quarantine::discard(&conn, &id)
}

// --- lists the interface shows --------------------------------------------

#[tauri::command]
fn trust_ip(state: State<'_, AppState>, ip: String, label: Option<String>) -> Result<(), String> {
    let conn = state.db.lock().unwrap();
    resolve::trust_ip(&conn, &ip, label.as_deref())
}

#[tauri::command]
fn untrust_ip(state: State<'_, AppState>, ip: String) -> Result<(), String> {
    let conn = state.db.lock().unwrap();
    db::set_ip_trust(&conn, &ip, false, None)
}

#[tauri::command]
fn list_trusted_ips(state: State<'_, AppState>) -> Result<Vec<IpRecord>, String> {
    let conn = state.db.lock().unwrap();
    db::list_trusted_ips(&conn)
}

#[tauri::command]
fn list_allowlist(state: State<'_, AppState>) -> Result<Vec<AllowEntry>, String> {
    let conn = state.db.lock().unwrap();
    allowlist::list(&conn)
}

#[tauri::command]
fn remove_from_allowlist(state: State<'_, AppState>, sha256: String) -> Result<(), String> {
    let conn = state.db.lock().unwrap();
    allowlist::remove(&conn, &sha256)
}

/// One line per action, already turned into a sentence.
#[derive(Serialize)]
struct ActionLine {
    #[serde(flatten)]
    record: ActionRecord,
    description: String,
}

#[tauri::command]
fn list_action_log(state: State<'_, AppState>, limit: Option<u32>) -> Result<Vec<ActionLine>, String> {
    let conn = state.db.lock().unwrap();
    Ok(actionlog::list(&conn, limit.unwrap_or(200))?
        .into_iter()
        .map(|record| ActionLine { description: actionlog::describe(&record), record })
        .collect())
}

#[tauri::command]
fn revert_action(state: State<'_, AppState>, id: i64) -> Result<String, String> {
    let conn = state.db.lock().unwrap();
    resolve::revert(&conn, id)
}

#[tauri::command]
fn list_autostart() -> Vec<autostart::AutostartEntry> {
    autostart::list()
}

// --- settings and facts about the installation ----------------------------

#[tauri::command]
fn get_config(state: State<'_, AppState>) -> ConfigView {
    ConfigView::from(&*state.config.lock().unwrap())
}

#[tauri::command]
fn set_config(state: State<'_, AppState>, update: ConfigUpdate) -> Result<ConfigView, String> {
    let mut config = state.config.lock().unwrap();
    update.apply(&mut config);
    config.save()?;
    Ok(ConfigView::from(&*config))
}

#[derive(Serialize)]
struct SystemInfo {
    version: String,
    system: String,
    geoip_available: bool,
    geoip_path: Option<String>,
    elevation_available: bool,
    elevation_note: String,
    elevated: bool,
    firewall_available: bool,
    firewall_note: String,
    database_path: String,
    config_path: String,
    quarantine_path: String,
    cached_files: i64,
    quarantined_files: usize,
    recent_scans: Vec<ScanRecord>,
    schedule: schedule::ScheduleStatus,
    watched_folders: Vec<String>,
}

#[tauri::command]
fn system_info(state: State<'_, AppState>, watcher_state: State<'_, WatcherState>) -> SystemInfo {
    let conn = state.db.lock().unwrap();
    SystemInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        system: platform::SYSTEM_NAME.to_string(),
        geoip_available: state.geo.is_some(),
        geoip_path: state.geo.as_ref().map(|g| g.path().to_string_lossy().into_owned()),
        elevation_available: platform::elevation_available(),
        elevation_note: platform::elevation_note().to_string(),
        elevated: platform::is_elevated(),
        firewall_available: platform::firewall_ready(),
        firewall_note: platform::firewall_note().to_string(),
        database_path: paths::database_path().to_string_lossy().into_owned(),
        config_path: paths::config_path().to_string_lossy().into_owned(),
        quarantine_path: paths::quarantine_dir().to_string_lossy().into_owned(),
        cached_files: db::cached_file_count(&conn),
        quarantined_files: db::list_quarantine(&conn).map(|q| q.len()).unwrap_or(0),
        recent_scans: db::recent_scans(&conn, 10).unwrap_or_default(),
        schedule: schedule::status(),
        watched_folders: watcher_state
            .0
            .lock()
            .unwrap()
            .as_ref()
            .map(|w| w.watching.clone())
            .unwrap_or_default(),
    }
}

#[tauri::command]
fn set_schedule(enabled: bool, frequency: Option<String>) -> Result<schedule::ScheduleStatus, String> {
    if enabled {
        schedule::install(frequency.as_deref().unwrap_or("daily"))?;
    } else {
        schedule::remove()?;
    }
    Ok(schedule::status())
}

/// Turns the folder watcher on or off, and remembers the choice.
#[tauri::command]
fn set_watcher(
    app: AppHandle,
    state: State<'_, AppState>,
    watcher_state: State<'_, WatcherState>,
    enabled: bool,
) -> Result<bool, String> {
    {
        let mut config = state.config.lock().unwrap();
        config.watch_folders = enabled;
        config.save()?;
    }

    let mut slot = watcher_state.0.lock().unwrap();
    if !enabled {
        *slot = None;
        return Ok(false);
    }

    let (paths, deep) = {
        let config = state.config.lock().unwrap();
        (config.scan_paths.clone(), config.deep_scan)
    };

    let emitter = app.clone();
    let started = watcher::start(&paths, deep, move |path| {
        let _ = emitter.emit("file-appeared", path);
    })?;
    *slot = Some(started);
    Ok(true)
}

/// Runs a command-line mode when asked for one, otherwise opens the window.
pub fn run() {
    if let Some(code) = cli::maybe_run() {
        std::process::exit(code);
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            // The GeoIP database travels as a bundled resource, and Tauri
            // knows where it landed.
            let bundled = app
                .path()
                .resolve("resources/GeoLite2-City.mmdb", tauri::path::BaseDirectory::Resource)
                .ok();

            let state = AppState::new(bundled.or_else(geoip::bundled_guess))
                .map_err(std::io::Error::other)?;

            let watch_on_start = state.config.lock().unwrap().watch_folders;
            let scan_on_start = state.config.lock().unwrap().scan_on_startup;

            app.manage(state);
            app.manage(WatcherState(Mutex::new(None)));

            if watch_on_start {
                let handle = app.handle().clone();
                let state: State<'_, AppState> = handle.state();
                let watcher_state: State<'_, WatcherState> = handle.state();
                if let Err(e) = set_watcher(handle.clone(), state, watcher_state, true) {
                    eprintln!("grt-sentry: the folder watcher did not start: {e}");
                }
            }

            // The first scan runs after the window exists, so it can show
            // progress rather than opening blank.
            if scan_on_start {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    let state: State<'_, AppState> = handle.state();
                    let emitter = handle.clone();
                    let result = dashboard::scan(&state, None, &move |progress| {
                        let _ = emitter.emit("scan-progress", progress);
                    })
                    .await;
                    match result {
                        Ok(status) => {
                            let _ = handle.emit("scan-finished", status);
                        }
                        Err(e) => {
                            let _ = handle.emit("scan-failed", e);
                        }
                    }
                });
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            quick_scan,
            full_scan,
            cancel_scan,
            current_status,
            scan_file,
            list_connections,
            close_connection,
            resolve_issue,
            list_quarantine,
            restore_from_quarantine,
            delete_from_quarantine,
            trust_ip,
            untrust_ip,
            list_trusted_ips,
            list_allowlist,
            remove_from_allowlist,
            list_action_log,
            revert_action,
            list_autostart,
            get_config,
            set_config,
            system_info,
            set_schedule,
            set_watcher,
        ])
        .run(tauri::generate_context!())
        .expect("GRT Sentry could not start");
}
