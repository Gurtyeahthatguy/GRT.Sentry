//! The command line, which is what the scheduled scan runs.
//!
//! `--scan` does the work without a window and exits, which is what
//! `schedule.rs` starts once a day and also the quickest way to see the same
//! answers from a terminal.

use std::io::IsTerminal;
use std::sync::atomic::Ordering;

use crate::state::{AppState, Severity, SystemStatus};

const USAGE: &str = "\
GRT Sentry, a local security scanner

  grt-sentry                 open the window
  grt-sentry --scan          run a scan without a window and print the result
  grt-sentry --status        print the result of the last scan
  grt-sentry --connections   list the active network connections
  grt-sentry --where         print where the data, configuration and quarantine live
  grt-sentry --version       print the version
  grt-sentry --help          print this

Exit status of --scan: 0 when nothing above information was found, 1 when
something was, 2 when the scan itself could not run.
";

/// Runs a command-line mode if one was asked for, and reports the exit code.
///
/// `None` means no mode matched and the window should open.
pub fn maybe_run() -> Option<i32> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.iter().find(|a| a.starts_with("--"))?;

    match mode.as_str() {
        "--help" | "--usage" => {
            print!("{USAGE}");
            Some(0)
        }
        "--version" => {
            println!("grt-sentry {}", env!("CARGO_PKG_VERSION"));
            Some(0)
        }
        "--where" => Some(print_locations()),
        "--scan" => Some(headless_scan()),
        "--status" => Some(print_last_status()),
        "--connections" => Some(print_connections()),
        _ => None,
    }
}

fn state() -> Result<AppState, String> {
    AppState::new(crate::geoip::bundled_guess())
}

fn print_locations() -> i32 {
    println!("system        {}", crate::platform::SYSTEM_NAME);
    println!("database      {}", crate::paths::database_path().display());
    println!("configuration {}", crate::paths::config_path().display());
    println!("quarantine    {}", crate::paths::quarantine_dir().display());
    match crate::geoip::bundled_guess() {
        Some(path) => println!("geoip         {}", path.display()),
        None => println!("geoip         not found"),
    }
    0
}

/// The scheduled scan, which prints a summary and notifies when something
/// needs attention.
fn headless_scan() -> i32 {
    let state = match state() {
        Ok(state) => state,
        Err(e) => {
            eprintln!("grt-sentry: {e}");
            return 2;
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("grt-sentry: cannot start the async runtime: {e}");
            return 2;
        }
    };

    // Progress is drawn only for a terminal. In the journal a carriage return
    // overwrites nothing, and the counter would be the whole entry.
    let interactive = std::io::stderr().is_terminal() && !std::env::args().any(|a| a == "--quiet");

    let status = runtime.block_on(crate::dashboard::scan(&state, None, &move |progress| {
        if interactive && progress.phase == "hashing" {
            eprint!("\r{} of {} ", progress.current, progress.total);
        }
    }));

    let status = match status {
        Ok(status) => status,
        Err(e) => {
            eprintln!("grt-sentry: {e}");
            return 2;
        }
    };

    if interactive {
        eprintln!();
    }
    print_status(&status);
    notify_if_needed(&status);

    if status.clean {
        0
    } else {
        1
    }
}

fn print_last_status() -> i32 {
    let Ok(state) = state() else { return 2 };
    let conn = state.db.lock().unwrap();

    match crate::db::recent_scans(&conn, 5) {
        Ok(scans) if !scans.is_empty() => {
            for scan in scans {
                println!(
                    "{}  {} files  {} issues",
                    format_time(scan.timestamp),
                    scan.files_checked,
                    scan.issues_found
                );
            }
            0
        }
        _ => {
            println!("No scan has been run yet.");
            0
        }
    }
}

fn print_connections() -> i32 {
    let Ok(state) = state() else { return 2 };
    let conn = state.db.lock().unwrap();

    match crate::netmon::snapshot(&conn, state.geo.as_ref()) {
        Ok(connections) => {
            for c in connections {
                let location = c.location.as_ref().map(|l| l.label()).unwrap_or_else(|| {
                    if c.private { "local network".into() } else { "unknown location".into() }
                });
                println!(
                    "{:<5} {:>21} {:<12} {:<28} {}",
                    c.protocol,
                    format!("{}:{}", c.remote_addr, c.remote_port),
                    c.state,
                    c.process_name.clone().unwrap_or_else(|| "-".into()),
                    location
                );
            }
            0
        }
        Err(e) => {
            eprintln!("grt-sentry: {e}");
            2
        }
    }
}

fn print_status(status: &SystemStatus) {
    let counts = format!("{} files checked, {} connections", status.files_checked, status.active_connections);

    if status.clean {
        println!("Nothing needs attention. {counts}.");
    } else {
        let serious = status.issues.iter().filter(|i| i.severity != Severity::Info).count();
        let plural = if serious == 1 { "thing needs" } else { "things need" };
        println!("{serious} {plural} attention. {counts}.");
    }

    for issue in &status.issues {
        let mark = match issue.severity {
            Severity::Critical => "!!",
            Severity::Warning => " !",
            Severity::Info => "  ",
        };
        println!("{mark} {}\n     {}", issue.title, issue.location);
    }
}

/// A desktop notification, when there is a desktop to notify.
fn notify_if_needed(status: &SystemStatus) {
    let serious = status.issues.iter().filter(|i| i.severity != Severity::Info).count();
    if serious == 0 {
        return;
    }

    let urgent = status.issues.iter().any(|i| i.severity == Severity::Critical);
    let plural = if serious == 1 { "thing needs" } else { "things need" };

    crate::platform::notify(
        "GRT Sentry",
        &format!("{serious} {plural} attention. Open GRT Sentry to see them."),
        urgent,
    );
}

fn format_time(timestamp: i64) -> String {
    chrono::Local
        .timestamp_opt(timestamp, 0)
        .single()
        .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| timestamp.to_string())
}

use chrono::TimeZone;

/// Stops a running scan, which is the same flag the headless scan honours.
pub fn cancel(state: &AppState) {
    state.cancel.store(true, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_with_nothing_serious_prints_as_clean() {
        // Only checks that formatting an empty status does not panic.
        print_status(&SystemStatus::default());
    }

    #[test]
    fn the_usage_text_lists_every_mode_the_parser_accepts() {
        for mode in ["--scan", "--status", "--connections", "--where", "--version", "--help"] {
            assert!(USAGE.contains(mode), "{mode} is accepted but not documented");
        }
    }
}
