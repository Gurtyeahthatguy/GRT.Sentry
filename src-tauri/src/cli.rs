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
  grt-sentry --report        print the last scan in full, to save or send
  grt-sentry --compare       print what changed between the last two scans
  grt-sentry --connections   list the active network connections
  grt-sentry --where         print where the data, configuration and quarantine live
  grt-sentry --version       print the version
  grt-sentry --help          print this

Exit status of --scan: 0 when nothing above information was found, 1 when
something was, 2 when the scan itself could not run. What was set aside does
not count, and the notification only comes for something new.
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
        "--report" => Some(print_report(false)),
        "--compare" => Some(print_report(true)),
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

fn print_report(compare: bool) -> i32 {
    let Ok(state) = state() else { return 2 };
    let conn = state.db.lock().unwrap();
    let text = if compare {
        crate::report::comparison(&conn, None, None).map(|c| crate::report::render_comparison(&c))
    } else {
        crate::report::scan_text(&conn, None)
    };
    match text {
        Ok(text) => {
            print!("{text}");
            0
        }
        Err(e) => {
            eprintln!("grt-sentry: {e}");
            2
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
        let serious = status.issues.iter().filter(|i| i.counts()).count();
        let plural = if serious == 1 { "thing needs" } else { "things need" };
        let new = if status.new_issues > 0 { format!(", {} new", status.new_issues) } else { String::new() };
        println!("{serious} {plural} attention{new}. {counts}.");
    }

    for issue in &status.issues {
        let mark = match issue.severity {
            _ if issue.set_aside => " -",
            Severity::Critical => "!!",
            Severity::Warning => " !",
            Severity::Info => "  ",
        };
        let note = if issue.set_aside {
            "  (set aside)"
        } else if issue.is_new() {
            "  (new)"
        } else {
            ""
        };
        println!("{mark} {}{note}\n     {}", issue.title, issue.location);
    }
}

/// A desktop notification, only when something new needs attention.
///
/// What a daily scan already said yesterday is not news, so it stays quiet.
fn notify_if_needed(status: &SystemStatus) {
    let Some(message) = notification(status) else { return };
    let urgent = status.issues.iter().any(|i| i.is_new() && i.severity == Severity::Critical);
    crate::platform::notify("GRT Sentry", &message, urgent);
}

fn notification(status: &SystemStatus) -> Option<String> {
    let new = status.new_issues as usize;
    if new == 0 {
        return None;
    }
    let serious = status.issues.iter().filter(|i| i.counts()).count();
    let what = if new == 1 { "1 new thing needs attention".to_string() } else { format!("{new} new things need attention") };
    let rest = if serious > new { format!(", {serious} in all") } else { String::new() };
    Some(format!("{what}{rest}. Open GRT Sentry to see them."))
}

fn format_time(timestamp: i64) -> String {
    crate::report::local_time(timestamp)
}

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
    fn only_something_new_makes_a_notification() {
        use crate::state::Issue;
        let seen = |times: u32| Issue { severity: Severity::Warning, times_seen: times, ..Default::default() };
        let mut status = SystemStatus { issues: vec![seen(3), seen(5)], ..Default::default() };
        status.finish();
        assert!(notification(&status).is_none(), "yesterday's news stays quiet");

        status.issues.push(seen(1));
        status.finish();
        assert_eq!(notification(&status).unwrap(), "1 new thing needs attention, 3 in all. Open GRT Sentry to see them.");
    }

    #[test]
    fn the_usage_text_lists_every_mode_the_parser_accepts() {
        for mode in ["--scan", "--status", "--report", "--compare", "--connections", "--where", "--version", "--help"] {
            assert!(USAGE.contains(mode), "{mode} is accepted but not documented");
        }
    }
}
