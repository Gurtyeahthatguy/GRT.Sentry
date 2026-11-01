//! Processes that run from somewhere a program should not run from.
//!
//! The connection monitor only sees processes that hold a socket. This looks
//! at every process this user may inspect and asks where its executable is:
//! deleted from the disk, held only in memory, or in a folder that anyone can
//! write to and that is emptied on reboot.
//!
//! A program whose file was replaced by an update is the innocent case of a
//! deleted executable, and the common one, so it is told apart: when a file is
//! back at the same path, the process is only running the old copy.

use std::path::Path;

use crate::indicators::Indicators;
use crate::platform::{self, ProcessInfo};
use crate::state::{Action, Finding, Issue, IssueKind, IssueTarget, Severity};

/// What is unusual about where one process runs from.
#[derive(Debug, Clone, PartialEq)]
pub enum Oddity {
    /// The file is gone and nothing replaced it.
    Deleted { path: String },
    /// The file was replaced, usually by an update.
    Replaced { path: String },
    /// An anonymous file in memory, which never touched the disk.
    MemoryOnly { label: String },
    /// A temporary folder, writable by everyone.
    Temporary { path: String },
    Downloads { path: String },
    /// A path or name in the user's own indicators.
    Indicator { path: String, note: String },
}

/// Folders where a running program is a reason to look.
const TEMPORARY: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/"];

/// What is odd about one process, if anything.
pub fn classify(process: &ProcessInfo, downloads: &Path, indicators: &Indicators, exists: &dyn Fn(&str) -> bool) -> Option<Oddity> {
    let exe = process.exe.as_deref()?;

    if let Some(note) = indicators.match_path(exe).or_else(|| indicators.match_name(&process.name)) {
        return Some(Oddity::Indicator { path: exe.to_string(), note });
    }

    if exe.starts_with("/memfd:") {
        return Some(Oddity::MemoryOnly { label: exe.trim_end_matches(" (deleted)").to_string() });
    }
    if let Some(path) = exe.strip_suffix(" (deleted)") {
        return Some(if exists(path) {
            Oddity::Replaced { path: path.to_string() }
        } else {
            Oddity::Deleted { path: path.to_string() }
        });
    }

    // AppImages run from a mount under /tmp, which is their normal place.
    if TEMPORARY.iter().any(|dir| exe.starts_with(dir)) && !exe.starts_with("/tmp/.mount_") {
        return Some(Oddity::Temporary { path: exe.to_string() });
    }
    let windows_temp = std::env::var("TEMP").ok().filter(|t| !t.is_empty());
    if let Some(temp) = windows_temp {
        if exe.to_ascii_lowercase().starts_with(&temp.to_ascii_lowercase()) {
            return Some(Oddity::Temporary { path: exe.to_string() });
        }
    }
    if Path::new(exe).starts_with(downloads) {
        return Some(Oddity::Downloads { path: exe.to_string() });
    }
    None
}

pub fn findings(indicators: &Indicators) -> Vec<Finding> {
    let downloads = platform::user_dir("DOWNLOAD", "Downloads");
    let exists = |path: &str| Path::new(path).exists();
    let mine = std::process::id() as i32;

    let mut findings = Vec::new();
    let mut replaced: Vec<String> = Vec::new();

    for process in platform::processes() {
        if process.pid == mine {
            continue;
        }
        let Some(oddity) = classify(&process, &downloads, indicators, &exists) else { continue };
        if let Oddity::Replaced { .. } = oddity {
            replaced.push(format!("{} (pid {})", process.name, process.pid));
            continue;
        }
        findings.push(finding(&process, &oddity));
    }

    // After an update this list can be long, and it is a reminder, not an
    // alarm, so it is one line.
    if !replaced.is_empty() {
        replaced.sort();
        replaced.dedup();
        findings.push(Finding::note(Issue {
            kind: IssueKind::SuspiciousProcess,
            severity: Severity::Info,
            title: format!(
                "{} {} still running the version from before an update",
                replaced.len(),
                if replaced.len() == 1 { "program is" } else { "programs are" }
            ),
            location: "Processes".to_string(),
            detail: Some(format!(
                "Their files were replaced on disk, usually by an update, and they keep running the old copy until they are restarted:\n\n{}",
                replaced.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
            )),
            actions: vec![Action::ignore()],
            ..Default::default()
        }));
    }

    findings
}

fn finding(process: &ProcessInfo, oddity: &Oddity) -> Finding {
    let who = format!("{} (pid {})", process.name, process.pid);
    let (severity, title, detail) = match oddity {
        Oddity::Deleted { path } => (
            Severity::Warning,
            format!("{who} runs from a file that no longer exists"),
            format!(
                "Its executable was {path}, which has been deleted and not replaced. A program that removes itself after starting leaves no file to scan, which is why malware does it."
            ),
        ),
        Oddity::MemoryOnly { label } => (
            Severity::Warning,
            format!("{who} runs from memory only"),
            format!(
                "Its executable is {label}, an anonymous file that never touched the disk. A few container runtimes start this way; most programs that do are trying not to be found."
            ),
        ),
        Oddity::Temporary { path } => (
            Severity::Warning,
            format!("{who} runs from a temporary folder"),
            format!(
                "Its executable is {path}. Anyone on the machine can write there and the folder is emptied on reboot; nothing installed properly runs from it."
            ),
        ),
        Oddity::Downloads { path } => (
            Severity::Info,
            format!("{who} runs from the downloads folder"),
            format!(
                "Its executable is {path}. That is normal for something just downloaded on purpose, and worth a look otherwise."
            ),
        ),
        Oddity::Indicator { path, note } => (
            Severity::Critical,
            format!("{who} matches one of your indicators"),
            format!("Its executable is {path}, which your indicators file lists: {note}"),
        ),
        Oddity::Replaced { .. } => unreachable!("grouped by the caller"),
    };

    Finding::new(
        Issue {
            kind: IssueKind::SuspiciousProcess,
            severity,
            title,
            location: who,
            detail: Some(detail),
            actions: vec![Action::new("kill_process", "Stop process", true), Action::ignore()],
            ..Default::default()
        },
        IssueTarget::Process { pid: process.pid, name: process.name.clone() },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(exe: &str) -> ProcessInfo {
        ProcessInfo { pid: 4242, name: "thing".into(), exe: Some(exe.to_string()) }
    }

    fn classify_with(exe: &str, present: &'static [&'static str]) -> Option<Oddity> {
        let exists = move |p: &str| present.contains(&p);
        classify(&process(exe), Path::new("/home/u/Downloads"), &Indicators::default(), &exists)
    }

    #[test]
    fn an_updated_program_is_told_apart_from_one_that_deleted_itself() {
        assert_eq!(
            classify_with("/usr/lib/firefox/firefox (deleted)", &["/usr/lib/firefox/firefox"]),
            Some(Oddity::Replaced { path: "/usr/lib/firefox/firefox".into() })
        );
        assert_eq!(
            classify_with("/home/u/.x/miner (deleted)", &[]),
            Some(Oddity::Deleted { path: "/home/u/.x/miner".into() })
        );
    }

    #[test]
    fn memory_temporary_and_downloads_are_each_named() {
        assert!(matches!(classify_with("/memfd:payload (deleted)", &[]), Some(Oddity::MemoryOnly { .. })));
        assert!(matches!(classify_with("/dev/shm/.k", &[]), Some(Oddity::Temporary { .. })));
        assert!(matches!(classify_with("/tmp/x", &[]), Some(Oddity::Temporary { .. })));
        assert!(matches!(classify_with("/home/u/Downloads/tool", &[]), Some(Oddity::Downloads { .. })));
    }

    #[test]
    fn ordinary_places_and_appimages_are_left_alone() {
        assert_eq!(classify_with("/usr/bin/bash", &[]), None);
        assert_eq!(classify_with("/tmp/.mount_GRT_Sxyz/usr/bin/grt-sentry", &[]), None);
        assert_eq!(classify_with("/home/u/.local/bin/tool", &[]), None);
        assert_eq!(classify(&ProcessInfo { pid: 2, name: "kthreadd".into(), exe: None }, Path::new("/d"), &Indicators::default(), &|_| true), None);
    }

    #[test]
    fn an_indicator_outranks_everything_else() {
        let indicators = Indicators::parse("/opt/evil/\n");
        let found = classify(&process("/opt/evil/run"), Path::new("/d"), &indicators, &|_| true);
        assert!(matches!(found, Some(Oddity::Indicator { .. })));
        assert_eq!(finding(&process("/opt/evil/run"), &found.unwrap()).issue.severity, Severity::Critical);
    }

    #[test]
    fn a_found_process_can_be_stopped_but_asks_first() {
        let f = finding(&process("/dev/shm/x"), &Oddity::Temporary { path: "/dev/shm/x".into() });
        let stop = f.issue.actions.iter().find(|a| a.id == "kill_process").unwrap();
        assert!(stop.destructive);
        assert!(matches!(f.target, IssueTarget::Process { pid: 4242, .. }));
    }
}
