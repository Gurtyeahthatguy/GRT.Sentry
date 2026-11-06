//! The data model the frontend sees, and the state kept between commands.
//!
//! Everything the interface renders is an `Issue`, so a file, a connection, a
//! missing update and a changed system file all arrive in the same shape with
//! their own list of `Action`s.
//!
//! An `Issue` carries no path and no pid. The frontend sends back an issue id
//! and an action id, and `IssueTarget`, which is never serialised, is what the
//! backend acts on.

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::geoip::GeoDb;

/// How much attention something deserves.
///
/// The variants are in order of severity: derived `Ord` sorts the issue list,
/// so `Critical` stays last.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Worth knowing, needs nothing done.
    Info,
    /// Suspicious. A person has to look at it and decide.
    Warning,
    /// Malicious with high confidence.
    Critical,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum IssueKind {
    MaliciousFile,
    /// A file no engine has ever seen. Not a verdict, just an absence of one.
    UnknownFile,
    SuspiciousConnection,
    OutdatedSecurityPackage,
    UnknownAutostartEntry,
    FailedLoginAttempts,
    IntegrityChanged,
    /// A file that matched one of GRT Sentry's own rules.
    RuleMatch,
    /// An archive a limit or a password kept from being checked completely.
    UncheckedArchive,
    /// A system program whose contents differ from what its package installed.
    PackageMismatch,
    /// A process running from a deleted file, from memory or from a temporary folder.
    SuspiciousProcess,
    /// Something the kernel answers for that the usual listings leave out.
    HiddenActivity,
    /// A kernel module that was not loaded before.
    KernelModule,
    BrowserExtension,
    /// Set-user-ID, set-group-ID or capabilities where they hand out privilege.
    SpecialPermission,
    /// A setting that leaves a door open: SSH, sudo, the search path.
    WeakConfiguration,
    /// A new account, a new sudo user, a login at an unusual hour.
    AccountActivity,
    /// A file in a watched system folder that no package explains.
    FolderChanged,
    /// A module could not run, for want of a key or a permission.
    ModuleUnavailable,
}

/// One button under an issue.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Action {
    /// "quarantine", "delete", "block_ip", "kill_process", "trust", "ignore",
    /// "update_baseline", "upload_vt".
    pub id: String,
    pub label: String,
    /// The interface asks for confirmation before sending a destructive one.
    pub destructive: bool,
}

impl Action {
    pub fn new(id: &str, label: &str, destructive: bool) -> Self {
        Self { id: id.to_string(), label: label.to_string(), destructive }
    }

    /// Moves an issue out of the way until it changes.
    pub fn ignore() -> Self {
        Action::new("ignore", "Set aside", false)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Issue {
    /// Stable within a scan. Actions refer to an issue by this id.
    pub id: String,
    pub kind: IssueKind,
    pub severity: Severity,
    /// One line: "Trojan.GenericKD detected".
    pub title: String,
    /// A path, or "node (pid 4821) to 185.220.101.7:443".
    pub location: String,
    /// The longer explanation shown under the title.
    pub detail: Option<String>,
    pub actions: Vec<Action>,
    /// What stays the same about this problem from one scan to the next.
    #[serde(skip)]
    pub fingerprint: String,
    /// When a scan first reported it, and how many scans have.
    #[serde(default)]
    pub first_seen: i64,
    #[serde(default)]
    pub times_seen: u32,
    /// Set aside by the user: still listed, never counted.
    #[serde(default)]
    pub set_aside: bool,
}

impl Issue {
    /// Above information and not set aside.
    pub fn counts(&self) -> bool {
        self.severity != Severity::Info && !self.set_aside
    }

    /// Counts, and no earlier scan reported it.
    pub fn is_new(&self) -> bool {
        self.counts() && self.times_seen <= 1
    }
}

impl Default for Issue {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            kind: IssueKind::ModuleUnavailable,
            severity: Severity::Info,
            title: String::new(),
            location: String::new(),
            detail: None,
            actions: vec![],
            fingerprint: String::new(),
            first_seen: 0,
            times_seen: 0,
            set_aside: false,
        }
    }
}

/// What an action operates on. Never crosses the IPC boundary.
#[derive(Clone, Debug)]
pub enum IssueTarget {
    File { path: String, sha256: String },
    Connection { ip: String, pid: Option<i32>, process: Option<String> },
    Integrity { path: String, current_hash: String },
    Package { path: String, digest: String },
    Process { pid: i32, name: String },
    /// Something a check recorded, which "Expected" makes the new normal.
    Baseline { kind: String, key: String, value: String },
    Autostart { key: String, name: String },
    Packages { names: Vec<String> },
    LoginAttempts { ip: String, failures: u32 },
    /// Addresses the automatic response offers to block in one go.
    BlockProposal { ips: Vec<String> },
    /// Nothing to act on.
    Informational,
}

/// An issue together with what it refers to.
///
/// `dashboard.rs` sends the `Issue` half to the interface and keeps the
/// `IssueTarget` half in the snapshot.
pub struct Finding {
    pub issue: Issue,
    pub target: IssueTarget,
}

impl Finding {
    pub fn new(issue: Issue, target: IssueTarget) -> Self {
        Self { issue, target }
    }

    /// A finding with nothing to act on.
    pub fn note(issue: Issue) -> Self {
        Self { issue, target: IssueTarget::Informational }
    }
}

/// The whole result of a scan, as the Status tab renders it.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SystemStatus {
    /// True when nothing above `Info` was found.
    pub clean: bool,
    /// UNIX timestamp, seconds.
    pub last_scan: i64,
    pub files_checked: u32,
    pub active_connections: u32,
    /// Files hashed but still waiting for a VirusTotal answer.
    pub queued_files: u32,
    pub issues: Vec<Issue>,
    /// Issues that count and that no earlier scan reported.
    #[serde(default)]
    pub new_issues: u32,
    /// The row in the scan history, 0 before it is recorded.
    #[serde(default)]
    pub scan_id: i64,
}

impl Default for SystemStatus {
    fn default() -> Self {
        Self {
            clean: true,
            last_scan: 0,
            files_checked: 0,
            active_connections: 0,
            queued_files: 0,
            issues: vec![],
            new_issues: 0,
            scan_id: 0,
        }
    }
}

impl SystemStatus {
    /// Sorts worst first with what was set aside last, and recomputes the counts.
    ///
    /// The sort is stable, so issues of equal severity keep the order the
    /// modules produced them in.
    pub fn finish(&mut self) {
        self.issues.sort_by_key(|issue| (issue.set_aside, std::cmp::Reverse(issue.severity)));
        self.clean = !self.issues.iter().any(Issue::counts);
        self.new_issues = self.issues.iter().filter(|i| i.is_new()).count() as u32;
    }
}

/// A scan's issues, kept so a later action knows what an issue id refers to.
#[derive(Default)]
pub struct Snapshot {
    pub status: SystemStatus,
    pub targets: HashMap<String, IssueTarget>,
}

/// Everything shared between commands.
///
/// The database sits behind a `Mutex` because `rusqlite::Connection` is `Send`
/// but not `Sync`. No lock is held across an `await`.
pub struct AppState {
    pub db: Mutex<rusqlite::Connection>,
    /// `None` when the GeoLite2 database is not installed.
    pub geo: Option<GeoDb>,
    pub config: Mutex<Config>,
    pub snapshot: Mutex<Snapshot>,
    /// Set while a scan runs, so a second cannot start on top of it.
    pub scanning: AtomicBool,
    /// Raised by `cancel_scan` and checked between files.
    pub cancel: AtomicBool,
    /// Serialises VirusTotal requests and keeps them 15 seconds apart.
    pub vt: crate::scanner::RateLimiter,
}

impl AppState {
    /// Opens the database, reads the configuration and loads the GeoIP data.
    ///
    /// `bundled_geoip` is the packaged copy's path when the caller knows it.
    pub fn new(bundled_geoip: Option<std::path::PathBuf>) -> Result<Self, String> {
        let db = crate::db::open()?;
        let config = Config::load();

        // Written back on every start, so a first run leaves a file to edit.
        if let Err(e) = config.save() {
            eprintln!("grt-sentry: could not write the configuration: {e}");
        }

        Ok(Self {
            db: Mutex::new(db),
            geo: GeoDb::discover(bundled_geoip),
            config: Mutex::new(config),
            snapshot: Mutex::new(Snapshot::default()),
            scanning: AtomicBool::new(false),
            cancel: AtomicBool::new(false),
            vt: crate::scanner::RateLimiter::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue(sev: Severity) -> Issue {
        Issue { severity: sev, ..Default::default() }
    }

    #[test]
    fn worst_issues_come_first_and_info_alone_still_counts_as_clean() {
        let mut status = SystemStatus {
            issues: vec![issue(Severity::Info), issue(Severity::Critical), issue(Severity::Warning)],
            ..Default::default()
        };
        status.finish();

        assert_eq!(status.issues[0].severity, Severity::Critical);
        assert_eq!(status.issues[1].severity, Severity::Warning);
        assert!(!status.clean);

        let mut only_info = SystemStatus { issues: vec![issue(Severity::Info)], ..Default::default() };
        only_info.finish();
        assert!(only_info.clean);
    }

    #[test]
    fn what_was_set_aside_goes_last_and_leaves_the_machine_clean() {
        let mut status = SystemStatus {
            issues: vec![
                Issue { severity: Severity::Critical, set_aside: true, times_seen: 4, ..Default::default() },
                Issue { severity: Severity::Info, ..Default::default() },
            ],
            ..Default::default()
        };
        status.finish();
        assert!(status.clean);
        assert_eq!(status.new_issues, 0);
        assert!(status.issues[1].set_aside);

        status.issues.push(Issue { severity: Severity::Warning, times_seen: 1, ..Default::default() });
        status.issues.push(Issue { severity: Severity::Warning, times_seen: 3, ..Default::default() });
        status.finish();
        assert!(!status.clean);
        assert_eq!(status.new_issues, 1, "seen before is not new");
    }

    #[test]
    fn equal_severity_keeps_the_order_the_modules_produced() {
        let mut status = SystemStatus {
            issues: vec![
                Issue { severity: Severity::Warning, title: "first".into(), ..Default::default() },
                Issue { severity: Severity::Warning, title: "second".into(), ..Default::default() },
            ],
            ..Default::default()
        };
        status.finish();
        assert_eq!(status.issues[0].title, "first");
    }
}
