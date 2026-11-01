//! Whole system folders compared with what was there, as AIDE does, kept small
//! by leaving to the package check what it already knows.
//!
//! In `/usr/bin` and `/usr/sbin` every file should come from a package, and
//! the package check already verifies those against their hashes. What is left
//! is the file no package explains, which is reported as soon as it is seen.
//!
//! In the folders of `/etc` that decide who logs in, what loads and what runs
//! as root, every file is recorded on the first scan. A later change is quiet
//! when it is the package's own version of a configuration file, as after an
//! update, and reported otherwise.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use rusqlite::Connection;

use crate::db;
use crate::platform;
use crate::scanner;
use crate::state::{Action, Finding, Issue, IssueKind, IssueTarget, Severity};

const KIND: &str = "folder";

/// Where every file should come from a package.
const PROGRAM_DIRS: &[&str] = &["/usr/bin", "/usr/sbin", "/bin", "/sbin"];

/// Where programs installed by hand go, so only a new one is mentioned.
const LOCAL_DIRS: &[&str] = &["/usr/local/bin", "/usr/local/sbin"];

/// The parts of /etc that decide who gets in and what runs as root.
const CONFIG_DIRS: &[&str] = &[
    "/etc/sudoers.d", "/etc/pam.d", "/etc/security", "/etc/ld.so.conf.d", "/etc/ssh/sshd_config.d", "/etc/udev/rules.d",
    "/etc/apt/sources.list.d", "/etc/yum.repos.d", "/etc/systemd/system", "/etc/init.d", "/etc/cron.d",
    "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
];

/// Single files with the same weight.
const CONFIG_FILES: &[&str] = &["/etc/rc.local", "/etc/ld.so.conf", "/etc/environment", "/etc/apt/sources.list"];

/// Where a link may point without it being strange.
const LINK_TARGETS: &[&str] = &["/usr/", "/etc/", "/opt/", "/snap/", "/var/lib/", "/bin/", "/sbin/", "/lib"];

#[derive(Debug, Clone, PartialEq)]
pub enum Entry {
    File { path: String },
    Link { path: String, target: String },
}

impl Entry {
    fn path(&self) -> &str {
        match self {
            Entry::File { path } | Entry::Link { path, .. } => path,
        }
    }
}

/// The files directly in a folder, or two levels down for /etc's.
fn list(dir: &str, depth: usize) -> Vec<Entry> {
    let root = Path::new(dir);
    if std::fs::symlink_metadata(root).map(|m| m.file_type().is_symlink()).unwrap_or(true) {
        return vec![];
    }
    walkdir::WalkDir::new(root)
        .max_depth(depth)
        .follow_links(false)
        .into_iter()
        // Enabled units are links in .wants folders, which the startup check
        // already lists.
        .filter_entry(|e| !e.file_name().to_string_lossy().ends_with(".wants") && !e.file_name().to_string_lossy().ends_with(".requires"))
        .flatten()
        .filter_map(|e| {
            let path = e.path().to_string_lossy().into_owned();
            if e.file_type().is_symlink() {
                let target = std::fs::read_link(e.path()).ok()?.to_string_lossy().into_owned();
                Some(Entry::Link { path, target })
            } else if e.file_type().is_file() {
                Some(Entry::File { path })
            } else {
                None
            }
        })
        .collect()
}

fn resolved(link: &str, target: &str) -> String {
    if target.starts_with('/') {
        return target.to_string();
    }
    let base = Path::new(link).parent().unwrap_or(Path::new("/"));
    base.join(target).to_string_lossy().into_owned()
}

pub fn findings(conn: &Connection) -> Vec<Finding> {
    let programs: Vec<Entry> = PROGRAM_DIRS.iter().flat_map(|d| list(d, 1)).collect();
    let local: Vec<Entry> = LOCAL_DIRS.iter().flat_map(|d| list(d, 1)).collect();
    let mut config: Vec<Entry> = CONFIG_DIRS.iter().flat_map(|d| list(d, 2)).collect();
    config.extend(CONFIG_FILES.iter().filter(|f| Path::new(f).is_file()).map(|f| Entry::File { path: f.to_string() }));

    let query: Vec<String> = programs.iter().chain(config.iter()).map(|e| e.path().to_string()).collect();
    let owned = platform::packaged(&query);
    let conffiles = platform::package_conffiles();

    let digest = |path: &str| scanner::hash_file(Path::new(path)).ok();
    judge_all(conn, &programs, &local, &config, owned.as_ref(), &conffiles, &digest)
}

/// Everything that does not touch the filesystem's real folders, so a test
/// can hand it made-up ones.
pub fn judge_all(
    conn: &Connection,
    programs: &[Entry],
    local: &[Entry],
    config: &[Entry],
    owned: Option<&HashSet<String>>,
    conffiles: &HashMap<String, String>,
    digest: &dyn Fn(&str) -> Option<String>,
) -> Vec<Finding> {
    let first_run = !db::baseline_started(conn, KIND);
    let mut findings = Vec::new();
    let accepted = |path: &str, value: &str| db::baseline_value(conn, KIND, path).as_deref() == Some(value);

    // Programs no package installed, and links pointing somewhere odd.
    if let Some(owned) = owned {
        for entry in programs {
            match entry {
                Entry::File { path } if !owned.contains(path) => {
                    let Some(hash) = digest(path) else { continue };
                    if accepted(path, &hash) {
                        continue;
                    }
                    findings.push(finding(
                        Severity::Warning,
                        format!("A program no package installed: {path}"),
                        format!(
                            "{path} is in a folder that only the package manager fills, and no installed package owns it. Something installed by hand with `make install` or a vendor script explains it; so does a replacement dropped in by an intruder.\n\nSHA-256: {hash}"
                        ),
                        path,
                        hash,
                    ));
                }
                Entry::Link { path, target } => {
                    let resolved = resolved(path, target);
                    if LINK_TARGETS.iter().any(|t| resolved.starts_with(t)) || owned.contains(path) {
                        continue;
                    }
                    let value = format!("link:{resolved}");
                    if accepted(path, &value) {
                        continue;
                    }
                    findings.push(finding(
                        Severity::Warning,
                        format!("A system command points outside the system: {path}"),
                        format!(
                            "{path} is a link to {resolved}. Commands in this folder run with whatever rights their caller has, root included, and the place it points to is not one the system keeps."
                        ),
                        path,
                        value,
                    ));
                }
                _ => {}
            }
        }
    }

    // Programs installed by hand: recorded, and mentioned when new.
    for entry in local {
        let path = entry.path();
        let value = match entry {
            Entry::File { .. } => match digest(path) {
                Some(hash) => hash,
                None => continue,
            },
            Entry::Link { target, .. } => format!("link:{}", resolved(path, target)),
        };
        match db::baseline_value(conn, KIND, path) {
            Some(known) if known == value => {}
            _ if first_run => {
                let _ = db::set_baseline_value(conn, KIND, path, &value);
            }
            known => findings.push(finding(
                Severity::Info,
                format!("{} program in {}: {path}", if known.is_some() { "Changed" } else { "New" }, parent(path)),
                format!("{path} {} since the last scan. Programs installed by hand go here, so this is usually one of yours.", if known.is_some() { "changed" } else { "appeared" }),
                path,
                value,
            )),
        }
    }

    // Configuration that decides who gets in.
    for entry in config {
        let path = entry.path();
        let value = match entry {
            Entry::File { .. } => match digest(path) {
                Some(hash) => hash,
                None => continue,
            },
            Entry::Link { target, .. } => format!("link:{}", resolved(path, target)),
        };
        let known = db::baseline_value(conn, KIND, path);
        if known.as_deref() == Some(value.as_str()) {
            continue;
        }
        // The package's own version, as an update leaves it.
        let as_shipped = conffiles.get(path).is_some_and(|shipped| {
            crate::packages::digest_like(Path::new(path), shipped).map(|d| &d == shipped).unwrap_or(false)
        });
        let packaged = owned.is_some_and(|o| o.contains(path));
        if first_run || as_shipped || (packaged && !conffiles.contains_key(path)) {
            let _ = db::set_baseline_value(conn, KIND, path, &value);
            continue;
        }
        let changed = known.is_some();
        findings.push(finding(
            Severity::Warning,
            format!("{} {path}", if changed { "Changed:" } else { "New file:" }),
            format!(
                "{path} {} since the last scan, and it is not the version a package ships. Files here decide who can log in, what runs as root and what every program loads, which makes them where an intruder makes a stay permanent.\n\nIf you or an installation did this, confirm it. Otherwise read it first:\n\n    sudo cat {path}",
                if changed { "changed" } else { "appeared" }
            ),
            path,
            value,
        ));
    }

    if first_run {
        let _ = db::mark_baseline_started(conn, KIND);
    }
    findings
}

fn parent(path: &str) -> String {
    Path::new(path).parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default()
}

fn finding(severity: Severity, title: String, detail: String, path: &str, value: String) -> Finding {
    Finding::new(
        Issue {
            kind: IssueKind::FolderChanged,
            severity,
            title,
            location: path.to_string(),
            detail: Some(detail),
            actions: vec![Action::new("update_baseline", "This was expected", false), Action::ignore()],
            ..Default::default()
        },
        IssueTarget::Baseline { kind: KIND.to_string(), key: path.to_string(), value },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str) -> Entry {
        Entry::File { path: path.into() }
    }

    fn hashes(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |p: &str| pairs.iter().find(|(k, _)| *k == p).map(|(_, v)| v.to_string())
    }

    #[test]
    fn an_unpackaged_program_is_reported_on_the_first_scan_and_quiet_once_accepted() {
        let conn = crate::db::open_memory();
        let owned: HashSet<String> = ["/usr/bin/ls".to_string()].into();
        let programs = [file("/usr/bin/ls"), file("/usr/bin/.sshd")];
        let digest = hashes(&[("/usr/bin/ls", "aa"), ("/usr/bin/.sshd", "bb")]);

        let found = judge_all(&conn, &programs, &[], &[], Some(&owned), &HashMap::new(), &digest);
        assert_eq!(found.len(), 1);
        assert!(found[0].issue.title.contains("/usr/bin/.sshd"));

        let IssueTarget::Baseline { kind, key, value } = &found[0].target else { panic!() };
        crate::db::set_baseline_value(&conn, kind, key, value).unwrap();
        assert!(judge_all(&conn, &programs, &[], &[], Some(&owned), &HashMap::new(), &digest).is_empty());

        // Replaced again: new contents, reported again.
        let changed = hashes(&[("/usr/bin/ls", "aa"), ("/usr/bin/.sshd", "cc")]);
        assert_eq!(judge_all(&conn, &programs, &[], &[], Some(&owned), &HashMap::new(), &changed).len(), 1);
    }

    #[test]
    fn a_command_linked_into_tmp_is_reported_and_alternatives_are_not() {
        let conn = crate::db::open_memory();
        let programs = [
            Entry::Link { path: "/usr/bin/editor".into(), target: "/etc/alternatives/editor".into() },
            Entry::Link { path: "/usr/bin/python3".into(), target: "python3.12".into() },
            Entry::Link { path: "/usr/bin/sudo2".into(), target: "/tmp/.s".into() },
        ];
        let found = judge_all(&conn, &programs, &[], &[], Some(&HashSet::new()), &HashMap::new(), &|_| None);
        assert_eq!(found.len(), 1);
        assert!(found[0].issue.detail.as_ref().unwrap().contains("/tmp/.s"));
    }

    #[test]
    fn config_is_recorded_first_and_an_update_to_the_shipped_version_is_quiet() {
        let dir = tempfile::tempdir().unwrap();
        let pam = dir.path().join("sshd");
        std::fs::write(&pam, b"auth include common-auth\n").unwrap();
        let pam_path = pam.to_string_lossy().into_owned();
        let config = [file(&pam_path)];
        let conn = crate::db::open_memory();
        let real = |p: &str| scanner::hash_file(Path::new(p)).ok();

        assert!(judge_all(&conn, &[], &[], &config, None, &HashMap::new(), &real).is_empty(), "first scan records");

        // An update ships a new version of the file, recorded in dpkg.
        std::fs::write(&pam, b"auth include common-auth\nsession optional pam_motd.so\n").unwrap();
        let shipped_md5 = format!("{:x}", <md5::Md5 as sha2::Digest>::digest(std::fs::read(&pam).unwrap()));
        let conffiles: HashMap<String, String> = [(pam_path.clone(), shipped_md5)].into();
        assert!(judge_all(&conn, &[], &[], &config, None, &conffiles, &real).is_empty(), "the package's own version");

        // Someone adds a line of their own.
        std::fs::write(&pam, b"auth sufficient pam_permit.so\nauth include common-auth\n").unwrap();
        let found = judge_all(&conn, &[], &[], &config, None, &conffiles, &real);
        assert_eq!(found.len(), 1);
        assert!(found[0].issue.title.starts_with("Changed:"));
        assert_eq!(found[0].issue.severity, Severity::Warning);
    }

    #[test]
    fn a_new_file_in_a_watched_config_folder_is_reported() {
        let conn = crate::db::open_memory();
        let digest = hashes(&[("/etc/sudoers.d/README", "r"), ("/etc/sudoers.d/99-x", "x")]);
        judge_all(&conn, &[], &[], &[file("/etc/sudoers.d/README")], None, &HashMap::new(), &digest);
        let found = judge_all(&conn, &[], &[], &[file("/etc/sudoers.d/README"), file("/etc/sudoers.d/99-x")], None, &HashMap::new(), &digest);
        assert_eq!(found.len(), 1);
        assert!(found[0].issue.title.starts_with("New file:"));
    }

    #[test]
    fn programs_installed_by_hand_are_mentioned_only_when_new() {
        let conn = crate::db::open_memory();
        let digest = hashes(&[("/usr/local/bin/a", "1"), ("/usr/local/bin/b", "2")]);
        assert!(judge_all(&conn, &[], &[file("/usr/local/bin/a")], &[], None, &HashMap::new(), &digest).is_empty());
        let found = judge_all(&conn, &[], &[file("/usr/local/bin/a"), file("/usr/local/bin/b")], &[], None, &HashMap::new(), &digest);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].issue.severity, Severity::Info);
    }

    /// Machine-dependent, so run by scripts/check-false-positives.sh.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore]
    fn on_this_machine_every_program_in_usr_bin_has_a_package() {
        let programs = list("/usr/bin", 1);
        let query: Vec<String> = programs.iter().map(|e| e.path().to_string()).collect();
        let Some(owned) = platform::packaged(&query) else { return };
        let conn = crate::db::open_memory();
        let digest = |p: &str| scanner::hash_file(Path::new(p)).ok();
        let found = judge_all(&conn, &programs, &[], &[], Some(&owned), &HashMap::new(), &digest);
        let titles: Vec<_> = found.iter().map(|f| f.issue.title.clone()).collect();
        assert!(found.is_empty(), "{titles:?}");
    }
}
