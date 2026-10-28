//! Whether the programs the package manager installed are still the ones it
//! installed.
//!
//! dpkg keeps an MD5 of every file it puts on the disk and rpm a SHA-256, so a
//! system program that was replaced can be found without a network and
//! without signatures. The check covers the places a rootkit replaces things:
//! the `bin` and `sbin` directories and the PAM modules that decide who may
//! log in. Configuration files are left out, since editing them is what they
//! are for; dpkg does not even record a hash for them.
//!
//! A file is hashed again only when its size or change time moved. The change
//! time, unlike the modification time, cannot be set back from user space, so
//! a replacement that copies the old timestamp is still read.

// The readers are for dpkg and rpm, which Windows does not have.
#![cfg_attr(windows, allow(dead_code))]

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use md5::Md5;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::actionlog;
use crate::db;
use crate::platform;
use crate::scanner::ScanProgress;
use crate::state::{Action, Finding, Issue, IssueKind, IssueTarget, Severity};

/// One file as the package manager recorded it.
#[derive(Debug, Clone, PartialEq)]
pub struct PackagedFile {
    pub path: PathBuf,
    /// Lowercase hex: 32 characters for MD5, 64 for SHA-256.
    pub digest: String,
    pub package: Option<String>,
}

/// Which package manager the records came from.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Manager {
    Dpkg,
    Rpm,
}

impl Manager {
    fn verify_command(self, package: Option<&str>) -> String {
        match (self, package) {
            (Manager::Dpkg, Some(name)) => format!("dpkg --verify {name}"),
            (Manager::Dpkg, None) => "dpkg --verify".to_string(),
            (Manager::Rpm, Some(name)) => format!("rpm -V {name}"),
            (Manager::Rpm, None) => "rpm -Va".to_string(),
        }
    }
}

/// Paths relative to the root, with or without the `usr/` that a merged
/// `/usr` adds, compared as one.
fn key(relative: &str) -> &str {
    let relative = relative.trim_start_matches('/');
    relative.strip_prefix("usr/").unwrap_or(relative)
}

/// The directories a replaced file matters most in.
pub fn in_scope(relative: &str) -> bool {
    let relative = key(relative);
    if let Some(rest) = relative.strip_prefix("bin/").or_else(|| relative.strip_prefix("sbin/")) {
        return !rest.is_empty() && !rest.contains('/');
    }
    let parts: Vec<&str> = relative.split('/').collect();
    match parts.as_slice() {
        ["lib" | "lib64", "security", name] | ["lib" | "lib64", _, "security", name] => name.starts_with("pam_"),
        _ => false,
    }
}

// --- dpkg -----------------------------------------------------------------

/// The lines of one `*.md5sums` file that fall in scope.
pub fn parse_md5sums(text: &str, package: &str, root: &Path) -> Vec<PackagedFile> {
    text.lines()
        .filter_map(|line| {
            let (digest, relative) = line.split_once("  ")?;
            if digest.len() != 32 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) || !in_scope(relative) {
                return None;
            }
            Some(PackagedFile {
                path: root.join(relative.trim_start_matches('/')),
                digest: digest.to_ascii_lowercase(),
                package: Some(package.to_string()),
            })
        })
        .collect()
}

/// `/var/lib/dpkg/diversions`: triplets of original, new place, and the
/// package that moved it.
pub fn parse_diversions(text: &str) -> HashMap<String, (String, String)> {
    let lines: Vec<&str> = text.lines().collect();
    lines
        .chunks_exact(3)
        .map(|triplet| (key(triplet[0]).to_string(), (triplet[1].to_string(), triplet[2].to_string())))
        .collect()
}

/// Every in-scope file dpkg installed, from its info directory.
pub fn dpkg_manifest(info_dir: &Path, root: &Path) -> Result<Vec<PackagedFile>, String> {
    let entries = std::fs::read_dir(info_dir).map_err(|e| format!("Cannot read {}: {e}", info_dir.display()))?;

    let diversions = info_dir
        .parent()
        .and_then(|dir| std::fs::read_to_string(dir.join("diversions")).ok())
        .map(|text| parse_diversions(&text))
        .unwrap_or_default();

    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix(".md5sums") else { continue };
        // Multi-arch packages are named "libfoo:amd64".
        let package = stem.split(':').next().unwrap_or(stem);
        let Ok(text) = std::fs::read_to_string(entry.path()) else { continue };

        for mut file in parse_md5sums(&text, package, root) {
            let relative = file.path.strip_prefix(root).unwrap_or(&file.path).to_string_lossy().into_owned();

            // A file another package diverted lives under its new name.
            if let Some((moved_to, by)) = diversions.get(key(&relative)) {
                if by != package {
                    file.path = root.join(moved_to.trim_start_matches('/'));
                }
            }

            if seen.insert(key(&file.path.strip_prefix(root).unwrap_or(&file.path).to_string_lossy()).to_string()) {
                out.push(file);
            }
        }
    }

    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

// --- rpm ------------------------------------------------------------------

/// The query format `rpm -qa` is asked for: digest, flags, package, path.
pub const RPM_QUERY_FORMAT: &str = "[%{FILEDIGESTS}\\t%{FILEFLAGS:fflags}\\t%{NAME}\\t%{FILENAMES}\\n]";

/// The output of `rpm -qa --qf RPM_QUERY_FORMAT`, in scope and without
/// configuration files.
pub fn parse_rpm_query(text: &str) -> Vec<PackagedFile> {
    let mut seen = HashSet::new();
    text.lines()
        .filter_map(|line| {
            let mut fields = line.splitn(4, '\t');
            let digest = fields.next()?;
            let flags = fields.next()?;
            let package = fields.next()?;
            let path = fields.next()?;

            // 'c' marks a configuration file. A directory or a link has no digest.
            if flags.contains('c') || !(digest.len() == 32 || digest.len() == 64) || !in_scope(path) {
                return None;
            }
            if !seen.insert(key(path).to_string()) {
                return None;
            }
            Some(PackagedFile {
                path: PathBuf::from(path),
                digest: digest.to_ascii_lowercase(),
                package: Some(package.to_string()),
            })
        })
        .collect()
}

// --- comparing ------------------------------------------------------------

/// The digest of a file, in the algorithm the record used.
fn digest_file(path: &Path, md5: bool) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut buffer = [0u8; 65536];
    if md5 {
        let mut hasher = Md5::new();
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    } else {
        let mut hasher = Sha256::new();
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }
}

/// A file whose contents differ from its package's record.
#[derive(Debug, Clone, PartialEq)]
pub struct Mismatch {
    pub path: String,
    pub package: Option<String>,
    pub actual: String,
}

#[derive(Debug, Default)]
pub struct Verification {
    pub checked: u32,
    pub mismatches: Vec<Mismatch>,
}

/// Compares each file with its record, reading only what changed since the
/// last scan.
pub fn verify(
    db: &Mutex<Connection>,
    files: &[PackagedFile],
    cancel: &AtomicBool,
    progress: &(dyn Fn(ScanProgress) + Sync),
) -> Verification {
    let mut outcome = Verification::default();
    let total = files.len() as u32;

    for (index, file) in files.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        if index % 64 == 0 {
            progress(ScanProgress {
                phase: "packages".into(),
                current: index as u32,
                total,
                message: "Comparing system programs with their packages".into(),
            });
        }

        // A link or a missing file says nothing about replaced contents.
        let Ok(metadata) = std::fs::symlink_metadata(&file.path) else { continue };
        if !metadata.is_file() {
            continue;
        }

        let path = file.path.to_string_lossy().into_owned();
        let size = metadata.len();
        let changed = platform::change_time(&metadata);
        let md5 = file.digest.len() == 32;

        let cached = {
            let conn = db.lock().unwrap();
            db::package_digest(&conn, &path, size, changed)
        };
        let actual = match cached {
            Some(digest) if digest.len() == file.digest.len() => digest,
            _ => match digest_file(&file.path, md5) {
                Ok(digest) => {
                    let conn = db.lock().unwrap();
                    let _ = db::put_package_digest(&conn, &path, size, changed, &digest);
                    digest
                }
                // Some sbin programs are readable only by root.
                Err(_) => continue,
            },
        };

        outcome.checked += 1;
        if actual == file.digest {
            continue;
        }

        let accepted = {
            let conn = db.lock().unwrap();
            db::package_accepted(&conn, &path).as_deref() == Some(actual.as_str())
        };
        if !accepted {
            outcome.mismatches.push(Mismatch { path, package: file.package.clone(), actual });
        }
    }

    outcome
}

/// The package check as the dashboard runs it.
pub fn findings(
    db: &Mutex<Connection>,
    cancel: &AtomicBool,
    progress: &(dyn Fn(ScanProgress) + Sync),
) -> Vec<Finding> {
    let (manager, files) = match platform::package_manifest() {
        None => {
            return vec![Finding::note(Issue {
                kind: IssueKind::ModuleUnavailable,
                severity: Severity::Info,
                title: "Package check unavailable".to_string(),
                location: "System programs".to_string(),
                detail: Some(platform::package_check_note().to_string()),
                actions: vec![Action::ignore()],
                ..Default::default()
            })]
        }
        Some(Err(e)) => {
            return vec![Finding::note(Issue {
                kind: IssueKind::ModuleUnavailable,
                severity: Severity::Info,
                title: "Could not read the package records".to_string(),
                location: "System programs".to_string(),
                detail: Some(e),
                actions: vec![Action::ignore()],
                ..Default::default()
            })]
        }
        Some(Ok(found)) => found,
    };

    let outcome = verify(db, &files, cancel, progress);
    outcome.mismatches.iter().map(|m| mismatch_finding(m, manager)).collect()
}

fn mismatch_finding(mismatch: &Mismatch, manager: Manager) -> Finding {
    let origin = match &mismatch.package {
        Some(name) => format!("It was installed by the package {name}"),
        None => "It was installed by the package manager".to_string(),
    };
    Finding::new(
        Issue {
            kind: IssueKind::PackageMismatch,
            severity: Severity::Critical,
            title: format!("System program differs from its package: {}", mismatch.path),
            location: mismatch.path.clone(),
            detail: Some(format!(
                "{origin}, and its contents no longer match what the package put there. Replacing a system program is how a rootkit hides; the innocent explanations are an update that is still running and a change someone made here on purpose.\n\n\
                 The package manager can confirm it on its own:\n\n    sudo {}\n\n\
                 If the change was intended, confirm it and this file is quiet until it changes again.",
                manager.verify_command(mismatch.package.as_deref())
            )),
            actions: vec![Action::new("update_baseline", "This was expected", false), Action::ignore()],
            ..Default::default()
        },
        IssueTarget::Package { path: mismatch.path.clone(), digest: mismatch.actual.clone() },
    )
}

/// Records that a file's current contents are expected, although they differ
/// from the package.
pub fn accept(conn: &Connection, path: &str, digest: &str) -> Result<(), String> {
    db::accept_package_file(conn, path, digest)?;
    actionlog::record(
        conn,
        actionlog::kind::UPDATE_BASELINE,
        path,
        Some("differs from its package, confirmed by the user"),
        false,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn md5_of(data: &[u8]) -> String {
        format!("{:x}", Md5::digest(data))
    }

    #[test]
    fn the_scope_is_programs_and_pam_modules() {
        assert!(in_scope("usr/bin/ls"));
        assert!(in_scope("/bin/ls"));
        assert!(in_scope("sbin/sshd"));
        assert!(in_scope("usr/lib/x86_64-linux-gnu/security/pam_unix.so"));
        assert!(in_scope("lib/security/pam_unix.so"));
        assert!(in_scope("/usr/lib64/security/pam_unix.so"));

        assert!(!in_scope("usr/bin/"));
        assert!(!in_scope("usr/share/doc/ls/README"));
        assert!(!in_scope("etc/ssh/sshd_config"));
        assert!(!in_scope("usr/lib/x86_64-linux-gnu/libc.so.6"));
        assert!(!in_scope("usr/lib/x86_64-linux-gnu/security/README"));
        assert!(!in_scope("usr/bin/sub/dir"));
    }

    #[test]
    fn md5sums_lines_become_records_and_out_of_scope_ones_are_dropped() {
        let text = "d41d8cd98f00b204e9800998ecf8427e  usr/bin/true\n\
                    0123456789abcdef0123456789abcdef  usr/share/man/man1/true.1.gz\n\
                    not a line\n";
        let found = parse_md5sums(text, "coreutils", Path::new("/"));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].path, PathBuf::from("/usr/bin/true"));
        assert_eq!(found[0].package.as_deref(), Some("coreutils"));
    }

    #[test]
    fn a_file_diverted_by_another_package_is_checked_where_it_was_moved() {
        let diversions = parse_diversions("/usr/bin/luit\n/usr/bin/luit.x11-utils\nluit\n");
        assert_eq!(diversions.get("bin/luit"), Some(&("/usr/bin/luit.x11-utils".to_string(), "luit".to_string())));
    }

    /// A fake root with a dpkg directory in it.
    fn fake_system(files: &[(&str, &[u8], &[u8])]) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let info = root.path().join("var/lib/dpkg/info");
        std::fs::create_dir_all(&info).unwrap();

        let mut md5sums = String::new();
        for (relative, recorded, on_disk) in files {
            let path = root.path().join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, on_disk).unwrap();
            md5sums.push_str(&format!("{}  {relative}\n", md5_of(recorded)));
        }
        std::fs::write(info.join("fakeutils:amd64.md5sums"), md5sums).unwrap();
        root
    }

    #[test]
    fn a_replaced_program_is_found_and_an_untouched_one_is_not() {
        let root = fake_system(&[
            ("usr/bin/ls", b"the real ls", b"the real ls"),
            ("usr/sbin/sshd", b"the real sshd", b"a backdoored sshd"),
            ("usr/share/doc/x", b"doc", b"edited doc"),
        ]);
        let files = dpkg_manifest(&root.path().join("var/lib/dpkg/info"), root.path()).unwrap();
        assert_eq!(files.len(), 2, "the document is out of scope");

        let db = Mutex::new(crate::db::open_memory());
        let outcome = verify(&db, &files, &AtomicBool::new(false), &|_| {});
        assert_eq!(outcome.checked, 2);
        assert_eq!(outcome.mismatches.len(), 1);
        assert!(outcome.mismatches[0].path.ends_with("usr/sbin/sshd"));
        assert_eq!(outcome.mismatches[0].package.as_deref(), Some("fakeutils"));

        let finding = mismatch_finding(&outcome.mismatches[0], Manager::Dpkg);
        assert_eq!(finding.issue.severity, Severity::Critical);
        assert!(finding.issue.detail.unwrap().contains("dpkg --verify fakeutils"));
    }

    #[test]
    fn a_confirmed_change_is_quiet_until_the_file_changes_again() {
        let root = fake_system(&[("usr/bin/tool", b"original", b"rebuilt locally")]);
        let files = dpkg_manifest(&root.path().join("var/lib/dpkg/info"), root.path()).unwrap();
        let db = Mutex::new(crate::db::open_memory());

        let first = verify(&db, &files, &AtomicBool::new(false), &|_| {});
        let mismatch = &first.mismatches[0];
        accept(&db.lock().unwrap(), &mismatch.path, &mismatch.actual).unwrap();

        assert!(verify(&db, &files, &AtomicBool::new(false), &|_| {}).mismatches.is_empty());

        std::fs::write(root.path().join("usr/bin/tool"), b"replaced again").unwrap();
        assert_eq!(verify(&db, &files, &AtomicBool::new(false), &|_| {}).mismatches.len(), 1);
    }

    #[test]
    fn an_unchanged_file_is_not_read_twice() {
        let root = fake_system(&[("usr/bin/a", b"x", b"x")]);
        let files = dpkg_manifest(&root.path().join("var/lib/dpkg/info"), root.path()).unwrap();
        let db = Mutex::new(crate::db::open_memory());
        verify(&db, &files, &AtomicBool::new(false), &|_| {});

        // The cached digest is what the second pass uses, so poisoning it
        // shows whether the file was read again.
        let path = files[0].path.to_string_lossy().into_owned();
        let metadata = std::fs::metadata(&files[0].path).unwrap();
        {
            let conn = db.lock().unwrap();
            db::put_package_digest(&conn, &path, metadata.len(), platform::change_time(&metadata), &"0".repeat(32))
                .unwrap();
        }
        assert_eq!(verify(&db, &files, &AtomicBool::new(false), &|_| {}).mismatches.len(), 1);
    }

    #[test]
    fn rpm_records_skip_configuration_and_links() {
        let sha = "a".repeat(64);
        let text = format!(
            "{sha}\t\tcoreutils\t/usr/bin/ls\n\
             {sha}\tc\topenssh\t/usr/sbin/sshd\n\
             \t\tcoreutils\t/usr/bin/link\n\
             {sha}\t\tpam\t/usr/lib64/security/pam_unix.so\n\
             {sha}\td\tcoreutils\t/usr/share/doc/README\n"
        );
        let found = parse_rpm_query(&text);
        let paths: Vec<_> = found.iter().map(|f| f.path.to_string_lossy().into_owned()).collect();
        assert_eq!(paths, vec!["/usr/bin/ls", "/usr/lib64/security/pam_unix.so"]);
        assert_eq!(found[0].package.as_deref(), Some("coreutils"));
    }

    #[test]
    fn sha256_records_are_compared_as_sha256() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ls");
        std::fs::write(&path, b"abc").unwrap();
        let files = vec![PackagedFile {
            path,
            digest: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
            package: None,
        }];
        let db = Mutex::new(crate::db::open_memory());
        let outcome = verify(&db, &files, &AtomicBool::new(false), &|_| {});
        assert_eq!(outcome.checked, 1);
        assert!(outcome.mismatches.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_is_never_a_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real");
        std::fs::write(&target, b"x").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let files = vec![PackagedFile { path: link, digest: "0".repeat(32), package: None }];
        let db = Mutex::new(crate::db::open_memory());
        assert!(verify(&db, &files, &AtomicBool::new(false), &|_| {}).mismatches.is_empty());
    }
}
