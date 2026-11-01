//! Files that hand out privilege: set-user-ID, set-group-ID and capabilities.
//!
//! A normal system has a few dozen, all from packages: passwd, sudo, mount.
//! What matters is one that no package explains, one in a folder anyone can
//! write to, and one on a program that can be talked into running a shell,
//! which turns the bit into root for whoever asks.
//!
//! Nothing here is changed. Removing the bit from a legitimate program breaks
//! the system, so the decision stays with the person.

use std::path::Path;

use rusqlite::Connection;

use crate::db;
use crate::platform::{self, SpecialFile};
use crate::state::{Action, Finding, Issue, IssueKind, IssueTarget, Severity};

const KIND: &str = "special";

/// Programs that run a shell, read or write any file, or run another program
/// when asked to, and so give their privilege to whoever runs them. Written for
/// this program from their documented behaviour.
const ESCALATES: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "mksh", "fish", "csh", "tcsh", "ash", "busybox", "env", "find", "xargs", "awk",
    "gawk", "mawk", "nawk", "vi", "vim", "vim.basic", "vim.tiny", "nvim", "rvim", "view", "ex", "ed", "emacs", "nano",
    "less", "more", "man", "most", "cp", "mv", "dd", "tee", "install", "rsync", "tar", "cpio", "zip", "sed", "git",
    "make", "gdb", "strace", "ltrace", "taskset", "nice", "ionice", "timeout", "stdbuf", "nohup", "flock", "chroot",
    "docker", "podman", "systemctl", "socat", "nc", "ncat", "netcat", "openssl", "curl", "wget", "scp", "ssh", "tmux",
    "screen", "script", "watch", "setarch", "run-parts", "start-stop-daemon", "capsh", "unshare", "nsenter", "chmod",
    "chown", "expect", "tclsh", "wish", "jq", "sqlite3", "mysql", "psql", "pip", "pip3", "npm", "apt", "apt-get",
    "dpkg", "rpm", "yum", "dnf", "journalctl", "base64", "xxd", "head", "tail", "cat", "sort", "uniq", "diff", "cut",
    "nl", "od", "hexdump", "strings", "file",
];

/// Interpreters, which come with version numbers in their names.
const ESCALATING_PREFIXES: &[&str] = &["python", "perl", "ruby", "lua", "php", "node", "pypy", "tclsh", "irb"];

/// Capabilities that amount to root: chown, override and read past
/// permissions, own any file, set any group or user, load kernel modules,
/// trace any process, administer the system.
const DANGEROUS_CAPABILITIES: u64 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 6) | (1 << 7) | (1 << 16) | (1 << 19) | (1 << 21);

pub fn escalates(path: &str) -> bool {
    let name = Path::new(path).file_name().and_then(|n| n.to_str()).unwrap_or("");
    ESCALATES.contains(&name) || ESCALATING_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Where a file was found, which decides how much a special bit means.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Place {
    System,
    /// Temporary folders and the home, where root has no business leaving a
    /// program.
    Writable,
}

/// The signature a file is accepted under, so a change to its bits or
/// capabilities brings it back.
fn signature(file: &SpecialFile) -> String {
    format!("{:o}:{}:{}", file.mode & 0o7777, file.uid, file.capabilities.unwrap_or(0))
}

/// What one file deserves, given whether a package owns it.
pub fn judge(file: &SpecialFile, place: Place, packaged: Option<bool>) -> Option<(Severity, String, String)> {
    let suid_root = file.mode & 0o4000 != 0 && file.uid == 0;
    let sgid = file.mode & 0o2000 != 0;
    let dangerous_caps = file.capabilities.unwrap_or(0) & DANGEROUS_CAPABILITIES != 0;
    let path = &file.path;

    if place == Place::Writable {
        if suid_root || (sgid && file.gid == 0) || dangerous_caps {
            return Some((
                Severity::Critical,
                format!("A program that runs as root, in a folder anyone can write: {path}"),
                format!(
                    "{path} carries {} and lives where no package puts programs. Only root can set this up, and the usual reason is a back door left behind to get root again later.",
                    describe_bits(file)
                ),
            ));
        }
        return None;
    }

    if escalates(path) && (suid_root || dangerous_caps) {
        return Some((
            Severity::Critical,
            format!("{path} gives root to anyone who runs it"),
            format!(
                "{path} carries {}. It is a program that can be asked to start a shell or write any file, so with that bit anyone on this machine becomes root by running it. No distribution ships it this way.",
                describe_bits(file)
            ),
        ));
    }

    if packaged == Some(false) && (suid_root || sgid || dangerous_caps) {
        return Some((
            if suid_root { Severity::Critical } else { Severity::Warning },
            format!("A privileged program no package installed: {path}"),
            format!(
                "{path} carries {} and belongs to no installed package. Software installed by hand can explain it; otherwise a program that runs with more rights than its user, put there outside the package manager, is how a machine is kept open.",
                describe_bits(file)
            ),
        ));
    }
    None
}

fn describe_bits(file: &SpecialFile) -> String {
    let mut parts = Vec::new();
    if file.mode & 0o4000 != 0 {
        parts.push(if file.uid == 0 { "set-user-ID root".to_string() } else { format!("set-user-ID for user {}", file.uid) });
    }
    if file.mode & 0o2000 != 0 {
        parts.push(format!("set-group-ID for group {}", file.gid));
    }
    if let Some(caps) = file.capabilities {
        parts.push(format!("capabilities 0x{caps:x}"));
    }
    parts.join(" and ")
}

pub fn findings(conn: &Connection, skip: &[String]) -> Vec<Finding> {
    let home = crate::paths::expand_tilde("~");
    let mut system = Vec::new();
    for root in ["/usr", "/opt", "/bin", "/sbin", "/etc"] {
        let path = Path::new(root);
        // /bin and /sbin are links into /usr on a merged system.
        if std::fs::symlink_metadata(path).map(|m| m.file_type().is_symlink()).unwrap_or(true) {
            continue;
        }
        system.extend(platform::special_files(path, 12, skip));
    }
    let mut writable = Vec::new();
    for (root, depth) in [("/tmp", 6), ("/var/tmp", 6), ("/dev/shm", 6)] {
        writable.extend(platform::special_files(Path::new(root), depth, skip));
    }
    writable.extend(platform::special_files(&home, 5, skip));

    let paths: Vec<String> = system.iter().map(|f| f.path.clone()).collect();
    let owned = platform::packaged(&paths);

    let judged = system
        .iter()
        .map(|f| (f, Place::System, owned.as_ref().map(|o| o.contains(&f.path))))
        .chain(writable.iter().map(|f| (f, Place::Writable, None)));

    let mut out = Vec::new();
    for (file, place, packaged) in judged {
        let Some((severity, title, detail)) = judge(file, place, packaged) else { continue };
        let current = signature(file);
        if db::baseline_value(conn, KIND, &file.path).as_deref() == Some(current.as_str()) {
            continue;
        }
        out.push(Finding::new(
            Issue {
                kind: IssueKind::SpecialPermission,
                severity,
                title,
                location: file.path.clone(),
                detail: Some(format!(
                    "{detail}\n\nTo take the bit away, as root: chmod u-s,g-s {}{}",
                    file.path,
                    if file.capabilities.is_some() { format!("; setcap -r {}", file.path) } else { String::new() }
                )),
                actions: vec![Action::new("trust", "Expected", false), Action::ignore()],
                ..Default::default()
            },
            IssueTarget::Baseline { kind: KIND.to_string(), key: file.path.clone(), value: current },
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, mode: u32, uid: u32, caps: Option<u64>) -> SpecialFile {
        SpecialFile { path: path.into(), mode, uid, gid: 0, capabilities: caps }
    }

    #[test]
    fn the_shipped_set_user_id_programs_are_quiet() {
        for path in ["/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/mount", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"] {
            assert!(judge(&file(path, 0o104755, 0, None), Place::System, Some(true)).is_none(), "{path}");
        }
        // ping with a network capability is how distributions ship it.
        assert!(judge(&file("/usr/bin/ping", 0o100755, 0, Some(1 << 13)), Place::System, Some(true)).is_none());
    }

    #[test]
    fn a_shell_or_an_interpreter_with_the_bit_is_root_for_everyone() {
        for path in ["/usr/bin/find", "/usr/bin/bash", "/usr/bin/python3.12", "/usr/bin/vim.basic"] {
            let (severity, ..) = judge(&file(path, 0o104755, 0, None), Place::System, Some(true)).expect(path);
            assert_eq!(severity, Severity::Critical, "{path}");
        }
        let (severity, ..) = judge(&file("/usr/bin/python3", 0o100755, 0, Some(1 << 7)), Place::System, Some(true)).unwrap();
        assert_eq!(severity, Severity::Critical, "cap_setuid on python is root");
    }

    #[test]
    fn a_privileged_file_no_package_owns_is_reported() {
        let (severity, title, _) = judge(&file("/usr/local/bin/helper", 0o104755, 0, None), Place::System, Some(false)).unwrap();
        assert_eq!(severity, Severity::Critical);
        assert!(title.contains("no package"));
        let (severity, ..) = judge(&file("/usr/local/bin/g", 0o102755, 0, None), Place::System, Some(false)).unwrap();
        assert_eq!(severity, Severity::Warning, "set-group-ID alone is less");
        // Without a package manager to ask, only the obvious cases count.
        assert!(judge(&file("/opt/x/helper", 0o104755, 0, None), Place::System, None).is_none());
    }

    #[test]
    fn root_programs_in_writable_folders_are_always_critical() {
        let (severity, ..) = judge(&file("/tmp/.x/sh", 0o104755, 0, None), Place::Writable, None).unwrap();
        assert_eq!(severity, Severity::Critical);
        // The user's own set-user-ID file gives nothing away.
        assert!(judge(&file("/home/u/bin/mine", 0o104755, 1000, None), Place::Writable, None).is_none());
    }

    #[test]
    fn accepting_a_file_holds_only_until_its_bits_change() {
        let f = file("/usr/local/bin/helper", 0o104755, 0, None);
        let conn = crate::db::open_memory();
        crate::db::set_baseline_value(&conn, KIND, &f.path, &signature(&f)).unwrap();
        assert_eq!(crate::db::baseline_value(&conn, KIND, &f.path), Some(signature(&f)));
        let changed = file("/usr/local/bin/helper", 0o106755, 0, None);
        assert_ne!(signature(&f), signature(&changed));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn this_machine_has_set_user_id_programs_and_they_read_back() {
        let found = platform::special_files(Path::new("/usr/bin"), 2, &[]);
        assert!(found.iter().any(|f| f.path.ends_with("/passwd") || f.path.ends_with("/su")), "{found:?}");
    }
}
