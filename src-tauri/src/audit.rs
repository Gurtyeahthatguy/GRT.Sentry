//! The handful of settings that leave a door open.
//!
//! Lynis checks hundreds of things. These are the few whose answer changes
//! what someone can do to this machine: whether SSH lets root or an empty
//! password in, whether sudo gives root without asking, and whether anyone may
//! replace the programs everyone runs.

use crate::platform::{self, LogAccess, PathEntry};
use crate::state::{Action, Finding, Issue, IssueKind, IssueTarget, Severity};

pub fn findings() -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Some(config) = platform::sshd_config() {
        let port = ssh_option(&config, "Port").and_then(|p| p.parse().ok()).unwrap_or(22);
        findings.extend(ssh_findings(&config, platform::listens_beyond_loopback(port)));
    }
    match platform::sudoers() {
        LogAccess::Ok(text) => findings.extend(sudo_findings(&text)),
        LogAccess::Denied => findings.push(Finding::new(
            Issue {
                kind: IssueKind::ModuleUnavailable,
                severity: Severity::Info,
                title: "The sudo rules can only be read by root".to_string(),
                location: "/etc/sudoers".to_string(),
                detail: Some(
                    "Whether someone can become root without a password is written there. Reading it needs administrator rights, once, and nothing is changed."
                        .to_string(),
                ),
                actions: vec![Action::new("read_sudoers", "Read with administrator rights", false), Action::ignore()],
                ..Default::default()
            },
            IssueTarget::Informational,
        )),
        LogAccess::Missing => {}
    }
    findings.extend(path_findings(&platform::path_entries()));
    findings
}

/// The value sshd uses for an option: the first one it reads wins.
fn ssh_option<'a>(config: &'a str, name: &str) -> Option<&'a str> {
    for line in config.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        // A Match block applies to some connections only; what follows it is
        // not the global value.
        let mut words = line.split_whitespace();
        let Some(key) = words.next() else { continue };
        if key.eq_ignore_ascii_case("match") {
            return None;
        }
        if key.eq_ignore_ascii_case(name) {
            return words.next();
        }
    }
    None
}

pub fn ssh_findings(config: &str, listening: bool) -> Vec<Finding> {
    let mut out = Vec::new();
    let yes = |v: Option<&str>| v.is_some_and(|v| v.eq_ignore_ascii_case("yes"));

    if yes(ssh_option(config, "PermitEmptyPasswords")) {
        out.push(weak(
            Severity::Critical,
            "SSH accepts accounts with no password",
            "/etc/ssh/sshd_config",
            "PermitEmptyPasswords is yes, so an account without a password can be logged into from the network by anyone who knows its name. Set it to no and restart ssh.",
        ));
    }
    if yes(ssh_option(config, "PermitRootLogin")) {
        let password = !ssh_option(config, "PasswordAuthentication").is_some_and(|v| v.eq_ignore_ascii_case("no"));
        out.push(weak(
            if listening && password { Severity::Critical } else { Severity::Warning },
            "SSH lets root log in directly",
            "/etc/ssh/sshd_config",
            "PermitRootLogin is yes. Guessing root's password is then all it takes, and root is the one name every attacker tries first. prohibit-password keeps key logins working; no is safer still.",
        ));
    }
    if listening && !ssh_option(config, "PasswordAuthentication").is_some_and(|v| v.eq_ignore_ascii_case("no")) {
        out.push(weak(
            Severity::Info,
            "SSH is reachable and accepts passwords",
            "/etc/ssh/sshd_config",
            "The SSH server listens beyond this machine and lets users log in with a password, which is what the bots scanning the internet try all day. With keys set up, PasswordAuthentication no closes that.",
        ));
    }
    out
}

/// sudo rules that give root without a password, read line by line.
pub fn sudo_findings(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('@') || (line.starts_with("Defaults") && !line.contains("!authenticate")) {
            continue;
        }
        let who = line.split_whitespace().next().unwrap_or("");
        if line.contains("!authenticate") {
            out.push(weak(
                Severity::Warning,
                "sudo is set to never ask for a password",
                "/etc/sudoers",
                &format!("This rule switches authentication off: {line}\n\nAnything running as that user becomes root without anyone typing anything."),
            ));
            continue;
        }
        let Some(after) = line.split("NOPASSWD:").nth(1) else { continue };
        let commands = after.trim();
        let everything = commands.split(',').any(|c| c.trim() == "ALL");
        let escalating: Vec<&str> =
            commands.split(',').map(str::trim).filter(|c| crate::privilege::escalates(c.split_whitespace().next().unwrap_or(""))).collect();
        if everything {
            out.push(weak(
                Severity::Warning,
                &format!("{who} becomes root without a password"),
                "/etc/sudoers",
                &format!("This rule lets {who} run anything as root without typing a password: {line}\n\nA program that runs as {who} can then do the same, which is what makes a stolen session into a stolen machine."),
            ));
        } else if !escalating.is_empty() {
            out.push(weak(
                Severity::Warning,
                &format!("{who} can run a shell as root without a password"),
                "/etc/sudoers",
                &format!(
                    "This rule allows {} without a password: {line}\n\nEach of those can be asked to start a shell, so the rule gives full root, not just those commands.",
                    escalating.join(", ")
                ),
            ));
        }
    }
    out
}

pub fn path_findings(entries: &[PathEntry]) -> Vec<Finding> {
    let mut out = Vec::new();
    for entry in entries {
        if !entry.dir.starts_with('/') {
            let shown = if entry.dir.is_empty() { "an empty entry".to_string() } else { format!("\"{}\"", entry.dir) };
            out.push(weak(
                Severity::Warning,
                "The search path includes the current folder",
                "PATH",
                &format!("PATH contains {shown}, which means the current folder. A program named like a common command, left in any folder, then runs when that command is typed there."),
            ));
            continue;
        }
        if entry.world_writable && !entry.sticky {
            out.push(weak(
                Severity::Critical,
                &format!("Anyone can put programs in {}", entry.dir),
                &entry.dir,
                &format!("{} is on the search path and every user may write to it, so anyone can replace a command that root and every other user runs. As root: chmod o-w {}", entry.dir, entry.dir),
            ));
        }
        for file in entry.writable_files.iter().take(20) {
            out.push(weak(
                Severity::Critical,
                &format!("Anyone can change {file}"),
                file,
                &format!("{file} is a program on the search path that every user may overwrite. Whoever does decides what runs the next time anyone, root included, types its name. As root: chmod o-w {file}"),
            ));
        }
    }
    out
}

fn weak(severity: Severity, title: &str, location: &str, detail: &str) -> Finding {
    Finding::note(Issue {
        kind: IssueKind::WeakConfiguration,
        severity,
        title: title.to_string(),
        location: location.to_string(),
        detail: Some(detail.to_string()),
        actions: vec![Action::ignore()],
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_ssh_value_wins_and_match_blocks_do_not_count() {
        let config = "# PermitRootLogin yes\nPermitRootLogin no\nPermitRootLogin yes\n";
        assert_eq!(ssh_option(config, "PermitRootLogin"), Some("no"));
        let config = "Match User backup\n  PermitRootLogin yes\n";
        assert_eq!(ssh_option(config, "PermitRootLogin"), None);
    }

    #[test]
    fn root_login_over_a_reachable_password_server_is_critical() {
        let found = ssh_findings("PermitRootLogin yes\n", true);
        let root = found.iter().find(|f| f.issue.title.contains("root")).unwrap();
        assert_eq!(root.issue.severity, Severity::Critical);
        assert!(found.iter().any(|f| f.issue.title.contains("accepts passwords")));

        let quiet = ssh_findings("PermitRootLogin prohibit-password\nPasswordAuthentication no\n", true);
        assert!(quiet.is_empty());
        assert_eq!(ssh_findings("PermitRootLogin yes\n", false)[0].issue.severity, Severity::Warning);
        assert_eq!(ssh_findings("PermitEmptyPasswords yes\n", false)[0].issue.severity, Severity::Critical);
    }

    #[test]
    fn sudo_rules_that_skip_the_password_are_found() {
        let text = "root ALL=(ALL:ALL) ALL\n\
                    %sudo ALL=(ALL:ALL) ALL\n\
                    backdoor ALL=(ALL) NOPASSWD: ALL\n\
                    deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart web, /usr/bin/find\n\
                    backup ALL=(root) NOPASSWD: /usr/local/bin/backup.sh\n\
                    Defaults:svc !authenticate\n\
                    Defaults env_reset\n";
        let found = sudo_findings(text);
        let titles: Vec<String> = found.iter().map(|f| f.issue.title.clone()).collect();
        assert_eq!(found.len(), 3, "{titles:?}");
        assert!(titles.iter().any(|t| t == "backdoor becomes root without a password"));
        assert!(titles.iter().any(|t| t == "deploy can run a shell as root without a password"));
        assert!(titles.iter().any(|t| t.contains("never ask")));
    }

    #[test]
    fn a_writable_folder_on_the_path_is_critical_and_a_sticky_one_is_not_reported() {
        let entries = vec![
            PathEntry { dir: "/usr/bin".into(), ..Default::default() },
            PathEntry { dir: "/opt/tools/bin".into(), world_writable: true, sticky: false, writable_files: vec![] },
            PathEntry { dir: "/srv/shared".into(), world_writable: true, sticky: true, writable_files: vec![] },
            PathEntry { dir: "/usr/local/bin".into(), writable_files: vec!["/usr/local/bin/deploy".into()], ..Default::default() },
            PathEntry { dir: "".into(), ..Default::default() },
        ];
        let found = path_findings(&entries);
        assert_eq!(found.len(), 3);
        assert!(found.iter().any(|f| f.issue.title == "Anyone can put programs in /opt/tools/bin"));
        assert!(found.iter().any(|f| f.issue.title == "Anyone can change /usr/local/bin/deploy"));
        assert!(found.iter().any(|f| f.issue.title.contains("current folder")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_search_path_here_reads_back() {
        assert!(platform::path_entries().iter().any(|e| e.dir == "/usr/bin"));
    }
}
