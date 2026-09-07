//! The Linux answers.

use std::collections::HashMap;
use std::fs::{self, Metadata};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use procfs::process::{all_processes, FDTarget};

use super::{AutostartEntry, LogAccess, RawSocket, ScheduleStatus, TargetSocket};

pub const SYSTEM_NAME: &str = "Linux";

// --- where things live ----------------------------------------------------

fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
}

fn xdg(var: &str, fallback: &str) -> PathBuf {
    match std::env::var_os(var) {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => home().join(fallback),
    }
}

pub fn data_dir() -> PathBuf {
    xdg("XDG_DATA_HOME", ".local/share")
}

pub fn config_dir() -> PathBuf {
    xdg("XDG_CONFIG_HOME", ".config")
}

/// Resolves an XDG user directory, which is localised on most desktops.
///
/// The real name is in `~/.config/user-dirs.dirs`. The English name is only
/// the fallback.
pub fn user_dir(kind: &str, fallback: &str) -> PathBuf {
    let key = format!("XDG_{kind}_DIR");

    if let Some(value) = std::env::var_os(&key) {
        if !value.is_empty() {
            return PathBuf::from(value);
        }
    }

    if let Ok(text) = fs::read_to_string(config_dir().join("user-dirs.dirs")) {
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            let Some((name, value)) = line.split_once('=') else { continue };
            if name.trim() != key {
                continue;
            }
            let value = value.trim().trim_matches('"');
            // The file writes home-relative paths as `$HOME/Name`.
            let expanded = match value.strip_prefix("$HOME/") {
                Some(rest) => home().join(rest),
                None if value == "$HOME" => home(),
                None => PathBuf::from(value),
            };
            if !expanded.as_os_str().is_empty() {
                return expanded;
            }
        }
    }

    home().join(fallback)
}

pub fn default_scan_paths() -> Vec<String> {
    [
        user_dir("DOWNLOAD", "Downloads"),
        user_dir("DESKTOP", "Desktop"),
        PathBuf::from("/tmp"),
        home().join(".local/share/applications"),
    ]
    .iter()
    .map(|p| p.to_string_lossy().into_owned())
    .collect()
}

/// The system files watched by default.
///
/// `/etc/shadow` is listed, and unreadable files are dropped in silence, so an
/// unprivileged run never sees it.
pub fn default_integrity_paths() -> Vec<String> {
    [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/sudoers",
        "/etc/crontab",
        "/etc/resolv.conf",
        "/etc/ld.so.preload",
        "/usr/bin/sudo",
        "/bin/bash",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

pub fn default_auth_log() -> String {
    "/var/log/auth.log".to_string()
}

// --- files ----------------------------------------------------------------

/// The executable bit counts as interesting on its own, since a downloaded
/// binary often has no extension.
pub fn is_executable(metadata: &Metadata) -> bool {
    metadata.mode() & 0o111 != 0
}

pub fn permission_bits(metadata: &Metadata) -> u32 {
    metadata.permissions().mode() & 0o7777
}

/// Makes a quarantined file inert: no read, write or execute for anybody.
///
/// Restoring still works, because a rename depends on the directory's
/// permissions rather than the file's.
pub fn seal(path: &Path) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o000))
}

/// Makes it readable again, for the copy fallback and the hash check.
pub fn unseal(path: &Path) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

pub fn restore_permissions(path: &Path, bits: u32) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(bits))
}

pub fn restrict_directory(path: &Path) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

pub fn restrict_file(file: &fs::File) -> io::Result<()> {
    file.set_permissions(fs::Permissions::from_mode(0o600))
}

// --- sockets --------------------------------------------------------------

/// Maps inode to process, in a single pass over `/proc`.
///
/// Other users' processes cannot be read, so their sockets end up with no
/// name, which the interface shows as unidentified.
fn inode_map() -> HashMap<u64, (i32, String)> {
    let mut map = HashMap::new();
    let Ok(processes) = all_processes() else {
        return map;
    };

    for process in processes.flatten() {
        let pid = process.pid();
        let name = process.stat().map(|s| s.comm).unwrap_or_default();
        let Ok(fds) = process.fd() else { continue };
        for fd in fds.flatten() {
            if let FDTarget::Socket(inode) = fd.target {
                map.insert(inode, (pid, name.clone()));
            }
        }
    }
    map
}

/// Every socket with a peer, read from `/proc/net`.
pub fn sockets() -> Result<Vec<RawSocket>, String> {
    let map = inode_map();
    let mut out = Vec::new();

    let mut push = |protocol: &'static str, local: SocketAddr, remote: SocketAddr, state: String, inode: u64| {
        // A socket with no peer is a listener, not a conversation.
        if remote.ip().is_unspecified() || remote.port() == 0 {
            return;
        }
        let (pid, process) = match map.get(&inode) {
            Some((pid, name)) => (Some(*pid), Some(name.clone())),
            None => (None, None),
        };
        out.push(RawSocket {
            protocol,
            local_addr: local.ip(),
            local_port: local.port(),
            remote_addr: remote.ip(),
            remote_port: remote.port(),
            state,
            pid,
            process,
        });
    };

    // Each file is optional: a kernel without IPv6 has no /proc/net/tcp6.
    if let Ok(entries) = procfs::net::tcp() {
        for e in entries {
            push("tcp", e.local_address, e.remote_address, format!("{:?}", e.state), e.inode);
        }
    }
    if let Ok(entries) = procfs::net::tcp6() {
        for e in entries {
            push("tcp6", e.local_address, e.remote_address, format!("{:?}", e.state), e.inode);
        }
    }
    if let Ok(entries) = procfs::net::udp() {
        for e in entries {
            push("udp", e.local_address, e.remote_address, format!("{:?}", e.state), e.inode);
        }
    }
    if let Ok(entries) = procfs::net::udp6() {
        for e in entries {
            push("udp6", e.local_address, e.remote_address, format!("{:?}", e.state), e.inode);
        }
    }

    Ok(out)
}

/// Whether a socket with exactly these endpoints is still open.
///
/// Both address families are searched, since a socket in `/proc/net/tcp6` can
/// hold an IPv4-mapped address.
pub fn socket_exists(target: &TargetSocket) -> bool {
    let matches = |local: SocketAddr, remote: SocketAddr| {
        local.port() == target.local_port
            && remote.port() == target.remote_port
            && normalise(local.ip()) == target.local
            && normalise(remote.ip()) == target.remote
    };

    if target.tcp {
        let tcp = procfs::net::tcp().into_iter().flatten();
        let tcp6 = procfs::net::tcp6().into_iter().flatten();
        tcp.chain(tcp6).any(|e| matches(e.local_address, e.remote_address))
    } else {
        let udp = procfs::net::udp().into_iter().flatten();
        let udp6 = procfs::net::udp6().into_iter().flatten();
        udp.chain(udp6).any(|e| matches(e.local_address, e.remote_address))
    }
}

/// Strips the IPv4-mapped IPv6 wrapper, so an address has one spelling.
pub fn normalise(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Asks the kernel to destroy these sockets, through `ss --kill`.
///
/// Returns whatever `ss` complained about, which is empty when it is happy.
/// The exit status says nothing: `ss` returns 0 whether or not it destroyed
/// anything, which is why the caller checks `/proc` afterwards.
pub fn close_sockets(targets: &[TargetSocket]) -> Result<String, String> {
    let mut complaints = Vec::new();

    // At most two calls, and so at most two prompts: TCP, then UDP.
    for (flag, tcp) in [("-t", true), ("-u", false)] {
        let group: Vec<&TargetSocket> = targets.iter().filter(|t| t.tcp == tcp).collect();
        if group.is_empty() {
            continue;
        }

        // Addresses are always bracketed: IPv6 requires it, IPv4 accepts it.
        let filter = group
            .iter()
            .map(|t| {
                format!(
                    "( dst [{}] and dport = {} and src [{}] and sport = {} )",
                    t.remote, t.remote_port, t.local, t.local_port
                )
            })
            .collect::<Vec<_>>()
            .join(" or ");

        let output = run_privileged_capture("ss", &["-K", flag, &filter])?;
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if !stderr.is_empty() {
            complaints.push(stderr);
        }
    }

    Ok(complaints.join(" "))
}

/// Turns what the kernel refused into something worth reading.
pub fn explain_close_failure(complaint: &str) -> String {
    if complaint.contains("not supported") {
        return "This kernel cannot destroy a socket on request (it was built without CONFIG_INET_DIAG_DESTROY). Stopping the process, or blocking the address, will still work.".to_string();
    }
    if complaint.contains("not permitted") {
        return "The kernel refused the request even with administrator rights. Stopping the process, or blocking the address, will still work.".to_string();
    }
    if complaint.is_empty() {
        return "The connection ended on its own before it could be closed.".to_string();
    }
    format!("The connection is still open. ss said: {complaint}")
}

// --- the firewall ---------------------------------------------------------

/// The nftables table scripts/setup-nftables.sh creates.
const TABLE: &str = "grtsentry";

pub fn block_address(ip: &IpAddr) -> Result<(), String> {
    let set = if ip.is_ipv4() { "blacklist" } else { "blacklist6" };
    let element = format!("{{ {ip} }}");
    run_privileged("nft", &["add", "element", "inet", TABLE, set, &element]).map_err(explain_nft)?;
    Ok(())
}

pub fn unblock_address(ip: &IpAddr) -> Result<(), String> {
    let set = if ip.is_ipv4() { "blacklist" } else { "blacklist6" };
    let element = format!("{{ {ip} }}");
    run_privileged("nft", &["delete", "element", "inet", TABLE, set, &element]).map_err(explain_nft)?;
    Ok(())
}

fn explain_nft(error: String) -> String {
    if error.contains("No such file or directory") || error.contains("does not exist") {
        return format!(
            "The firewall table this program uses does not exist yet. Run scripts/setup-nftables.sh once, with sudo, to create it. ({error})"
        );
    }
    if error.contains("File exists") {
        return "That address is already in the blocked set.".to_string();
    }
    error
}

pub fn firewall_ready() -> bool {
    run_plain("nft", &["--version"]).is_ok()
}

pub fn firewall_note() -> &'static str {
    "nftables, through scripts/setup-nftables.sh"
}

// --- processes ------------------------------------------------------------

/// The name the system currently gives this pid, for the check against a pid
/// that was reused between the scan and the button.
pub fn process_name(pid: i32) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/comm")).ok().map(|s| s.trim().to_string())
}

pub fn process_exists(pid: i32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// SIGTERM, so a program told to stop can close its files first.
pub fn stop_process(pid: i32) -> Result<(), String> {
    let target = pid.to_string();
    if run_plain("kill", &["-TERM", &target]).is_ok() {
        return Ok(());
    }
    // Another user's process needs root to signal.
    run_privileged("kill", &["-TERM", &target]).map(|_| ())
}

// --- elevation ------------------------------------------------------------

pub fn elevation_available() -> bool {
    which("pkexec").is_some()
}

pub fn elevation_note() -> &'static str {
    "pkexec"
}

/// Linux does not need the program itself to be privileged: the two
/// operations that do ask for it when they run.
pub fn is_elevated() -> bool {
    unsafe_getuid() == 0
}

fn unsafe_getuid() -> u32 {
    fs::metadata("/proc/self").map(|m| m.uid()).unwrap_or(1000)
}

fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|dir| dir.join(program)).find(|c| c.is_file())
}

pub fn run_plain(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("Cannot run {program}: {e}"))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(if stderr.is_empty() { format!("{program} failed") } else { stderr })
    }
}

/// Runs a program as root and hands back everything it produced.
///
/// `pkexec` exits 126 when the dialog is cancelled and 127 when no polkit
/// agent is running, and both are translated into a sentence.
pub fn run_privileged_capture(program: &str, args: &[&str]) -> Result<std::process::Output, String> {
    if !elevation_available() {
        return Err(
            "This needs administrator rights, and pkexec is not installed. Install the policykit-1 package, or run the equivalent command yourself in a terminal."
                .to_string(),
        );
    }

    let mut full = vec![program];
    full.extend_from_slice(args);

    let output = Command::new("pkexec")
        .args(&full)
        .output()
        .map_err(|e| format!("Cannot run pkexec: {e}"))?;

    match output.status.code() {
        Some(126) => Err("Authentication was cancelled, so nothing was changed.".to_string()),
        Some(127) => Err(
            "Authentication is not available. This usually means no polkit agent is running, which is normal outside a desktop session."
                .to_string(),
        ),
        _ => Ok(output),
    }
}

pub fn run_privileged(program: &str, args: &[&str]) -> Result<String, String> {
    let output = run_privileged_capture(program, args)?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(if stderr.is_empty() { format!("{program} failed") } else { stderr })
}

// --- pending updates ------------------------------------------------------

pub fn updates_tool_available() -> bool {
    run_plain("apt", &["--version"]).is_ok()
}

pub fn update_tool_name() -> &'static str {
    "apt"
}

pub fn update_command() -> &'static str {
    "sudo apt update && sudo apt upgrade"
}

/// Packages upgradable from a security pocket.
///
/// `apt list --upgradable` prints `name/pocket version arch [upgradable from:
/// old]`, and the pocket is what marks a security fix. Pocket names are never
/// translated, but the surrounding text is, so the command runs under
/// `LC_ALL=C` and nothing else is parsed.
pub fn security_updates() -> Result<Vec<String>, String> {
    let output = Command::new("apt")
        .args(["list", "--upgradable"])
        .env("LC_ALL", "C")
        .env("DEBIAN_FRONTEND", "noninteractive")
        .output()
        .map_err(|e| format!("Cannot run apt: {e}"))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    Ok(parse_upgradable(&String::from_utf8_lossy(&output.stdout)))
}

pub fn parse_upgradable(text: &str) -> Vec<String> {
    let mut out: Vec<String> = text
        .lines()
        .filter_map(|line| {
            let (name, rest) = line.split_once('/')?;
            let pocket = rest.split_whitespace().next()?;
            // Both Debian and Ubuntu name the pocket <suite>-security.
            if pocket.ends_with("-security") {
                Some(name.trim().to_string())
            } else {
                None
            }
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

pub fn reboot_required() -> bool {
    Path::new("/var/run/reboot-required").exists() || Path::new("/run/reboot-required").exists()
}

/// Libraries the loader is told to insert into every process, from
/// `/etc/ld.so.preload`.
///
/// Almost nothing legitimate uses this on a desktop, and it is how a rootkit
/// hides files and connections from the tools used to look for them.
pub fn injected_libraries() -> Option<(String, Vec<String>)> {
    let contents = fs::read_to_string("/etc/ld.so.preload").ok()?;
    let listed = contents
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect();
    Some(("/etc/ld.so.preload".to_string(), listed))
}

/// What the list of pending updates is called here.
pub fn updates_heading() -> &'static str {
    "These packages have a fix published in the security repository"
}

// --- what starts by itself ------------------------------------------------

pub fn autostart_entries() -> Vec<AutostartEntry> {
    let mut entries = Vec::new();
    entries.extend(desktop_entries(&config_dir().join("autostart"), "user desktop entry"));
    entries.extend(desktop_entries(Path::new("/etc/xdg/autostart"), "system desktop entry"));
    entries.extend(user_services());
    entries.extend(user_crontab());
    entries
}

fn desktop_entries(dir: &Path, source: &str) -> Vec<AutostartEntry> {
    let Ok(read) = fs::read_dir(dir) else {
        return vec![]; // No user autostart directory is normal.
    };

    let mut out = Vec::new();
    for entry in read.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("desktop") {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else { continue };
        let Some((name, command)) = parse_desktop(&text) else { continue };

        let file = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        out.push(AutostartEntry {
            key: format!("{source}:{file}"),
            source: source.to_string(),
            name: if name.is_empty() { file } else { name },
            command,
        });
    }
    out
}

/// `(Name, Exec)` from a desktop file, unless it is switched off.
pub fn parse_desktop(text: &str) -> Option<(String, String)> {
    let mut fields: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            fields.entry(key.trim()).or_insert(value.trim());
        }
    }

    if fields.get("Hidden").map(|v| v.eq_ignore_ascii_case("true")).unwrap_or(false) {
        return None;
    }
    // The other way a desktop switches an entry off.
    if fields.get("X-GNOME-Autostart-enabled").map(|v| v.eq_ignore_ascii_case("false")).unwrap_or(false) {
        return None;
    }

    Some((
        fields.get("Name").unwrap_or(&"").to_string(),
        fields.get("Exec").unwrap_or(&"").to_string(),
    ))
}

fn user_services() -> Vec<AutostartEntry> {
    let Ok(output) = Command::new("systemctl")
        .args(["--user", "list-unit-files", "--state=enabled", "--no-legend", "--no-pager", "--plain"])
        .env("LC_ALL", "C")
        .output()
    else {
        return vec![];
    };
    if !output.status.success() {
        return vec![];
    }

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let unit = line.split_whitespace().next()?;
            if unit.is_empty() {
                return None;
            }
            Some(AutostartEntry {
                key: format!("user service:{unit}"),
                source: "user service".to_string(),
                name: unit.to_string(),
                command: format!("systemctl --user status {unit}"),
            })
        })
        .collect()
}

fn user_crontab() -> Vec<AutostartEntry> {
    let Ok(output) = Command::new("crontab").args(["-l"]).env("LC_ALL", "C").output() else {
        return vec![];
    };
    if !output.status.success() {
        return vec![]; // "no crontab for user" is the usual case.
    }

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| AutostartEntry {
            // The line itself is the identity, so an edited job reads as new.
            key: format!("cron:{line}"),
            source: "cron".to_string(),
            name: "Scheduled command".to_string(),
            command: line.to_string(),
        })
        .collect()
}

pub fn entry_path_for(source: &str, file: &str) -> Option<PathBuf> {
    match source {
        "user desktop entry" => Some(config_dir().join("autostart").join(file)),
        "system desktop entry" => Some(PathBuf::from("/etc/xdg/autostart").join(file)),
        _ => None,
    }
}

// --- failed logins --------------------------------------------------------

/// How much of the end of the log to read, which is some thousands of lines.
const TAIL_BYTES: u64 = 512 * 1024;

pub fn read_auth_log(path: &str) -> LogAccess {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(e) => {
            return match e.kind() {
                io::ErrorKind::PermissionDenied => LogAccess::Denied,
                _ => LogAccess::Missing,
            }
        }
    };

    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let start = size.saturating_sub(TAIL_BYTES);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return LogAccess::Missing;
    }

    let mut buffer = Vec::new();
    if file.read_to_end(&mut buffer).is_err() {
        return LogAccess::Missing;
    }

    let text = String::from_utf8_lossy(&buffer).into_owned();
    // The first line is almost certainly cut in half by the seek.
    let text = match (start > 0, text.find('\n')) {
        (true, Some(first)) => text[first + 1..].to_string(),
        _ => text,
    };
    LogAccess::Ok(text)
}

pub fn read_auth_log_privileged(path: &str) -> Result<String, String> {
    if !path.starts_with('/') {
        return Err("The log path must be absolute.".to_string());
    }
    run_privileged("tail", &["-n", "5000", path])
}

pub fn auth_log_denied_detail(path: &str) -> String {
    format!(
        "{path} belongs to root and is readable by the adm group, which this user is not in.\n\n\
         The button below reads it once with administrator rights. To stop the prompt coming back, join the group:\n\n    sudo usermod -aG adm $USER\n\nthen log out and back in."
    )
}

pub fn auth_log_missing_detail(path: &str) -> String {
    format!(
        "Nothing at {path}. Many systems keep authentication records only in the systemd journal, in which case this module has nothing to read and the rest of the scan is unaffected."
    )
}

// --- the scheduled scan ---------------------------------------------------

const SERVICE: &str = "grt-sentry-scan.service";
const TIMER: &str = "grt-sentry-scan.timer";

fn unit_dir() -> PathBuf {
    config_dir().join("systemd/user")
}

fn systemctl(args: &[&str]) -> Result<String, String> {
    let mut full = vec!["--user"];
    full.extend_from_slice(args);
    run_plain("systemctl", &full)
}

pub fn scheduling_supported() -> bool {
    let uid = unsafe_getuid();
    Path::new(&format!("/run/user/{uid}/systemd")).exists() || systemctl(&["is-system-running"]).is_ok()
}

/// `Persistent=true` matters on a laptop: a scan missed because the machine
/// was off runs shortly after it comes back.
pub fn schedule_install(frequency: &str, executable: &Path) -> Result<(), String> {
    let dir = unit_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("Cannot create {}: {e}", dir.display()))?;

    let service = format!(
        "[Unit]\n\
         Description=GRT Sentry scheduled scan\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         ExecStart={} --scan\n\
         Nice=10\n\
         IOSchedulingClass=idle\n",
        executable.display()
    );

    let timer = format!(
        "[Unit]\n\
         Description=Run the GRT Sentry scan {frequency}\n\
         \n\
         [Timer]\n\
         OnCalendar={frequency}\n\
         Persistent=true\n\
         RandomizedDelaySec=15m\n\
         \n\
         [Install]\n\
         WantedBy=timers.target\n"
    );

    fs::write(dir.join(SERVICE), service).map_err(|e| format!("Cannot write the service unit: {e}"))?;
    fs::write(dir.join(TIMER), timer).map_err(|e| format!("Cannot write the timer unit: {e}"))?;

    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", "--now", TIMER])?;
    Ok(())
}

pub fn schedule_remove() -> Result<(), String> {
    // Errors are ignored: an absent timer should still leave a clean state.
    let _ = systemctl(&["disable", "--now", TIMER]);
    let dir = unit_dir();
    let _ = fs::remove_file(dir.join(TIMER));
    let _ = fs::remove_file(dir.join(SERVICE));
    let _ = systemctl(&["daemon-reload"]);
    Ok(())
}

pub fn schedule_status() -> ScheduleStatus {
    let dir = unit_dir();
    let installed = dir.join(TIMER).is_file();

    let frequency = fs::read_to_string(dir.join(TIMER)).ok().and_then(|text| {
        text.lines()
            .find_map(|line| line.trim().strip_prefix("OnCalendar=").map(|v| v.trim().to_string()))
    });

    let enabled = systemctl(&["is-enabled", TIMER]).map(|s| s.trim() == "enabled").unwrap_or(false);

    let next_run = systemctl(&["list-timers", "--no-legend", "--no-pager", TIMER])
        .ok()
        .and_then(|text| text.lines().next().map(|l| l.trim().to_string()))
        .filter(|l| !l.is_empty());

    ScheduleStatus { installed, enabled, frequency, next_run, supported: scheduling_supported() }
}

// --- notification ---------------------------------------------------------

/// `notify-send` is how a desktop notification is sent on Linux, and its
/// absence is not an error.
pub fn notify(title: &str, body: &str, urgent: bool) {
    let urgency = if urgent { "critical" } else { "normal" };
    let _ = Command::new("notify-send")
        .args([
            "--app-name=GRT Sentry",
            &format!("--urgency={urgency}"),
            "--icon=grt-sentry",
            title,
            body,
        ])
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(tcp: bool, remote: &str, remote_port: u16, local_port: u16) -> TargetSocket {
        TargetSocket {
            tcp,
            local: "192.168.1.20".parse().unwrap(),
            local_port,
            remote: remote.parse().unwrap(),
            remote_port,
        }
    }

    /// The filter is built here rather than by the caller, so this is where it
    /// is checked that it names one socket and no other.
    fn filter_for(targets: &[TargetSocket]) -> String {
        targets
            .iter()
            .map(|t| {
                format!(
                    "( dst [{}] and dport = {} and src [{}] and sport = {} )",
                    t.remote, t.remote_port, t.local, t.local_port
                )
            })
            .collect::<Vec<_>>()
            .join(" or ")
    }

    #[test]
    fn the_filter_names_one_socket_and_only_that_socket() {
        assert_eq!(
            filter_for(&[target(true, "185.220.101.7", 443, 44321)]),
            "( dst [185.220.101.7] and dport = 443 and src [192.168.1.20] and sport = 44321 )"
        );
    }

    #[test]
    fn several_sockets_become_one_filter_and_so_one_authentication() {
        let filter = filter_for(&[
            target(true, "185.220.101.7", 443, 1),
            target(true, "185.220.101.7", 80, 2),
        ]);
        assert!(filter.contains(" or "));
        assert_eq!(filter.matches("dst [185.220.101.7]").count(), 2);
    }

    #[test]
    fn an_ipv6_address_is_bracketed_because_ss_refuses_it_bare() {
        let mut ipv6 = target(true, "2606:4700:4700::1111", 443, 44321);
        ipv6.local = "2a00:1450::1".parse().unwrap();
        let filter = filter_for(&[ipv6]);

        assert!(filter.contains("dst [2606:4700:4700::1111]"), "got: {filter}");
        assert!(filter.contains("src [2a00:1450::1]"), "got: {filter}");
    }

    #[test]
    fn only_the_security_pocket_counts_as_a_security_update() {
        let output = "Listing...\n\
            grub-common/resolute-updates 2.14 amd64 [upgradable from: 2.13]\n\
            openssl/resolute-security 3.0.2 amd64 [upgradable from: 3.0.1]\n\
            libc6/jammy-security 2.35 amd64 [upgradable from: 2.34]\n";
        assert_eq!(parse_upgradable(output), vec!["libc6", "openssl"]);
    }

    #[test]
    fn a_package_listed_twice_is_named_once() {
        let output = "openssl/jammy-security 1 amd64 [upgradable from: 0]\n\
                      openssl/jammy-security 1 i386 [upgradable from: 0]\n";
        assert_eq!(parse_upgradable(output), vec!["openssl"]);
    }

    #[test]
    fn noise_and_headers_are_ignored() {
        assert!(parse_upgradable("Listing...\n\nWARNING: apt has no stable CLI.\n").is_empty());
        assert!(parse_upgradable("").is_empty());
    }

    #[test]
    fn a_pocket_that_merely_mentions_security_is_not_the_security_pocket() {
        assert!(parse_upgradable("thing/security-testing 1 amd64 [upgradable from: 0]\n").is_empty());
    }

    #[test]
    fn a_desktop_file_yields_its_name_and_command() {
        let text = "[Desktop Entry]\nType=Application\nName=Steam\nExec=/usr/bin/steam -silent\n";
        assert_eq!(parse_desktop(text), Some(("Steam".into(), "/usr/bin/steam -silent".into())));
    }

    #[test]
    fn a_disabled_entry_is_not_an_entry() {
        assert!(parse_desktop("[Desktop Entry]\nName=Thing\nExec=/bin/thing\nHidden=true\n").is_none());
        assert!(parse_desktop(
            "[Desktop Entry]\nName=Thing\nExec=/bin/thing\nX-GNOME-Autostart-enabled=false\n"
        )
        .is_none());
    }

    #[test]
    fn comments_and_repeated_keys_do_not_confuse_the_parser() {
        let text = "# a comment\n[Desktop Entry]\nName=First\nName=Second\nExec=/bin/x\n";
        // The first value wins, as the desktop entry specification says.
        assert_eq!(parse_desktop(text).unwrap().0, "First");
    }

    #[test]
    fn a_localised_user_directory_is_read_from_the_xdg_file() {
        // The variable takes priority, which also keeps the test off the
        // host's own folders.
        let _env = crate::testenv::lock();
        std::env::set_var("XDG_DOWNLOAD_DIR", "/tmp/grt-sentry-download-test");
        assert_eq!(user_dir("DOWNLOAD", "Downloads"), PathBuf::from("/tmp/grt-sentry-download-test"));
        std::env::remove_var("XDG_DOWNLOAD_DIR");
    }

    #[test]
    fn a_real_socket_list_from_this_machine_is_readable() {
        // No assertion about the contents, since a quiet machine is a
        // legitimate outcome. The walk itself must work.
        let list = sockets().expect("reading the socket table must not fail");
        for socket in list {
            assert_ne!(socket.remote_port, 0);
        }
    }
}
