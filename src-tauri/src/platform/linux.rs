//! The Linux answers.

use std::collections::HashMap;
use std::fs::{self, Metadata};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use procfs::process::{all_processes, FDTarget};

use super::{
    Account, AutostartEntry, BrowserKind, HiddenProcess, KernelModules, LogAccess, PathEntry, ProcessInfo, RawSocket,
    ScheduleStatus, SpecialFile, TargetSocket,
};

pub const SYSTEM_NAME: &str = "Linux";

// --- where things live ----------------------------------------------------

/// `HOME`, or the account's home from the user database when a service
/// started this without one; never a path relative to wherever it runs.
pub fn home_dir() -> PathBuf {
    home()
}

fn home() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from).filter(|p| p.is_absolute()) {
        return home;
    }
    // SAFETY: getpwuid returns a pointer into static storage or null, read at once.
    let from_passwd = unsafe {
        let entry = libc::getpwuid(libc::getuid());
        (!entry.is_null() && !(*entry).pw_dir.is_null())
            .then(|| std::ffi::CStr::from_ptr((*entry).pw_dir).to_string_lossy().into_owned())
    };
    from_passwd.map(PathBuf::from).filter(|p| p.is_absolute()).unwrap_or_else(|| PathBuf::from("/tmp"))
}

/// An XDG directory, ignored when it is not absolute, as the specification says.
fn xdg(var: &str, fallback: &str) -> PathBuf {
    match std::env::var_os(var).map(PathBuf::from) {
        Some(value) if value.is_absolute() => value,
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

/// When the inode last changed, which unlike the modification time cannot be
/// set back from user space.
pub fn change_time(metadata: &Metadata) -> i64 {
    metadata.ctime()
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
    nft(&["add", "element", "inet", TABLE, set, &element]).map_err(explain_nft)?;
    Ok(())
}

pub fn unblock_address(ip: &IpAddr) -> Result<(), String> {
    let set = if ip.is_ipv4() { "blacklist" } else { "blacklist6" };
    let element = format!("{{ {ip} }}");
    nft(&["delete", "element", "inet", TABLE, set, &element]).map_err(explain_nft)?;
    Ok(())
}

/// Root changes the firewall itself, under the profile's own rule for nft;
/// anyone else asks through pkexec.
fn nft(args: &[&str]) -> Result<String, String> {
    if is_elevated() {
        run_plain("nft", args)
    } else {
        run_privileged("nft", args)
    }
}

/// nftables drops an element by itself when its timeout runs out.
pub const BLOCKS_EXPIRE: bool = true;

/// The set for one address family, IPv4 or IPv6, whose elements time out.
fn timed_set(ip: &IpAddr) -> &'static str {
    if ip.is_ipv4() { "autoblock" } else { "autoblock6" }
}

/// Blocks addresses for a number of hours, in one command and so one password.
pub fn block_for(ips: &[IpAddr], hours: i64) -> Result<(), String> {
    let mut args: Vec<String> = Vec::new();
    for set in ["autoblock", "autoblock6"] {
        let elements: Vec<String> =
            ips.iter().filter(|ip| timed_set(ip) == set).map(|ip| format!("{ip} timeout {hours}h")).collect();
        if elements.is_empty() {
            continue;
        }
        if !args.is_empty() {
            args.push(";".to_string());
        }
        args.extend(["add", "element", "inet", TABLE, set].map(String::from));
        args.push(format!("{{ {} }}", elements.join(", ")));
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    nft(&refs).map_err(explain_nft)?;
    Ok(())
}

pub fn unblock_for(ip: &IpAddr) -> Result<(), String> {
    let element = format!("{{ {ip} }}");
    nft(&["delete", "element", "inet", TABLE, timed_set(ip), &element]).map_err(explain_nft)?;
    Ok(())
}

fn explain_nft(error: String) -> String {
    if error.contains("No such file or directory") || error.contains("does not exist") {
        return format!(
            "The firewall table or set this program uses does not exist yet. Run scripts/setup-nftables.sh once, with sudo, to create it; a table made before 0.4 needs it again for the sets that lift after a day. ({error})"
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

/// The program a process runs, readable even after its file was deleted.
pub fn process_executable(pid: i32) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/exe"))
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

// --- packaged files -------------------------------------------------------

/// What dpkg or rpm recorded about the files they installed, whichever this
/// system has. `None` when it has neither.
pub fn package_manifest() -> Option<Result<(crate::packages::Manager, Vec<crate::packages::PackagedFile>), String>> {
    use crate::packages::{dpkg_manifest, parse_rpm_query, Manager, RPM_QUERY_FORMAT};

    let info = Path::new("/var/lib/dpkg/info");
    if info.is_dir() {
        return Some(dpkg_manifest(info, Path::new("/")).map(|files| (Manager::Dpkg, files)));
    }
    which("rpm")?;
    Some(run_plain("rpm", &["-qa", "--qf", RPM_QUERY_FORMAT]).map(|text| (Manager::Rpm, parse_rpm_query(&text))))
}

pub fn package_check_note() -> &'static str {
    "Neither dpkg nor rpm keeps records on this system, so there is nothing to compare its programs against."
}

// --- what runs, and what hides --------------------------------------------

fn listed_pids() -> Option<Vec<i32>> {
    let entries = fs::read_dir("/proc").ok()?;
    Some(entries.flatten().filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok()).collect())
}

/// Every process in the list, with the link to its executable when this user
/// may read it.
pub fn processes() -> Vec<ProcessInfo> {
    listed_pids()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|pid| {
            let name = fs::read_to_string(format!("/proc/{pid}/comm")).ok()?.trim().to_string();
            let exe = fs::read_link(format!("/proc/{pid}/exe")).ok().map(|p| p.to_string_lossy().into_owned());
            Some(ProcessInfo { pid, name, exe })
        })
        .collect()
}

/// Processes that answer at /proc/PID but are missing from the listing of
/// /proc, which is what a rootkit that filters directory reads leaves behind.
///
/// Threads answer at /proc/TID too and are never listed, so they are excluded
/// by their thread group.
pub fn hidden_processes() -> Option<Vec<HiddenProcess>> {
    let listed = listed_pids()?;
    let mut known: std::collections::HashSet<i32> = listed.iter().copied().collect();
    for pid in &listed {
        if let Ok(tasks) = fs::read_dir(format!("/proc/{pid}/task")) {
            known.extend(tasks.flatten().filter_map(|t| t.file_name().to_str()?.parse::<i32>().ok()));
        }
    }

    let pid_max = fs::read_to_string("/proc/sys/kernel/pid_max")
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .unwrap_or(32_768);
    let highest = listed.iter().copied().max().unwrap_or(0);
    let limit = highest.saturating_add(10_000).max(32_768).min(pid_max);

    let candidates: Vec<i32> =
        (1..=limit).filter(|pid| !known.contains(pid) && Path::new(&format!("/proc/{pid}")).exists()).collect();

    // A process that started during the pass is in the listing by now.
    let relisted: std::collections::HashSet<i32> = listed_pids()?.into_iter().collect();
    Some(
        candidates
            .into_iter()
            .filter(|pid| !relisted.contains(pid))
            .filter_map(|pid| {
                let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
                let field = |name: &str| status.lines().find_map(|l| l.strip_prefix(name)).map(|v| v.trim().to_string());
                let tgid: i32 = field("Tgid:")?.parse().ok()?;
                if tgid != pid {
                    return None;
                }
                Some(HiddenProcess { pid, name: field("Name:").unwrap_or_default() })
            })
            .collect(),
    )
}

fn tcp_local_ports() -> std::collections::HashSet<u16> {
    let mut ports = std::collections::HashSet::new();
    if let Ok(entries) = procfs::net::tcp() {
        ports.extend(entries.iter().map(|e| e.local_address.port()));
    }
    if let Ok(entries) = procfs::net::tcp6() {
        ports.extend(entries.iter().map(|e| e.local_address.port()));
    }
    ports
}

/// Whether binding this address fails because something holds the port.
///
/// The socket is bound and closed, never listening, so nothing outside can
/// reach it in between.
fn port_taken(address: SocketAddr) -> bool {
    use socket2::{Domain, Socket, Type};
    let domain = if address.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let Ok(socket) = Socket::new(domain, Type::STREAM, None) else { return false };
    let _ = socket.set_reuse_address(true);
    if address.is_ipv6() {
        let _ = socket.set_only_v6(true);
    }
    matches!(socket.bind(&address.into()), Err(e) if e.kind() == io::ErrorKind::AddrInUse)
}

fn port_in_use(port: u16) -> bool {
    port_taken(SocketAddr::from(([0, 0, 0, 0], port))) || port_taken(SocketAddr::from(([0u16; 8], port)))
}

/// TCP ports that something holds but the socket table does not show.
///
/// Ports below the unprivileged limit cannot be bound by an ordinary user, so
/// they are probed only with administrator rights.
pub fn hidden_ports() -> Option<Vec<u16>> {
    socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).ok()?;
    let first = if is_elevated() {
        1
    } else {
        fs::read_to_string("/proc/sys/net/ipv4/ip_unprivileged_port_start")
            .ok()
            .and_then(|s| s.trim().parse::<u16>().ok())
            .unwrap_or(1024)
            .max(1)
    };

    let known = tcp_local_ports();
    let unexplained: Vec<u16> = (first..=u16::MAX).filter(|p| !known.contains(p) && port_in_use(*p)).collect();

    // A connection that opened during the pass explains its port by now.
    let known = tcp_local_ports();
    Some(unexplained.into_iter().filter(|p| !known.contains(p) && port_in_use(*p)).collect())
}

/// The ports below which an ordinary user cannot look.
#[cfg(test)]
pub fn hidden_port_floor() -> u16 {
    if is_elevated() {
        return 1;
    }
    fs::read_to_string("/proc/sys/net/ipv4/ip_unprivileged_port_start")
        .ok()
        .and_then(|s| s.trim().parse::<u16>().ok())
        .unwrap_or(1024)
}

/// Whether something listens on this TCP port on an address other machines
/// can reach.
pub fn listens_beyond_loopback(port: u16) -> bool {
    let listening = |local: SocketAddr, state: &procfs::net::TcpState| {
        *state == procfs::net::TcpState::Listen && local.port() == port && !local.ip().is_loopback()
    };
    procfs::net::tcp().map(|e| e.iter().any(|e| listening(e.local_address, &e.state))).unwrap_or(false)
        || procfs::net::tcp6().map(|e| e.iter().any(|e| listening(e.local_address, &e.state))).unwrap_or(false)
}

pub fn kernel_modules() -> Option<KernelModules> {
    let listed = fs::read_to_string("/proc/modules")
        .ok()?
        .lines()
        .filter_map(|line| line.split_whitespace().next().map(String::from))
        .collect();

    let mut sysfs = Vec::new();
    for entry in fs::read_dir("/sys/module").ok()?.flatten() {
        let dir = entry.path();
        // Built-in modules have a directory here but no initstate.
        if !dir.join("initstate").exists() {
            continue;
        }
        let taint = fs::read_to_string(dir.join("taint")).unwrap_or_default().trim().to_string();
        sysfs.push((entry.file_name().to_string_lossy().into_owned(), taint));
    }
    Some(KernelModules { listed, sysfs })
}

/// Permitted capabilities from a file's security.capability attribute.
fn file_capabilities(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let name = c"security.capability";
    let mut buffer = [0u8; 24];
    // SAFETY: both strings are NUL-terminated and the buffer length is passed.
    let read = unsafe {
        libc::getxattr(c_path.as_ptr(), name.as_ptr(), buffer.as_mut_ptr().cast(), buffer.len())
    };
    if read < 8 {
        return None;
    }
    let word = |at: usize| u32::from_le_bytes([buffer[at], buffer[at + 1], buffer[at + 2], buffer[at + 3]]) as u64;
    let low = word(4);
    // Version 2 and 3 carry the upper 32 capabilities after the lower ones.
    let high = if read >= 20 { word(12) } else { 0 };
    let permitted = low | (high << 32);
    (permitted != 0).then_some(permitted)
}

/// Files under a root with set-user-ID, set-group-ID or capabilities, without
/// leaving its filesystem.
pub fn special_files(root: &Path, max_depth: usize, skip: &[String]) -> Vec<SpecialFile> {
    let keep = |e: &walkdir::DirEntry| {
        !(e.depth() > 0
            && e.file_type().is_dir()
            && e.file_name().to_str().is_some_and(|name| skip.iter().any(|s| s == name)))
    };

    walkdir::WalkDir::new(root)
        .max_depth(max_depth)
        .follow_links(false)
        .same_file_system(true)
        .into_iter()
        .filter_entry(keep)
        .flatten()
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| {
            let metadata = e.metadata().ok()?;
            let mode = metadata.mode();
            let capabilities = if mode & 0o111 != 0 { file_capabilities(e.path()) } else { None };
            if mode & 0o6000 == 0 && capabilities.is_none() {
                return None;
            }
            Some(SpecialFile {
                path: e.path().to_string_lossy().into_owned(),
                mode,
                uid: metadata.uid(),
                gid: metadata.gid(),
                capabilities,
            })
        })
        .collect()
}

// --- packages, beyond their hashes -----------------------------------------

/// Which of these paths some installed package owns.
pub fn packaged(paths: &[String]) -> Option<std::collections::HashSet<String>> {
    use crate::packages::path_key;

    let info = Path::new("/var/lib/dpkg/info");
    if info.is_dir() {
        let wanted: HashMap<String, &String> = paths.iter().map(|p| (path_key(p).to_string(), p)).collect();
        let mut owned = std::collections::HashSet::new();
        // dpkg-divert moves a packaged file aside under a new name, which no
        // package list mentions.
        if let Ok(text) = fs::read_to_string("/var/lib/dpkg/diversions") {
            for (_, (moved_to, _)) in crate::packages::parse_diversions(&text) {
                if let Some(path) = wanted.get(path_key(&moved_to)) {
                    owned.insert((*path).clone());
                }
            }
        }
        for entry in fs::read_dir(info).ok()?.flatten() {
            if entry.path().extension().and_then(|e| e.to_str()) != Some("list") {
                continue;
            }
            let Ok(text) = fs::read_to_string(entry.path()) else { continue };
            for line in text.lines() {
                if let Some(path) = wanted.get(path_key(line)) {
                    owned.insert((*path).clone());
                }
            }
        }
        return Some(owned);
    }

    which("rpm")?;
    if paths.is_empty() {
        return Some(Default::default());
    }
    let mut owned = std::collections::HashSet::new();
    for chunk in paths.chunks(500) {
        let mut args = vec!["-qf", "--qf", "%{NAME}\\n"];
        args.extend(chunk.iter().map(|s| s.as_str()));
        // rpm exits non-zero when any one path is unowned, so stdout is read
        // either way: one line per path, in order.
        let Ok(output) = Command::new("rpm").args(&args).env("LC_ALL", "C").output() else { return None };
        let text = String::from_utf8_lossy(&output.stdout);
        for (path, line) in chunk.iter().zip(text.lines()) {
            if !line.contains("is not owned by any package") {
                owned.insert(path.clone());
            }
        }
    }
    Some(owned)
}

/// Configuration files as their packages shipped them, path to digest.
pub fn package_conffiles() -> HashMap<String, String> {
    if let Ok(text) = fs::read_to_string("/var/lib/dpkg/status") {
        return crate::packages::parse_conffiles(&text);
    }
    if which("rpm").is_some() {
        if let Ok(text) = run_plain("rpm", &["-qa", "--qf", crate::packages::RPM_QUERY_FORMAT]) {
            return crate::packages::parse_rpm_conffiles(&text);
        }
    }
    HashMap::new()
}

// --- browsers -------------------------------------------------------------

/// Where each browser keeps its profiles, packaged the usual way, as a snap
/// or as a flatpak.
pub fn browser_roots() -> Vec<(String, BrowserKind, PathBuf)> {
    let home = home();
    let config = config_dir();
    let firefox = [
        ("Firefox", home.join(".mozilla/firefox")),
        ("Firefox", home.join("snap/firefox/common/.mozilla/firefox")),
        ("Firefox", home.join(".var/app/org.mozilla.firefox/.mozilla/firefox")),
        ("LibreWolf", home.join(".librewolf")),
        ("LibreWolf", home.join(".var/app/io.gitlab.librewolf-community/.librewolf")),
    ];
    let chromium = [
        ("Chrome", config.join("google-chrome")),
        ("Chrome", home.join(".var/app/com.google.Chrome/config/google-chrome")),
        ("Chromium", config.join("chromium")),
        ("Chromium", home.join("snap/chromium/common/chromium")),
        ("Chromium", home.join(".var/app/org.chromium.Chromium/config/chromium")),
        ("Brave", config.join("BraveSoftware/Brave-Browser")),
        ("Brave", home.join(".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser")),
        ("Edge", config.join("microsoft-edge")),
        ("Vivaldi", config.join("vivaldi")),
    ];
    firefox
        .into_iter()
        .map(|(name, dir)| (name.to_string(), BrowserKind::Firefox, dir))
        .chain(chromium.into_iter().map(|(name, dir)| (name.to_string(), BrowserKind::Chromium, dir)))
        .filter(|(_, _, dir)| dir.is_dir())
        .collect()
}

// --- accounts and configuration -------------------------------------------

pub fn accounts() -> Option<Vec<Account>> {
    let text = fs::read_to_string("/etc/passwd").ok()?;
    Some(
        text.lines()
            .filter_map(|line| {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() < 7 {
                    return None;
                }
                Some(Account { name: fields[0].to_string(), uid: fields[2].parse().ok()?, shell: fields[6].to_string() })
            })
            .collect(),
    )
}

/// Accounts for the record of the machine, name to user ID and shell.
pub fn account_list() -> Option<std::collections::BTreeMap<String, String>> {
    Some(accounts()?.into_iter().map(|a| (a.name, format!("uid {}, {}", a.uid, a.shell))).collect())
}

/// Installed packages, name to version, from dpkg or rpm.
pub fn installed_packages() -> Option<std::collections::BTreeMap<String, String>> {
    if let Ok(text) = fs::read_to_string("/var/lib/dpkg/status") {
        return Some(crate::timeline::parse_dpkg_status(&text));
    }
    if which("rpm").is_some() {
        let text = run_plain("rpm", &["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"]).ok()?;
        return Some(crate::timeline::parse_rpm_list(&text));
    }
    None
}

/// Linux programs carry no signature to check.
pub fn signed(_path: &Path) -> Option<bool> {
    None
}

pub fn in_user_profile(_path: &str) -> bool {
    false
}

/// There is no Defender here.
pub fn defender_status() -> Option<Result<String, String>> {
    None
}

/// AppArmor does it from outside, when the profile is loaded.
pub fn harden_process() {}

/// What confines this process, in one line for the settings page.
pub fn confinement() -> String {
    let label = fs::read_to_string("/proc/self/attr/apparmor/current")
        .or_else(|_| fs::read_to_string("/proc/self/attr/current"))
        .unwrap_or_default();
    let label = label.trim_end_matches(['\0', '\n']).trim();
    if label.is_empty() || label == "unconfined" {
        "not confined: the AppArmor profile is not loaded for this copy, which is the case for a build run from its folder".to_string()
    } else {
        format!("AppArmor, {label}")
    }
}

/// The SSH server's configuration with its includes spliced in, when an SSH
/// server is installed.
pub fn sshd_config() -> Option<String> {
    if !Path::new("/usr/sbin/sshd").exists() {
        return None;
    }
    fn read_with_includes(path: &Path, depth: u32, out: &mut String) {
        let Ok(text) = fs::read_to_string(path) else { return };
        for line in text.lines() {
            let trimmed = line.trim();
            let mut words = trimmed.split_whitespace();
            if depth < 4 && words.next().is_some_and(|w| w.eq_ignore_ascii_case("include")) {
                for pattern in words {
                    let pattern = if pattern.starts_with('/') { pattern.to_string() } else { format!("/etc/ssh/{pattern}") };
                    for file in expand_glob(&pattern) {
                        read_with_includes(&file, depth + 1, out);
                    }
                }
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
    }
    let mut out = String::new();
    read_with_includes(Path::new("/etc/ssh/sshd_config"), 0, &mut out);
    Some(out)
}

/// A `dir/*.suffix` pattern, which is the only shape sshd's includes take in
/// practice.
fn expand_glob(pattern: &str) -> Vec<PathBuf> {
    let Some((dir, file)) = pattern.rsplit_once('/') else { return vec![] };
    let Some((prefix, suffix)) = file.split_once('*') else { return vec![PathBuf::from(pattern)] };
    let mut found: Vec<PathBuf> = fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with(prefix) && n.ends_with(suffix))
                })
                .collect()
        })
        .unwrap_or_default();
    found.sort();
    found
}

/// The sudo rules, which only root may normally read.
pub fn sudoers() -> LogAccess {
    let main = Path::new("/etc/sudoers");
    let mut text = match fs::read_to_string(main) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return LogAccess::Denied,
        Err(_) => return LogAccess::Missing,
    };
    match fs::read_dir("/etc/sudoers.d") {
        Ok(entries) => {
            let mut files: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
            files.sort();
            for file in files {
                match fs::read_to_string(&file) {
                    Ok(more) => text.push_str(&more),
                    Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return LogAccess::Denied,
                    Err(_) => {}
                }
            }
        }
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return LogAccess::Denied,
        Err(_) => {}
    }
    LogAccess::Ok(text)
}

pub fn sudoers_privileged() -> Result<String, String> {
    run_privileged("sh", &["-c", "cat /etc/sudoers; cat /etc/sudoers.d/* 2>/dev/null; true"])
}

/// Every directory programs are looked up in, from this process's PATH and
/// the system default.
pub fn path_entries() -> Vec<PathEntry> {
    let from_env = std::env::var("PATH").unwrap_or_default();
    let mut dirs: Vec<String> = from_env.split(':').map(String::from).collect();
    for standard in ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
        dirs.push(standard.to_string());
    }
    let mut seen = std::collections::HashSet::new();
    dirs.retain(|d| seen.insert(d.clone()));

    dirs.into_iter()
        .filter_map(|dir| {
            // An empty entry or a relative one means the current directory.
            if dir.is_empty() || !dir.starts_with('/') {
                return Some(PathEntry { dir, ..Default::default() });
            }
            let metadata = fs::metadata(&dir).ok()?;
            if !metadata.is_dir() {
                return None;
            }
            let mode = metadata.mode();
            let writable_files = fs::read_dir(&dir)
                .map(|entries| {
                    entries
                        .flatten()
                        .filter_map(|e| {
                            let m = fs::symlink_metadata(e.path()).ok()?;
                            (m.is_file() && m.mode() & 0o002 != 0).then(|| e.path().to_string_lossy().into_owned())
                        })
                        .collect()
                })
                .unwrap_or_default();
            Some(PathEntry { dir, world_writable: mode & 0o002 != 0, sticky: mode & 0o1000 != 0, writable_files })
        })
        .collect()
}

/// The last day of authentication messages from the journal, for systems
/// that no longer write /var/log/auth.log.
pub fn journal_auth() -> LogAccess {
    if which("journalctl").is_none() {
        return LogAccess::Missing;
    }
    let Ok(output) = Command::new("journalctl")
        .args(["SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10", "--since=-24h", "-o", "short-iso", "-q", "--no-pager"])
        .env("LC_ALL", "C")
        .output()
    else {
        return LogAccess::Missing;
    };
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("insufficient permissions") || stderr.contains("not seeing messages from other users") {
        return LogAccess::Denied;
    }
    if !output.status.success() {
        return LogAccess::Missing;
    }
    LogAccess::Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

// --- what starts by itself ------------------------------------------------

pub fn autostart_entries() -> Vec<AutostartEntry> {
    let mut entries = Vec::new();
    entries.extend(desktop_entries(&config_dir().join("autostart"), "user desktop entry"));
    entries.extend(desktop_entries(Path::new("/etc/xdg/autostart"), "system desktop entry"));
    entries.extend(user_services());
    entries.extend(user_crontab());
    entries.extend(system_services());
    entries.extend(system_cron());
    entries.extend(shell_startup());
    entries.extend(boot_modules());
    entries
}

/// Every source the list above reads, so one that is empty today still
/// counts as watched.
pub const AUTOSTART_SOURCES: &[&str] = &[
    "user desktop entry",
    "system desktop entry",
    "user service",
    "cron",
    "system service",
    "system cron",
    "cron script",
    "shell startup",
    "boot module",
];

/// System units enabled to start, read from the links systemctl enable
/// leaves rather than from systemctl, which would need the system bus.
fn system_services() -> Vec<AutostartEntry> {
    let mut units = Vec::new();
    for base in ["/etc/systemd/system", "/usr/lib/systemd/system"] {
        let Ok(entries) = fs::read_dir(base) else { continue };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !(name.ends_with(".wants") || name.ends_with(".requires")) {
                continue;
            }
            let Ok(links) = fs::read_dir(entry.path()) else { continue };
            units.extend(links.flatten().map(|l| l.file_name().to_string_lossy().into_owned()));
        }
    }
    units.sort();
    units.dedup();
    units
        .into_iter()
        .map(|unit| AutostartEntry {
            key: format!("system service:{unit}"),
            source: "system service".to_string(),
            name: unit.clone(),
            command: format!("systemctl status {unit}"),
        })
        .collect()
}

/// The meaningful lines of a configuration file: no blanks, no comments.
fn lines_of(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .map(|text| {
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

fn files_in(dir: &str) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .map(|entries| entries.flatten().map(|e| e.path()).filter(|p| p.is_file()).collect())
        .unwrap_or_default();
    files.sort();
    files
}

fn system_cron() -> Vec<AutostartEntry> {
    let mut out = Vec::new();
    let mut tables = vec![PathBuf::from("/etc/crontab")];
    tables.extend(files_in("/etc/cron.d"));
    for table in tables {
        let file = table.to_string_lossy().into_owned();
        for line in lines_of(&table) {
            // SHELL=, PATH= and MAILTO= set the environment and schedule nothing.
            let first = line.split_whitespace().next().unwrap_or("");
            if first.contains('=') {
                continue;
            }
            out.push(AutostartEntry {
                key: format!("system cron:{file}|{line}"),
                source: "system cron".to_string(),
                name: format!("Scheduled in {file}"),
                command: line,
            });
        }
    }
    for period in ["hourly", "daily", "weekly", "monthly"] {
        for script in files_in(&format!("/etc/cron.{period}")) {
            let path = script.to_string_lossy().into_owned();
            if path.ends_with("/.placeholder") {
                continue;
            }
            out.push(AutostartEntry {
                key: format!("cron script:{path}"),
                source: "cron script".to_string(),
                name: format!("Runs {period}"),
                command: path,
            });
        }
    }
    out
}

/// Each line of the files a shell reads when it starts, because one line is
/// all it takes to run something at every login.
fn shell_startup() -> Vec<AutostartEntry> {
    let home = home();
    let mut files: Vec<PathBuf> = [
        ".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zshenv", ".config/fish/config.fish",
    ]
    .iter()
    .map(|f| home.join(f))
    .collect();
    files.extend(["/etc/profile", "/etc/bash.bashrc", "/etc/zsh/zshrc", "/etc/zsh/zprofile"].iter().map(PathBuf::from));
    files.extend(files_in("/etc/profile.d"));

    let mut out = Vec::new();
    for file in files {
        let path = file.to_string_lossy().into_owned();
        for line in lines_of(&file) {
            out.push(AutostartEntry {
                key: format!("shell startup:{path}|{line}"),
                source: "shell startup".to_string(),
                name: format!("A line in {path}"),
                command: line,
            });
        }
    }
    out
}

fn boot_modules() -> Vec<AutostartEntry> {
    let mut files = vec![PathBuf::from("/etc/modules")];
    files.extend(files_in("/etc/modules-load.d"));
    let mut out = Vec::new();
    for file in files {
        let path = file.to_string_lossy().into_owned();
        for line in lines_of(&file) {
            let module = line.split_whitespace().next().unwrap_or(&line).to_string();
            out.push(AutostartEntry {
                key: format!("boot module:{module}"),
                source: "boot module".to_string(),
                name: format!("Kernel module {module}"),
                command: format!("loaded at boot, from {path}"),
            });
        }
    }
    out
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
        "system cron" | "shell startup" => file.split_once('|').map(|(path, _)| PathBuf::from(path)),
        "cron script" => Some(PathBuf::from(file)),
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
        "Nothing at {path}, and the systemd journal could not be read either. Reading the journal's authentication messages needs membership of the adm or systemd-journal group."
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
/// A path as one word of an `ExecStart=` line, whatever spaces or signs it holds.
fn unit_quoted(path: &Path) -> String {
    let text = path.to_string_lossy().replace('\\', "\\\\").replace('"', "\\\"").replace('%', "%%");
    format!("\"{text}\"")
}

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
        unit_quoted(executable)
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

    #[test]
    fn a_path_with_spaces_stays_one_word_in_the_unit() {
        let quoted = unit_quoted(Path::new("/home/me/GRT Sentry/50% \"done\"/grt-sentry"));
        assert_eq!(quoted, "\"/home/me/GRT Sentry/50%% \\\"done\\\"/grt-sentry\"");
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
