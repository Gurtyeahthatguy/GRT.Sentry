//! The Windows answers.
//!
//! The socket table, the elevation check and the process list come from the
//! Win32 API, because there is no file to read and no command whose output is
//! stable enough to parse. Everything else drives a program Windows ships with:
//! `netsh` for the firewall, `reg` and `schtasks` for what starts by itself,
//! `wevtutil` for the security log, `winget` for updates.
//!
//! Two operations need an elevated process: blocking an address and closing a
//! connection. Windows has no equivalent of a per-command authentication
//! dialog, so instead of asking each time the program reports whether it is
//! elevated and says what to do about it.

use std::fs::{self, Metadata};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, SetTcpEntry, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_LH, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::{AutostartEntry, LogAccess, RawSocket, ScheduleStatus, TargetSocket};

pub const SYSTEM_NAME: &str = "Windows";

// --- where things live ----------------------------------------------------

fn env_dir(name: &str, fallback: &str) -> PathBuf {
    match std::env::var_os(name) {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => PathBuf::from(fallback),
    }
}

fn profile() -> PathBuf {
    env_dir("USERPROFILE", "C:\\Users\\Default")
}

/// `%LOCALAPPDATA%`, which is where data that should not roam belongs.
pub fn data_dir() -> PathBuf {
    match std::env::var_os("LOCALAPPDATA") {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => profile().join("AppData\\Local"),
    }
}

/// `%APPDATA%`.
pub fn config_dir() -> PathBuf {
    match std::env::var_os("APPDATA") {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => profile().join("AppData\\Roaming"),
    }
}

/// Windows keeps the shell folders under the profile, and does not localise
/// the path the way a Linux desktop does.
pub fn user_dir(kind: &str, fallback: &str) -> PathBuf {
    let _ = kind;
    profile().join(fallback)
}

pub fn default_scan_paths() -> Vec<String> {
    [
        profile().join("Downloads"),
        profile().join("Desktop"),
        env_dir("TEMP", "C:\\Windows\\Temp"),
    ]
    .iter()
    .map(|p| p.to_string_lossy().into_owned())
    .collect()
}

/// The Windows files worth a hash. Short, and all small.
pub fn default_integrity_paths() -> Vec<String> {
    let root = env_dir("SystemRoot", "C:\\Windows");
    [
        root.join("System32\\drivers\\etc\\hosts"),
        root.join("System32\\drivers\\etc\\services"),
        root.join("System32\\cmd.exe"),
        root.join("System32\\svchost.exe"),
        root.join("System32\\userinit.exe"),
    ]
    .iter()
    .map(|p| p.to_string_lossy().into_owned())
    .collect()
}

/// There is no file to read: failed logons are in the event log, and the
/// reader below ignores this path.
pub fn default_auth_log() -> String {
    "Security event log".to_string()
}

// --- files ----------------------------------------------------------------

/// Windows has no executable bit, so the extension is the only signal, and
/// the caller already checks that.
pub fn is_executable(_metadata: &Metadata) -> bool {
    false
}

/// 1 when the file was read-only, 0 otherwise. Restoring reads it back.
pub fn permission_bits(metadata: &Metadata) -> u32 {
    u32::from(metadata.permissions().readonly())
}

/// Makes a quarantined file inert as far as Windows allows without rewriting
/// its ACL: read-only, and named so nothing associates it with a program.
pub fn seal(path: &Path) -> io::Result<()> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_readonly(true);
    fs::set_permissions(path, perms)
}

pub fn unseal(path: &Path) -> io::Result<()> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_readonly(false);
    fs::set_permissions(path, perms)
}

pub fn restore_permissions(path: &Path, bits: u32) -> io::Result<()> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_readonly(bits != 0);
    fs::set_permissions(path, perms)
}

/// The user profile is already private to the user on Windows, and setting an
/// ACL by hand would be a step backwards from what the system inherits.
pub fn restrict_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

pub fn restrict_file(_file: &fs::File) -> io::Result<()> {
    Ok(())
}

// --- sockets --------------------------------------------------------------

/// `dwState` as the TCP table reports it, spelled as the interface shows it.
fn tcp_state(state: u32) -> String {
    match state {
        1 => "Closed",
        2 => "Listen",
        3 => "SynSent",
        4 => "SynReceived",
        5 => "Established",
        6 => "FinWait1",
        7 => "FinWait2",
        8 => "CloseWait",
        9 => "Closing",
        10 => "LastAck",
        11 => "TimeWait",
        12 => "DeleteTcb",
        _ => "Unknown",
    }
    .to_string()
}

/// The table stores ports in network order in the low two bytes.
fn port_of(raw: u32) -> u16 {
    u16::from_be_bytes([(raw & 0xff) as u8, ((raw >> 8) & 0xff) as u8])
}

/// Asks for the table twice: once for the size, once for the contents.
fn tcp_table(family: u32) -> Result<Vec<u8>, String> {
    let mut size: u32 = 0;
    // The first call is expected to fail, and only sets the size.
    unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
    }
    if size == 0 {
        return Ok(Vec::new());
    }

    let mut buffer = vec![0u8; size as usize];
    let result = unsafe {
        GetExtendedTcpTable(
            buffer.as_mut_ptr() as *mut _,
            &mut size,
            0,
            family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if result != NO_ERROR {
        return Err(format!("the TCP table could not be read (error {result})"));
    }
    buffer.truncate(size as usize);
    Ok(buffer)
}

/// Every TCP connection with a peer, from the Win32 socket table.
///
/// UDP is not listed. The Windows UDP table carries the local endpoint and the
/// owning process but no remote address, so there is no conversation to show.
pub fn sockets() -> Result<Vec<RawSocket>, String> {
    let names = process_names();
    let mut out = Vec::new();

    let buffer = tcp_table(AF_INET as u32)?;
    if !buffer.is_empty() {
        let table = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
        let count = unsafe { (*table).dwNumEntries } as usize;
        let rows = unsafe { std::ptr::addr_of!((*table).table) } as *const MIB_TCPROW_OWNER_PID;
        for index in 0..count {
            let row = unsafe { &*rows.add(index) };
            let remote = Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes());
            let remote_port = port_of(row.dwRemotePort);
            if remote.is_unspecified() || remote_port == 0 {
                continue;
            }
            let pid = row.dwOwningPid as i32;
            out.push(RawSocket {
                protocol: "tcp",
                local_addr: IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
                local_port: port_of(row.dwLocalPort),
                remote_addr: IpAddr::V4(remote),
                remote_port,
                state: tcp_state(row.dwState),
                pid: Some(pid),
                process: names.get(&pid).cloned(),
            });
        }
    }

    let buffer = tcp_table(AF_INET6 as u32)?;
    if !buffer.is_empty() {
        let table = buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
        let count = unsafe { (*table).dwNumEntries } as usize;
        let rows = unsafe { std::ptr::addr_of!((*table).table) } as *const MIB_TCP6ROW_OWNER_PID;
        for index in 0..count {
            let row = unsafe { &*rows.add(index) };
            let remote = Ipv6Addr::from(row.ucRemoteAddr);
            let remote_port = port_of(row.dwRemotePort);
            if remote.is_unspecified() || remote_port == 0 {
                continue;
            }
            let pid = row.dwOwningPid as i32;
            out.push(RawSocket {
                protocol: "tcp6",
                local_addr: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                local_port: port_of(row.dwLocalPort),
                remote_addr: IpAddr::V6(remote),
                remote_port,
                state: tcp_state(row.dwState),
                pid: Some(pid),
                process: names.get(&pid).cloned(),
            });
        }
    }

    Ok(out)
}

pub fn socket_exists(target: &TargetSocket) -> bool {
    let Ok(open) = sockets() else { return false };
    open.iter().any(|s| {
        s.local_port == target.local_port
            && s.remote_port == target.remote_port
            && normalise(s.local_addr) == target.local
            && normalise(s.remote_addr) == target.remote
    })
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

/// Sets each connection to DELETE_TCB, which is how Windows closes one.
///
/// It needs an elevated process, and it exists for IPv4 TCP only: there is no
/// public call that ends an IPv6 connection or a UDP association.
pub fn close_sockets(targets: &[TargetSocket]) -> Result<String, String> {
    if !is_elevated() {
        return Err(
            "Closing a connection needs administrator rights. Start GRT Sentry as administrator, or stop the process instead."
                .to_string(),
        );
    }

    let mut complaints = Vec::new();

    for target in targets {
        let (IpAddr::V4(local), IpAddr::V4(remote)) = (target.local, target.remote) else {
            complaints.push("Windows cannot close an IPv6 connection on request.".to_string());
            continue;
        };
        if !target.tcp {
            complaints.push("Windows cannot close a UDP association on request.".to_string());
            continue;
        }

        let mut row: MIB_TCPROW_LH = unsafe { std::mem::zeroed() };
        // 12 is MIB_TCP_STATE_DELETE_TCB: the state that ends the connection.
        row.Anonymous.dwState = 12;
        row.dwLocalAddr = u32::from_ne_bytes(local.octets());
        row.dwLocalPort = u32::from(target.local_port.to_be());
        row.dwRemoteAddr = u32::from_ne_bytes(remote.octets());
        row.dwRemotePort = u32::from(target.remote_port.to_be());

        let result = unsafe { SetTcpEntry(&row) };
        if result != NO_ERROR {
            complaints.push(format!("the connection to {remote} was refused (error {result})"));
        }
    }

    Ok(complaints.join(" "))
}

pub fn explain_close_failure(complaint: &str) -> String {
    if complaint.is_empty() {
        return "The connection ended on its own before it could be closed.".to_string();
    }
    format!("The connection is still open: {complaint}")
}

// --- the firewall ---------------------------------------------------------

/// Every rule this program adds carries this prefix, so they can be found and
/// removed without touching anything else in the firewall.
fn rule_name(ip: &IpAddr) -> String {
    format!("GRT Sentry block {ip}")
}

pub fn block_address(ip: &IpAddr) -> Result<(), String> {
    require_elevation()?;
    let name = format!("name={}", rule_name(ip));
    let remote = format!("remoteip={ip}");
    run_plain(
        "netsh",
        &["advfirewall", "firewall", "add", "rule", &name, "dir=out", "action=block", &remote],
    )
    .map(|_| ())
}

pub fn unblock_address(ip: &IpAddr) -> Result<(), String> {
    require_elevation()?;
    let name = format!("name={}", rule_name(ip));
    run_plain("netsh", &["advfirewall", "firewall", "delete", "rule", &name]).map(|_| ())
}

pub fn firewall_ready() -> bool {
    run_plain("netsh", &["advfirewall", "show", "allprofiles", "state"]).is_ok()
}

pub fn firewall_note() -> &'static str {
    "Windows Defender Firewall, through netsh"
}

// --- processes ------------------------------------------------------------

/// pid to executable name, from one snapshot of the process list.
fn process_names() -> std::collections::HashMap<i32, String> {
    let mut map = std::collections::HashMap::new();
    let snapshot: HANDLE = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return map;
    }

    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    let mut ok = unsafe { Process32FirstW(snapshot, &mut entry) };
    while ok != 0 {
        let end = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
        let name = String::from_utf16_lossy(&entry.szExeFile[..end]);
        map.insert(entry.th32ProcessID as i32, name);
        ok = unsafe { Process32NextW(snapshot, &mut entry) };
    }

    unsafe { CloseHandle(snapshot) };
    map
}

pub fn process_name(pid: i32) -> Option<String> {
    process_names().get(&pid).cloned()
}

pub fn process_exists(pid: i32) -> bool {
    process_names().contains_key(&pid)
}

/// `taskkill` without `/f`, which asks the program to close rather than
/// ending it outright.
pub fn stop_process(pid: i32) -> Result<(), String> {
    run_plain("taskkill", &["/pid", &pid.to_string()]).map(|_| ())
}

// --- elevation ------------------------------------------------------------

/// Windows has no per-command authentication dialog, so the answer is about
/// the process itself.
pub fn elevation_available() -> bool {
    is_elevated()
}

pub fn elevation_note() -> &'static str {
    "the process runs elevated"
}

/// Whether this process holds an elevated token.
pub fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size: u32 = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            size,
            &mut size,
        );
        CloseHandle(token);

        ok != 0 && elevation.TokenIsElevated != 0
    }
}

fn require_elevation() -> Result<(), String> {
    if is_elevated() {
        Ok(())
    } else {
        Err("This needs administrator rights. Close GRT Sentry, right-click it and choose Run as administrator.".to_string())
    }
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
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let message = if stderr.is_empty() { stdout } else { stderr };
        Err(if message.is_empty() { format!("{program} failed") } else { message })
    }
}

pub fn run_privileged(program: &str, args: &[&str]) -> Result<String, String> {
    require_elevation()?;
    run_plain(program, args)
}

pub fn run_privileged_capture(program: &str, args: &[&str]) -> Result<std::process::Output, String> {
    require_elevation()?;
    Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("Cannot run {program}: {e}"))
}

// --- pending updates ------------------------------------------------------

pub fn updates_tool_available() -> bool {
    run_plain("winget", &["--version"]).is_ok()
}

pub fn update_tool_name() -> &'static str {
    "winget"
}

pub fn update_command() -> &'static str {
    "winget upgrade --all"
}

/// Packages winget has a newer version for.
///
/// Windows does not mark an update as a security fix the way a Debian pocket
/// does, so this is every pending upgrade rather than a filtered set, and the
/// interface says so.
pub fn security_updates() -> Result<Vec<String>, String> {
    let text = run_plain("winget", &["upgrade", "--include-unknown"])?;
    Ok(parse_winget(&text))
}

pub fn parse_winget(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut header_seen = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // The table starts after a row of dashes.
        if trimmed.starts_with("---") {
            header_seen = true;
            continue;
        }
        if !header_seen {
            continue;
        }
        // The last lines are a count, not a package.
        if trimmed.starts_with(char::is_numeric) && trimmed.contains("upgrade") {
            break;
        }
        if let Some(name) = trimmed.split("  ").next() {
            let name = name.trim();
            if !name.is_empty() {
                out.push(name.to_string());
            }
        }
    }

    out.sort();
    out.dedup();
    out
}

/// Windows asks for a restart through the servicing stack, which is not
/// readable without the update API. Left to the system's own notice.
pub fn reboot_required() -> bool {
    false
}

/// Libraries Windows is told to insert into every process, from the
/// `AppInit_DLLs` value.
///
/// It is the counterpart of ld.so.preload, and is read only when
/// `LoadAppInit_DLLs` says the loader is honouring it.
pub fn injected_libraries() -> Option<(String, Vec<String>)> {
    let key = "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
    let text = run_plain("reg", &["query", key, "/v", "LoadAppInit_DLLs"]).ok()?;
    let enabled = text
        .split_whitespace()
        .last()
        .map(|value| value != "0x0")
        .unwrap_or(false);
    if !enabled {
        return None;
    }

    let text = run_plain("reg", &["query", key, "/v", "AppInit_DLLs"]).ok()?;
    let value = text.lines().find_map(|line| {
        let rest = line.split("REG_SZ").nth(1)?;
        Some(rest.trim().to_string())
    })?;

    let listed = value
        .split([',', ' '])
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect();
    Some((format!("{key}\\AppInit_DLLs"), listed))
}

/// What the list of pending updates is called here.
///
/// Windows does not mark an update as a security fix, so the heading does not
/// claim these are security fixes.
pub fn updates_heading() -> &'static str {
    "These packages have a newer version available"
}

// --- what starts by itself ------------------------------------------------

pub fn autostart_entries() -> Vec<AutostartEntry> {
    let mut entries = Vec::new();
    entries.extend(run_keys("HKCU", "user registry"));
    entries.extend(run_keys("HKLM", "system registry"));
    entries.extend(startup_folder());
    entries.extend(scheduled_tasks());
    entries
}

/// `reg query` prints `    Name    REG_SZ    Value`, which is stable across
/// Windows versions and not translated.
fn run_keys(hive: &str, source: &str) -> Vec<AutostartEntry> {
    let key = format!("{hive}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    let Ok(text) = run_plain("reg", &["query", &key]) else {
        return vec![];
    };

    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let name = parts.next()?;
            let kind = parts.next()?;
            if !kind.starts_with("REG_") {
                return None;
            }
            let command = line.split_once(kind)?.1.trim().to_string();
            Some(AutostartEntry {
                key: format!("{source}:{name}"),
                source: source.to_string(),
                name: name.to_string(),
                command,
            })
        })
        .collect()
}

fn startup_folder() -> Vec<AutostartEntry> {
    let dir = config_dir().join("Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    let Ok(read) = fs::read_dir(&dir) else {
        return vec![];
    };

    read.flatten()
        .filter(|entry| entry.path().is_file())
        .map(|entry| {
            let file = entry.file_name().to_string_lossy().into_owned();
            AutostartEntry {
                key: format!("startup folder:{file}"),
                source: "startup folder".to_string(),
                name: file.clone(),
                command: entry.path().to_string_lossy().into_owned(),
            }
        })
        .collect()
}

/// Scheduled tasks, as CSV so the fields survive a locale.
fn scheduled_tasks() -> Vec<AutostartEntry> {
    let Ok(text) = run_plain("schtasks", &["/query", "/fo", "csv", "/nh"]) else {
        return vec![];
    };

    text.lines()
        .filter_map(|line| {
            let name = line.split(',').next()?.trim().trim_matches('"');
            if name.is_empty() || name == "TaskName" {
                return None;
            }
            Some(AutostartEntry {
                key: format!("scheduled task:{name}"),
                source: "scheduled task".to_string(),
                name: name.to_string(),
                command: format!("schtasks /query /tn \"{name}\" /v"),
            })
        })
        .collect()
}

pub fn entry_path_for(source: &str, file: &str) -> Option<PathBuf> {
    match source {
        "startup folder" => {
            Some(config_dir().join("Microsoft\\Windows\\Start Menu\\Programs\\Startup").join(file))
        }
        _ => None,
    }
}

// --- failed logons --------------------------------------------------------

/// Event 4625 is a failed logon. Reading the Security log needs an elevated
/// process, which is why this reports Denied rather than failing.
pub fn read_auth_log(_path: &str) -> LogAccess {
    if !is_elevated() {
        return LogAccess::Denied;
    }
    match read_security_log() {
        Ok(text) => LogAccess::Ok(text),
        Err(_) => LogAccess::Missing,
    }
}

fn read_security_log() -> Result<String, String> {
    run_plain(
        "wevtutil",
        &[
            "qe",
            "Security",
            "/q:*[System[(EventID=4625)]]",
            "/rd:true",
            "/c:400",
            "/f:text",
        ],
    )
}

pub fn read_auth_log_privileged(_path: &str) -> Result<String, String> {
    require_elevation()?;
    read_security_log()
}

pub fn auth_log_denied_detail(_path: &str) -> String {
    "Failed logons are in the Security event log, which only an elevated process may read. Start GRT Sentry as administrator to include this check.".to_string()
}

pub fn auth_log_missing_detail(_path: &str) -> String {
    "The Security event log could not be read on this system, so failed logons are not part of this scan.".to_string()
}

// --- the scheduled scan ---------------------------------------------------

const TASK_NAME: &str = "GRT Sentry scan";

pub fn scheduling_supported() -> bool {
    run_plain("schtasks", &["/query", "/tn", TASK_NAME]).is_ok()
        || run_plain("schtasks", &["/?"]).is_ok()
}

pub fn schedule_install(frequency: &str, executable: &Path) -> Result<(), String> {
    let schedule = match frequency {
        "hourly" => "HOURLY",
        "weekly" => "WEEKLY",
        _ => "DAILY",
    };

    let command = format!("\"{}\" --scan", executable.display());
    run_plain(
        "schtasks",
        &["/create", "/f", "/tn", TASK_NAME, "/tr", &command, "/sc", schedule, "/st", "03:00"],
    )
    .map(|_| ())
}

pub fn schedule_remove() -> Result<(), String> {
    let _ = run_plain("schtasks", &["/delete", "/f", "/tn", TASK_NAME]);
    Ok(())
}

pub fn schedule_status() -> ScheduleStatus {
    let Ok(text) = run_plain("schtasks", &["/query", "/tn", TASK_NAME, "/fo", "list"]) else {
        return ScheduleStatus {
            installed: false,
            enabled: false,
            frequency: None,
            next_run: None,
            supported: scheduling_supported(),
        };
    };

    let field = |label: &str| {
        text.lines()
            .find(|line| line.trim_start().starts_with(label))
            .and_then(|line| line.split_once(':'))
            .map(|(_, value)| value.trim().to_string())
            .filter(|v| !v.is_empty())
    };

    let status = field("Status").unwrap_or_default();

    ScheduleStatus {
        installed: true,
        enabled: !status.eq_ignore_ascii_case("Disabled"),
        frequency: field("Schedule Type"),
        next_run: field("Next Run Time"),
        supported: true,
    }
}

// --- notification ---------------------------------------------------------

/// Windows ships no command that raises a notification, so this goes through
/// the balloon PowerShell can build from the forms assembly. The text is
/// generated here and holds no file name, which keeps the quoting safe.
pub fn notify(title: &str, body: &str, _urgent: bool) {
    let safe = |text: &str| text.replace('\'', "").replace('"', "");
    let script = format!(
        "Add-Type -AssemblyName System.Windows.Forms; \
         $n = New-Object System.Windows.Forms.NotifyIcon; \
         $n.Icon = [System.Drawing.SystemIcons]::Warning; \
         $n.Visible = $true; \
         $n.ShowBalloonTip(10000, '{}', '{}', 'Warning'); \
         Start-Sleep -Seconds 10",
        safe(title),
        safe(body)
    );

    let _ = Command::new("powershell")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &script])
        .status();
}
