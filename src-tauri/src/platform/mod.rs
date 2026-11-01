//! Everything that differs between operating systems.
//!
//! The rest of the program asks questions: which sockets are open, what starts
//! at boot, who failed to log in, how a quarantined file is made inert. The
//! answers live here, once per system, behind one set of signatures.
//!
//! Keeping them in one place is also what makes the unsafe code auditable. The
//! Windows half calls the socket table API directly; nothing outside this
//! module does.

use std::net::IpAddr;
use std::path::PathBuf;

#[cfg(not(windows))]
mod linux;
#[cfg(not(windows))]
pub use linux::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

/// One socket as the operating system reports it, before this program adds
/// history or location to it.
#[derive(Debug, Clone)]
pub struct RawSocket {
    /// "tcp", "tcp6", "udp" or "udp6".
    pub protocol: &'static str,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub state: String,
    pub pid: Option<i32>,
    pub process: Option<String>,
}

/// A socket named precisely enough to be destroyed, every field already
/// through a parser.
#[derive(Debug, Clone)]
pub struct TargetSocket {
    pub tcp: bool,
    pub local: IpAddr,
    pub local_port: u16,
    pub remote: IpAddr,
    pub remote_port: u16,
}

/// What a scheduled scan looks like right now.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScheduleStatus {
    pub installed: bool,
    pub enabled: bool,
    pub frequency: Option<String>,
    pub next_run: Option<String>,
    /// False where this system has no scheduler this program can drive.
    pub supported: bool,
}

/// What came back when the program tried to read the authentication record.
pub enum LogAccess {
    Ok(String),
    /// It exists but this user may not read it.
    Denied,
    /// There is nothing to read on this system.
    Missing,
}

/// One thing that starts by itself.
#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct AutostartEntry {
    /// Stable across runs: source plus file, key or unit name.
    pub key: String,
    pub source: String,
    pub name: String,
    pub command: String,
}

/// Where a startup entry is declared, when it is a file.
pub fn autostart_entry_path(key: &str) -> Option<PathBuf> {
    let (source, file) = key.split_once(':')?;
    entry_path_for(source, file)
}

/// A running process, as far as this user can see it.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: i32,
    pub name: String,
    /// What the executable link says, " (deleted)" included, when readable.
    pub exe: Option<String>,
}

/// A process the kernel answers for but the process list leaves out.
#[derive(Debug, Clone)]
pub struct HiddenProcess {
    pub pid: i32,
    pub name: String,
}

/// The loaded kernel modules, from the two places that list them.
#[derive(Debug, Clone, Default)]
pub struct KernelModules {
    /// Names in /proc/modules.
    pub listed: Vec<String>,
    /// Loadable modules in /sys/module, with their taint letters.
    pub sysfs: Vec<(String, String)>,
}

/// A file with set-user-ID, set-group-ID or capabilities.
#[derive(Debug, Clone)]
pub struct SpecialFile {
    pub path: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Permitted capabilities as a bit mask, when the file carries any.
    pub capabilities: Option<u64>,
}

/// Which family a browser belongs to, which decides how its records read.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BrowserKind {
    Firefox,
    Chromium,
}

/// An account in the password database.
#[derive(Debug, Clone, PartialEq)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub shell: String,
}

/// A directory on the search path, and what about it is unsafe.
#[derive(Debug, Clone, Default)]
pub struct PathEntry {
    pub dir: String,
    pub world_writable: bool,
    pub sticky: bool,
    /// Programs in it that anyone may overwrite.
    pub writable_files: Vec<String>,
}
