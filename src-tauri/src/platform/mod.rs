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
