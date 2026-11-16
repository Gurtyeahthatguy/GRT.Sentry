//! A decoy port: a listener that offers no service and notes who knocks.
//!
//! Nothing legitimate connects to a port nobody advertised, so whoever does is
//! looking at what this machine answers. The connection is closed at once
//! without a byte sent. It runs only while the window is open, or while
//! `grt-sentry --decoy` runs in a terminal, never as a resident service.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rusqlite::Connection;

use crate::db;
use crate::state::{Action, Finding, Issue, IssueKind, IssueTarget, Severity};

/// One address is noted at most once in this many seconds.
const QUIET: Duration = Duration::from_secs(10);

/// How far back a scan looks.
const WINDOW: i64 = 24 * 60 * 60;

/// Someone who connected.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Hit {
    pub ip: String,
    pub port: u16,
}

pub struct Decoy {
    pub port: u16,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl Drop for Decoy {
    fn drop(&mut self) {
        // Each listener looks at the flag between waits, so this takes a
        // quarter of a second at most and needs no connection to wake it.
        self.stop.store(true, Ordering::SeqCst);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

/// How long a listener waits between looks at the stop flag.
const POLL: Duration = Duration::from_millis(250);

/// IPv6 on a socket of its own, so it does not take the IPv4 port as well.
#[cfg(not(windows))]
fn bind_v6(port: u16) -> std::io::Result<TcpListener> {
    use socket2::{Domain, Socket, Type};
    let socket = Socket::new(Domain::IPV6, Type::STREAM, None)?;
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;
    socket.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port).into())?;
    socket.listen(16)?;
    Ok(socket.into())
}

#[cfg(windows)]
fn bind_v6(port: u16) -> std::io::Result<TcpListener> {
    TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port))
}

/// Starts listening, and calls `on_hit` for every connection that is noted.
pub fn start(port: u16, on_hit: impl Fn(Hit) + Send + Sync + 'static) -> Result<Decoy, String> {
    if port == 0 {
        return Err("Choose a port for the decoy.".to_string());
    }
    let v4 = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            format!("Port {port} needs administrator rights; ports from 1024 up do not.")
        } else {
            format!("Port {port} cannot be used: {e}")
        }
    })?;
    let mut listeners = vec![v4];
    // A machine without IPv6 still gets the decoy on IPv4.
    if let Ok(v6) = bind_v6(port) {
        listeners.push(v6);
    }

    // Created here, once, so the listeners never race to set it up.
    db::open()?;

    let stop = Arc::new(AtomicBool::new(false));
    let on_hit = Arc::new(on_hit);
    let threads = listeners
        .into_iter()
        .map(|listener| {
            let stop = stop.clone();
            let on_hit = on_hit.clone();
            std::thread::spawn(move || listen(listener, port, &stop, &*on_hit))
        })
        .collect();
    Ok(Decoy { port, stop, threads })
}

fn listen(listener: TcpListener, port: u16, stop: &AtomicBool, on_hit: &(dyn Fn(Hit) + Send + Sync)) {
    let mut conn = db::open().ok();
    let mut last: HashMap<IpAddr, Instant> = HashMap::new();
    if listener.set_nonblocking(true).is_err() {
        return;
    }
    while !stop.load(Ordering::SeqCst) {
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            // Nothing waiting, or a connection gone before it was taken.
            Err(_) => {
                std::thread::sleep(POLL);
                continue;
            }
        };
        let peer = stream.peer_addr().ok();
        // Closed without a word: there is no service here to describe.
        drop(stream);
        let Some(peer) = peer else { continue };
        let ip = crate::platform::normalise(peer.ip());
        if last.get(&ip).is_some_and(|t| t.elapsed() < QUIET) {
            continue;
        }
        last.insert(ip, Instant::now());
        if last.len() > 10_000 {
            last.clear();
        }
        if conn.is_none() {
            conn = db::open().ok();
        }
        match &conn {
            Some(conn) => {
                if let Err(e) = db::record_decoy_hit(conn, &ip.to_string(), port) {
                    eprintln!("grt-sentry: a knock on the decoy could not be recorded: {e}");
                }
            }
            None => eprintln!("grt-sentry: a knock on the decoy could not be recorded: the database did not open"),
        }
        on_hit(Hit { ip: ip.to_string(), port });
    }
}

/// An issue for every address that touched the decoy in the last day.
pub fn findings(conn: &Connection, now: i64) -> Vec<Finding> {
    let Ok(hits) = db::decoy_hits_since(conn, now - WINDOW) else { return Vec::new() };
    hits.into_iter()
        .filter(|(ip, ..)| !db::ip_trusted(conn, ip))
        .map(|(ip, count, last, port)| {
            Finding::new(
                Issue {
                    kind: IssueKind::DecoyTouched,
                    severity: Severity::Warning,
                    title: format!("{ip} knocked on the decoy port"),
                    location: ip.clone(),
                    detail: Some(format!(
                        "{count} {} in the last 24 hours on port {port}, the last at {}. The port offers no service and \
                         nobody was told about it, so whoever connects is looking at what this machine answers: a \
                         scanner, a worm, or someone on the same network.",
                        if count == 1 { "connection" } else { "connections" },
                        crate::report::local_time(last)
                    )),
                    actions: vec![
                        Action::new("block_ip", "Block address", true),
                        Action::new("trust", "Expected", false),
                        Action::ignore(),
                    ],
                    ..Default::default()
                },
                IssueTarget::Connection { ip, pid: None, process: None },
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;
    use std::sync::Mutex;

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    #[test]
    fn a_knock_is_noted_once_and_answered_with_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = crate::testenv::isolated_data_dir(&tmp.path().join("data"));
        let port = free_port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = seen.clone();
        let decoy = start(port, move |hit| record.lock().unwrap().push(hit)).unwrap();

        for _ in 0..3 {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
            use std::io::Read;
            let mut answer = Vec::new();
            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let _ = stream.read_to_end(&mut answer);
            assert!(answer.is_empty(), "the decoy says nothing");
        }
        std::thread::sleep(Duration::from_millis(200));
        drop(decoy);

        let hits = seen.lock().unwrap().clone();
        assert_eq!(hits.len(), 1, "three knocks in ten seconds are one note");
        assert_eq!(hits[0].ip, "127.0.0.1");

        let conn = db::open().unwrap();
        let found = findings(&conn, db::now());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].issue.kind, IssueKind::DecoyTouched);
        assert!(found[0].issue.detail.as_deref().unwrap().contains(&format!("port {port}")));
    }

    #[test]
    fn a_port_in_use_is_refused_with_a_reason() {
        let held = TcpListener::bind("0.0.0.0:0").unwrap();
        let port = held.local_addr().unwrap().port();
        assert!(start(port, |_| {}).err().unwrap().contains("cannot be used"));
        assert!(start(0, |_| {}).is_err());
    }

    #[test]
    fn stopping_does_not_note_its_own_wake_up() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = crate::testenv::isolated_data_dir(&tmp.path().join("data"));
        let seen = Arc::new(Mutex::new(0));
        let record = seen.clone();
        drop(start(free_port(), move |_| *record.lock().unwrap() += 1).unwrap());
        assert_eq!(*seen.lock().unwrap(), 0);
    }
}
