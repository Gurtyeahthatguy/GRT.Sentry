//! An optional eye on the download folders.
//!
//! Off by default, since a permanent watcher is a permanent process. When it
//! is on it notices that an interesting file appeared and tells the window.
//!
//! It never starts a scan by itself: a scan spends VirusTotal requests out of
//! a budget of four a minute, and an archive being unpacked would spend all of
//! them in seconds.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use notify::{Event, EventKind, RecursiveMode, Watcher as _};

/// Repeat events for one path are ignored inside this window.
const DEBOUNCE: Duration = Duration::from_secs(3);

/// Keeps the watcher alive. Dropping it stops watching.
pub struct FolderWatcher {
    _inner: notify::RecommendedWatcher,
    pub watching: Vec<String>,
}

/// Starts watching the given directories.
///
/// `on_file` runs on the watcher's own thread, so it should hand the path on
/// rather than do work.
pub fn start<F>(paths: &[String], deep: bool, on_file: F) -> Result<FolderWatcher, String>
where
    F: Fn(String) + Send + 'static,
{
    let recent: Mutex<HashMap<String, Instant>> = Mutex::new(HashMap::new());

    let mut watcher = notify::recommended_watcher(move |result: notify::Result<Event>| {
        let Ok(event) = result else { return };
        if !matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
            return;
        }

        for path in event.paths {
            if !path.is_file() {
                continue;
            }

            let Ok(metadata) = std::fs::metadata(&path) else { continue };
            let executable = crate::platform::is_executable(&metadata);
            if !crate::scanner::is_interesting(&path, executable, deep) {
                continue;
            }

            let key = path.to_string_lossy().into_owned();
            {
                let mut recent = recent.lock().unwrap();
                let now = Instant::now();
                if let Some(previous) = recent.get(&key) {
                    if now.duration_since(*previous) < DEBOUNCE {
                        continue;
                    }
                }
                recent.insert(key.clone(), now);
                // The map would otherwise grow for the life of the program.
                if recent.len() > 512 {
                    recent.retain(|_, seen| now.duration_since(*seen) < Duration::from_secs(300));
                }
            }

            on_file(key);
        }
    })
    .map_err(|e| format!("Cannot start the folder watcher: {e}"))?;

    let mut watching = Vec::new();
    for raw in paths {
        let path = crate::paths::expand_tilde(raw);
        if !path.is_dir() {
            continue;
        }
        // Non-recursive, because a whole tree costs one inotify watch per
        // directory and the kernel grants a limited number.
        match watcher.watch(Path::new(&path), RecursiveMode::NonRecursive) {
            Ok(()) => watching.push(path.to_string_lossy().into_owned()),
            Err(e) => eprintln!("grt-sentry: cannot watch {}: {e}", path.display()),
        }
    }

    if watching.is_empty() {
        return Err("None of the configured folders could be watched.".to_string());
    }

    Ok(FolderWatcher { _inner: watcher, watching })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn an_interesting_file_appearing_is_announced_once() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, rx) = mpsc::channel();

        let _watcher = start(&[dir.path().to_string_lossy().into_owned()], false, move |path| {
            let _ = tx.send(path);
        })
        .expect("the watcher must start");

        // The watch has to be established before the write.
        std::thread::sleep(Duration::from_millis(300));
        std::fs::write(dir.path().join("setup.sh"), b"#!/bin/sh\n").unwrap();

        let received = rx.recv_timeout(Duration::from_secs(5)).expect("an event must arrive");
        assert!(received.ends_with("setup.sh"));

        // A second write within the debounce window says nothing more.
        std::fs::write(dir.path().join("setup.sh"), b"#!/bin/sh\necho\n").unwrap();
        assert!(rx.recv_timeout(Duration::from_millis(800)).is_err());
    }

    #[test]
    fn an_ordinary_document_is_not_announced() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, rx) = mpsc::channel();

        let _watcher = start(&[dir.path().to_string_lossy().into_owned()], false, move |path| {
            let _ = tx.send(path);
        })
        .unwrap();

        std::thread::sleep(Duration::from_millis(300));
        std::fs::write(dir.path().join("notes.txt"), b"hello").unwrap();

        assert!(rx.recv_timeout(Duration::from_millis(800)).is_err());
    }

    #[test]
    fn watching_nothing_that_exists_is_an_error_rather_than_a_silent_no_op() {
        assert!(start(&["/nonexistent/place".to_string()], false, |_| {}).is_err());
    }
}
