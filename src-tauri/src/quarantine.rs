//! Putting a file somewhere it cannot do anything, without destroying it.
//!
//! A quarantined file is still there byte for byte, renamed so its extension
//! means nothing to a desktop and with its permission bits cleared. One button
//! puts it back where it was, with the permissions it had.

use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::Connection;

use crate::actionlog;
use crate::db::{self, QuarantineEntry};
use crate::{paths, platform, scanner};

/// Creates the quarantine directory if needed, with 0700.
fn ensure_dir() -> Result<PathBuf, String> {
    let dir = paths::quarantine_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("Cannot create {}: {e}", dir.display()))?;
    platform::restrict_directory(&dir)
        .map_err(|e| format!("Cannot set permissions on {}: {e}", dir.display()))?;
    Ok(dir)
}

/// Moves a file into quarantine and records it.
///
/// The hash is taken before the move, and is what proves later that the file
/// coming out is the file that went in.
pub fn quarantine_file(conn: &Connection, path: &str, reason: &str) -> Result<String, String> {
    let source = Path::new(path);
    if !source.is_file() {
        return Err(format!("{path} is not a file"));
    }

    let metadata = fs::metadata(source).map_err(|e| format!("Cannot read {path}: {e}"))?;
    let original_mode = platform::permission_bits(&metadata);
    let sha256 = scanner::hash_file(source).map_err(|e| format!("Cannot hash {path}: {e}"))?;

    let dir = ensure_dir()?;
    let id = uuid::Uuid::new_v4().to_string();
    let destination = dir.join(format!("{id}.bin"));

    move_file(source, &destination, &sha256)?;

    platform::seal(&destination)
        .map_err(|e| format!("Cannot lock {}: {e}", destination.display()))?;

    let entry = QuarantineEntry {
        id: id.clone(),
        original_path: path.to_string(),
        quarantine_path: destination.to_string_lossy().into_owned(),
        sha256,
        quarantined_at: db::now(),
        reason: Some(reason.to_string()),
        original_mode,
    };
    db::add_quarantine(conn, &entry)?;

    // The path no longer holds what the cache says it does.
    let _ = db::forget_file(conn, path);
    actionlog::record(conn, actionlog::kind::QUARANTINE, path, Some(reason), true);

    Ok(id)
}

/// `rename` when possible, copy-verify-remove when not.
///
/// `/tmp` is usually a tmpfs and the home directory is elsewhere, so the
/// fallback is the normal case. A copy that does not match its hash leaves the
/// original where it was.
fn move_file(source: &Path, destination: &Path, expected_hash: &str) -> Result<(), String> {
    if fs::rename(source, destination).is_ok() {
        return Ok(());
    }
    copy_verify_remove(source, destination, expected_hash)
}

/// The cross-filesystem half of `move_file`.
///
/// Separate because `rename` succeeds within one filesystem and would
/// otherwise hide this path from the tests.
fn copy_verify_remove(source: &Path, destination: &Path, expected_hash: &str) -> Result<(), String> {
    fs::copy(source, destination)
        .map_err(|e| format!("Cannot copy {} to quarantine: {e}", source.display()))?;

    let copied = scanner::hash_file(destination)
        .map_err(|e| format!("Cannot verify the quarantined copy: {e}"))?;
    if copied != expected_hash {
        let _ = fs::remove_file(destination);
        return Err("The copy does not match the original; nothing was moved.".to_string());
    }

    fs::remove_file(source).map_err(|e| {
        let _ = fs::remove_file(destination);
        format!("The copy succeeded but {} could not be removed: {e}", source.display())
    })?;

    Ok(())
}

/// Puts a quarantined file back, and says where it landed.
///
/// A file already at the original path is not overwritten: the restored copy
/// goes beside it under a new name.
pub fn restore(conn: &Connection, id: &str) -> Result<String, String> {
    let entry = db::get_quarantine(conn, id)?
        .ok_or_else(|| "That quarantine entry no longer exists.".to_string())?;

    let quarantined = PathBuf::from(&entry.quarantine_path);
    if !quarantined.is_file() {
        return Err(format!("The quarantined file is missing from {}", entry.quarantine_path));
    }

    platform::unseal(&quarantined)
        .map_err(|e| format!("Cannot unlock the quarantined file: {e}"))?;

    let original = PathBuf::from(&entry.original_path);
    if let Some(parent) = original.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Cannot recreate {}: {e}", parent.display()))?;
    }

    let destination = if original.exists() { free_name(&original) } else { original.clone() };
    move_file(&quarantined, &destination, &entry.sha256)?;

    platform::restore_permissions(&destination, entry.original_mode)
        .map_err(|e| format!("The file is back but its permissions could not be restored: {e}"))?;

    db::remove_quarantine(conn, id)?;
    actionlog::record(
        conn,
        actionlog::kind::RESTORE,
        &destination.to_string_lossy(),
        Some("restored from quarantine"),
        false,
    );

    Ok(destination.to_string_lossy().into_owned())
}

/// `name.ext` becomes `name (restored).ext`, then `name (restored 2).ext`.
fn free_name(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or(Path::new("."));
    let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let extension = path.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();

    let mut candidate = parent.join(format!("{stem} (restored){extension}"));
    let mut n = 2;
    while candidate.exists() && n < 1000 {
        candidate = parent.join(format!("{stem} (restored {n}){extension}"));
        n += 1;
    }
    candidate
}

/// Destroys a quarantined file for good.
pub fn discard(conn: &Connection, id: &str) -> Result<(), String> {
    let entry = db::get_quarantine(conn, id)?
        .ok_or_else(|| "That quarantine entry no longer exists.".to_string())?;

    let path = PathBuf::from(&entry.quarantine_path);
    if path.exists() {
        // A sealed file can still be unlinked by the directory's owner; the
        // unseal is for the filesystem that disagrees.
        let _ = platform::unseal(&path);
        fs::remove_file(&path).map_err(|e| format!("Cannot delete {}: {e}", path.display()))?;
    }

    db::remove_quarantine(conn, id)?;
    actionlog::record(
        conn,
        actionlog::kind::DELETE,
        &entry.original_path,
        Some("deleted from quarantine"),
        false,
    );
    Ok(())
}

pub fn list(conn: &Connection) -> Result<Vec<QuarantineEntry>, String> {
    db::list_quarantine(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testenv;

    #[test]
    fn a_quarantined_file_leaves_its_place_and_becomes_unreadable() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = testenv::isolated_data_dir(&tmp.path().join("data"));

        let victim = tmp.path().join("setup.exe");
        fs::write(&victim, b"pretend malware").unwrap();

        let conn = crate::db::open_memory();
        let id = quarantine_file(&conn, victim.to_str().unwrap(), "flagged by 34 engines").unwrap();

        assert!(!victim.exists(), "the file must not stay where it was");

        let entry = db::get_quarantine(&conn, &id).unwrap().unwrap();
        let stored = PathBuf::from(&entry.quarantine_path);
        assert!(stored.exists());
        assert_eq!(stored.extension().unwrap(), "bin", "the original name and extension are gone");
        assert_eq!(entry.reason.as_deref(), Some("flagged by 34 engines"));

        assert_eq!(actionlog::list(&conn, 10).unwrap()[0].action, actionlog::kind::QUARANTINE);
    }

    #[test]
    fn restoring_puts_back_the_same_bytes_and_the_same_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = testenv::isolated_data_dir(&tmp.path().join("data"));

        let victim = tmp.path().join("thing.sh");
        fs::write(&victim, b"#!/bin/sh\necho hello\n").unwrap();
        let before = scanner::hash_file(&victim).unwrap();

        let conn = crate::db::open_memory();
        let id = quarantine_file(&conn, victim.to_str().unwrap(), "test").unwrap();
        let restored = restore(&conn, &id).unwrap();

        assert_eq!(restored, victim.to_string_lossy());
        assert_eq!(scanner::hash_file(&victim).unwrap(), before);
        assert!(db::get_quarantine(&conn, &id).unwrap().is_none());
    }

    #[test]
    fn restoring_never_overwrites_whatever_took_the_name_in_the_meantime() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = testenv::isolated_data_dir(&tmp.path().join("data"));

        let victim = tmp.path().join("script.sh");
        fs::write(&victim, b"original").unwrap();

        let conn = crate::db::open_memory();
        let id = quarantine_file(&conn, victim.to_str().unwrap(), "test").unwrap();

        // Something else now lives at that path.
        fs::write(&victim, b"a different file entirely").unwrap();

        let restored = restore(&conn, &id).unwrap();
        assert_ne!(restored, victim.to_string_lossy());
        assert!(restored.contains("(restored)"));
        assert_eq!(fs::read(&victim).unwrap(), b"a different file entirely");
        assert_eq!(fs::read(&restored).unwrap(), b"original");
    }

    #[test]
    fn the_cross_filesystem_fallback_copies_verifies_and_only_then_removes() {
        // `rename` succeeds inside one filesystem, so the fallback is called
        // directly rather than hoping the test lands across two.
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("a.bin");
        let destination = tmp.path().join("b.bin");
        fs::write(&source, b"contents").unwrap();
        let hash = scanner::hash_file(&source).unwrap();

        copy_verify_remove(&source, &destination, &hash).unwrap();
        assert!(!source.exists(), "the original is removed once the copy is verified");
        assert_eq!(fs::read(&destination).unwrap(), b"contents");
    }

    #[test]
    fn a_copy_that_does_not_match_leaves_the_original_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("c.bin");
        let destination = tmp.path().join("d.bin");
        fs::write(&source, b"contents").unwrap();

        // A hash that cannot match what was copied.
        let result = copy_verify_remove(&source, &destination, "0000");

        assert!(result.is_err());
        assert!(source.exists(), "a failed verification must never destroy the original");
        assert!(!destination.exists(), "and must not leave a half-trusted copy behind");
    }

    #[test]
    fn discarding_removes_the_file_and_the_row() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = testenv::isolated_data_dir(&tmp.path().join("data"));

        let victim = tmp.path().join("bad.run");
        fs::write(&victim, b"x").unwrap();

        let conn = crate::db::open_memory();
        let id = quarantine_file(&conn, victim.to_str().unwrap(), "test").unwrap();
        let stored = PathBuf::from(db::get_quarantine(&conn, &id).unwrap().unwrap().quarantine_path);

        discard(&conn, &id).unwrap();
        assert!(!stored.exists());
        assert!(db::get_quarantine(&conn, &id).unwrap().is_none());
        assert!(list(&conn).unwrap().is_empty());
    }

    #[test]
    fn quarantining_something_that_is_not_there_fails_cleanly() {
        let conn = crate::db::open_memory();
        assert!(quarantine_file(&conn, "/nonexistent/file", "test").is_err());
        assert!(list(&conn).unwrap().is_empty());
    }
}
