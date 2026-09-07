//! One SQLite file at `~/.local/share/grt-sentry/sentry.db`.
//!
//! `file_cache` is the table that matters: a file whose path, size and
//! modification time match a row here is never read again. The rest are small
//! by nature.
//!
//! Everything returns `Result<_, String>`, because these strings reach the
//! interface and the call sites wrap them in something readable.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

use crate::paths;

/// Bumped when the schema changes in a way that needs migrating.
const SCHEMA_VERSION: i64 = 1;

/// Seconds since the epoch.
pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn wrap(e: rusqlite::Error) -> String {
    e.to_string()
}

/// Opens the database in the user's data directory, creating it if needed.
pub fn open() -> Result<Connection, String> {
    let dir = paths::data_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("Cannot create {}: {e}", dir.display()))?;
    open_at(&paths::database_path())
}

/// Opens a database at an explicit path, for the tests.
pub fn open_at(path: &Path) -> Result<Connection, String> {
    let conn = Connection::open(path).map_err(|e| format!("Cannot open {}: {e}", path.display()))?;
    prepare(&conn)?;
    Ok(conn)
}

/// An in-memory database, for tests that do not care about a file.
#[cfg(test)]
pub fn open_memory() -> Connection {
    let conn = Connection::open_in_memory().expect("in-memory database");
    prepare(&conn).expect("schema");
    conn
}

fn prepare(conn: &Connection) -> Result<(), String> {
    // WAL keeps a reader from blocking a writer and survives a crash mid-scan.
    // NORMAL synchronous can lose the last transaction on a power cut, which
    // for a hash cache is not a loss.
    conn.pragma_update(None, "journal_mode", "WAL").map_err(wrap)?;
    conn.pragma_update(None, "synchronous", "NORMAL").map_err(wrap)?;
    conn.pragma_update(None, "foreign_keys", "ON").map_err(wrap)?;
    apply_schema(conn)
}

fn apply_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        -- Files already checked.
        CREATE TABLE IF NOT EXISTS file_cache (
            path        TEXT PRIMARY KEY,
            sha256      TEXT NOT NULL,
            size        INTEGER NOT NULL,
            mtime       INTEGER NOT NULL,
            vt_verdict  INTEGER,
            vt_checked  INTEGER
        );

        -- Addresses seen before.
        CREATE TABLE IF NOT EXISTS known_ips (
            ip          TEXT PRIMARY KEY,
            first_seen  INTEGER NOT NULL,
            last_seen   INTEGER NOT NULL,
            label       TEXT,
            trusted     INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS scan_history (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     INTEGER NOT NULL,
            files_checked INTEGER,
            issues_found  INTEGER
        );

        CREATE TABLE IF NOT EXISTS quarantine (
            id              TEXT PRIMARY KEY,
            original_path   TEXT NOT NULL,
            quarantine_path TEXT NOT NULL,
            sha256          TEXT NOT NULL,
            quarantined_at  INTEGER NOT NULL,
            reason          TEXT,
            -- Needed to restore the file with the permissions it had.
            original_mode   INTEGER NOT NULL DEFAULT 384
        );

        -- Hashes the user has vouched for, keyed by hash and never by path.
        CREATE TABLE IF NOT EXISTS allowlist (
            sha256   TEXT PRIMARY KEY,
            label    TEXT,
            added_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS integrity_baseline (
            path       TEXT PRIMARY KEY,
            sha256     TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS autostart_baseline (
            key        TEXT PRIMARY KEY,
            source     TEXT NOT NULL,
            name       TEXT,
            command    TEXT,
            first_seen INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS action_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  INTEGER NOT NULL,
            action     TEXT NOT NULL,
            target     TEXT NOT NULL,
            reason     TEXT,
            reversible INTEGER NOT NULL DEFAULT 0,
            reverted   INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS action_log_time ON action_log (timestamp DESC);
        CREATE INDEX IF NOT EXISTS scan_history_time ON scan_history (timestamp DESC);
        "#,
    )
    .map_err(wrap)?;

    conn.execute(
        "INSERT INTO meta (key, value) VALUES ('schema_version', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![SCHEMA_VERSION.to_string()],
    )
    .map_err(wrap)?;

    Ok(())
}

// --- file cache -----------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CachedFile {
    pub sha256: String,
    /// Engines that called it malicious, or `None` if never asked.
    pub vt_verdict: Option<i64>,
    pub vt_checked: Option<i64>,
}

/// The cached record for a file, if path, size and mtime all still match.
pub fn cached_file(conn: &Connection, path: &str, size: u64, mtime: i64) -> Option<CachedFile> {
    conn.query_row(
        "SELECT sha256, vt_verdict, vt_checked FROM file_cache
         WHERE path = ?1 AND size = ?2 AND mtime = ?3",
        params![path, size as i64, mtime],
        |row| {
            Ok(CachedFile {
                sha256: row.get(0)?,
                vt_verdict: row.get(1)?,
                vt_checked: row.get(2)?,
            })
        },
    )
    .optional()
    .ok()
    .flatten()
}

/// Records a freshly computed hash, dropping any verdict about the old bytes.
pub fn put_file(conn: &Connection, path: &str, sha256: &str, size: u64, mtime: i64) -> Result<(), String> {
    conn.execute(
        "INSERT INTO file_cache (path, sha256, size, mtime, vt_verdict, vt_checked)
         VALUES (?1, ?2, ?3, ?4, NULL, NULL)
         ON CONFLICT(path) DO UPDATE SET
             sha256 = excluded.sha256,
             size = excluded.size,
             mtime = excluded.mtime,
             vt_verdict = CASE WHEN file_cache.sha256 = excluded.sha256
                               THEN file_cache.vt_verdict ELSE NULL END,
             vt_checked = CASE WHEN file_cache.sha256 = excluded.sha256
                               THEN file_cache.vt_checked ELSE NULL END",
        params![path, sha256, size as i64, mtime],
    )
    .map_err(wrap)?;
    Ok(())
}

/// Stores what VirusTotal said, for every path holding this hash.
///
/// Keyed by hash, so the same installer in two folders costs one lookup.
pub fn put_verdict(conn: &Connection, sha256: &str, malicious: i64) -> Result<(), String> {
    conn.execute(
        "UPDATE file_cache SET vt_verdict = ?2, vt_checked = ?3 WHERE sha256 = ?1",
        params![sha256, malicious, now()],
    )
    .map_err(wrap)?;
    Ok(())
}

/// A verdict for this hash that is recent enough to reuse.
pub fn verdict_for_hash(conn: &Connection, sha256: &str, max_age_secs: i64) -> Option<i64> {
    conn.query_row(
        "SELECT vt_verdict FROM file_cache
         WHERE sha256 = ?1 AND vt_verdict IS NOT NULL AND vt_checked >= ?2
         LIMIT 1",
        params![sha256, now() - max_age_secs],
        |row| row.get::<_, Option<i64>>(0),
    )
    .optional()
    .ok()
    .flatten()
    .flatten()
}

/// Drops a path from the cache.
pub fn forget_file(conn: &Connection, path: &str) -> Result<(), String> {
    conn.execute("DELETE FROM file_cache WHERE path = ?1", params![path]).map_err(wrap)?;
    Ok(())
}

pub fn cached_file_count(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM file_cache", [], |r| r.get(0)).unwrap_or(0)
}

// --- known addresses ------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct IpRecord {
    pub ip: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub label: Option<String>,
    pub trusted: bool,
    /// True when this call created the row.
    #[serde(skip)]
    pub is_new: bool,
}

/// Records that an address was seen, and says whether it was new.
pub fn observe_ip(conn: &Connection, ip: &str) -> Result<IpRecord, String> {
    let existing: Option<(i64, i64, Option<String>, i64)> = conn
        .query_row(
            "SELECT first_seen, last_seen, label, trusted FROM known_ips WHERE ip = ?1",
            params![ip],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(wrap)?;

    let stamp = now();
    match existing {
        Some((first_seen, _, label, trusted)) => {
            conn.execute("UPDATE known_ips SET last_seen = ?2 WHERE ip = ?1", params![ip, stamp])
                .map_err(wrap)?;
            Ok(IpRecord { ip: ip.to_string(), first_seen, last_seen: stamp, label, trusted: trusted != 0, is_new: false })
        }
        None => {
            conn.execute(
                "INSERT INTO known_ips (ip, first_seen, last_seen, trusted) VALUES (?1, ?2, ?2, 0)",
                params![ip, stamp],
            )
            .map_err(wrap)?;
            Ok(IpRecord { ip: ip.to_string(), first_seen: stamp, last_seen: stamp, label: None, trusted: false, is_new: true })
        }
    }
}

/// Marks an address as trusted, or takes it back.
pub fn set_ip_trust(conn: &Connection, ip: &str, trusted: bool, label: Option<&str>) -> Result<(), String> {
    let stamp = now();
    conn.execute(
        "INSERT INTO known_ips (ip, first_seen, last_seen, label, trusted)
         VALUES (?1, ?2, ?2, ?3, ?4)
         ON CONFLICT(ip) DO UPDATE SET
             trusted = excluded.trusted,
             label = COALESCE(excluded.label, known_ips.label),
             last_seen = excluded.last_seen",
        params![ip, stamp, label, if trusted { 1 } else { 0 }],
    )
    .map_err(wrap)?;
    Ok(())
}

pub fn list_trusted_ips(conn: &Connection) -> Result<Vec<IpRecord>, String> {
    let mut stmt = conn
        .prepare("SELECT ip, first_seen, last_seen, label, trusted FROM known_ips WHERE trusted = 1 ORDER BY last_seen DESC")
        .map_err(wrap)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(IpRecord {
                ip: row.get(0)?,
                first_seen: row.get(1)?,
                last_seen: row.get(2)?,
                label: row.get(3)?,
                trusted: row.get::<_, i64>(4)? != 0,
                is_new: false,
            })
        })
        .map_err(wrap)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(wrap)
}

// --- scan history ---------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ScanRecord {
    pub timestamp: i64,
    pub files_checked: i64,
    pub issues_found: i64,
}

pub fn record_scan(conn: &Connection, files_checked: u32, issues_found: usize) -> Result<(), String> {
    conn.execute(
        "INSERT INTO scan_history (timestamp, files_checked, issues_found) VALUES (?1, ?2, ?3)",
        params![now(), files_checked as i64, issues_found as i64],
    )
    .map_err(wrap)?;
    Ok(())
}

pub fn recent_scans(conn: &Connection, limit: u32) -> Result<Vec<ScanRecord>, String> {
    let mut stmt = conn
        .prepare("SELECT timestamp, files_checked, issues_found FROM scan_history ORDER BY timestamp DESC LIMIT ?1")
        .map_err(wrap)?;
    let rows = stmt
        .query_map(params![limit], |row| {
            Ok(ScanRecord {
                timestamp: row.get(0)?,
                files_checked: row.get(1).unwrap_or(0),
                issues_found: row.get(2).unwrap_or(0),
            })
        })
        .map_err(wrap)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(wrap)
}

// --- quarantine -----------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: String,
    pub quarantine_path: String,
    pub sha256: String,
    pub quarantined_at: i64,
    pub reason: Option<String>,
    pub original_mode: u32,
}

pub fn add_quarantine(conn: &Connection, entry: &QuarantineEntry) -> Result<(), String> {
    conn.execute(
        "INSERT INTO quarantine (id, original_path, quarantine_path, sha256, quarantined_at, reason, original_mode)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            entry.id,
            entry.original_path,
            entry.quarantine_path,
            entry.sha256,
            entry.quarantined_at,
            entry.reason,
            entry.original_mode as i64
        ],
    )
    .map_err(wrap)?;
    Ok(())
}

pub fn list_quarantine(conn: &Connection) -> Result<Vec<QuarantineEntry>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT id, original_path, quarantine_path, sha256, quarantined_at, reason, original_mode
             FROM quarantine ORDER BY quarantined_at DESC",
        )
        .map_err(wrap)?;
    let rows = stmt.query_map([], row_to_quarantine).map_err(wrap)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(wrap)
}

pub fn get_quarantine(conn: &Connection, id: &str) -> Result<Option<QuarantineEntry>, String> {
    conn.query_row(
        "SELECT id, original_path, quarantine_path, sha256, quarantined_at, reason, original_mode
         FROM quarantine WHERE id = ?1",
        params![id],
        row_to_quarantine,
    )
    .optional()
    .map_err(wrap)
}

fn row_to_quarantine(row: &rusqlite::Row) -> rusqlite::Result<QuarantineEntry> {
    Ok(QuarantineEntry {
        id: row.get(0)?,
        original_path: row.get(1)?,
        quarantine_path: row.get(2)?,
        sha256: row.get(3)?,
        quarantined_at: row.get(4)?,
        reason: row.get(5)?,
        original_mode: row.get::<_, i64>(6)? as u32,
    })
}

pub fn remove_quarantine(conn: &Connection, id: &str) -> Result<(), String> {
    conn.execute("DELETE FROM quarantine WHERE id = ?1", params![id]).map_err(wrap)?;
    Ok(())
}

// --- allowlist ------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct AllowEntry {
    pub sha256: String,
    pub label: Option<String>,
    pub added_at: i64,
}

pub fn allow_hash(conn: &Connection, sha256: &str, label: Option<&str>) -> Result<(), String> {
    conn.execute(
        "INSERT INTO allowlist (sha256, label, added_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(sha256) DO UPDATE SET label = COALESCE(excluded.label, allowlist.label)",
        params![sha256, label, now()],
    )
    .map_err(wrap)?;
    Ok(())
}

pub fn is_allowed(conn: &Connection, sha256: &str) -> bool {
    conn.query_row("SELECT 1 FROM allowlist WHERE sha256 = ?1", params![sha256], |_| Ok(()))
        .optional()
        .ok()
        .flatten()
        .is_some()
}

pub fn list_allowed(conn: &Connection) -> Result<Vec<AllowEntry>, String> {
    let mut stmt = conn
        .prepare("SELECT sha256, label, added_at FROM allowlist ORDER BY added_at DESC")
        .map_err(wrap)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(AllowEntry { sha256: row.get(0)?, label: row.get(1)?, added_at: row.get(2)? })
        })
        .map_err(wrap)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(wrap)
}

pub fn remove_allowed(conn: &Connection, sha256: &str) -> Result<(), String> {
    conn.execute("DELETE FROM allowlist WHERE sha256 = ?1", params![sha256]).map_err(wrap)?;
    Ok(())
}

// --- integrity baseline ---------------------------------------------------

pub fn baseline_hash(conn: &Connection, path: &str) -> Option<String> {
    conn.query_row("SELECT sha256 FROM integrity_baseline WHERE path = ?1", params![path], |r| r.get(0))
        .optional()
        .ok()
        .flatten()
}

pub fn set_baseline(conn: &Connection, path: &str, sha256: &str) -> Result<(), String> {
    conn.execute(
        "INSERT INTO integrity_baseline (path, sha256, updated_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(path) DO UPDATE SET sha256 = excluded.sha256, updated_at = excluded.updated_at",
        params![path, sha256, now()],
    )
    .map_err(wrap)?;
    Ok(())
}

// --- autostart baseline ---------------------------------------------------

pub fn autostart_is_known(conn: &Connection, key: &str) -> bool {
    conn.query_row("SELECT 1 FROM autostart_baseline WHERE key = ?1", params![key], |_| Ok(()))
        .optional()
        .ok()
        .flatten()
        .is_some()
}

pub fn autostart_baseline_is_empty(conn: &Connection) -> bool {
    conn.query_row("SELECT COUNT(*) FROM autostart_baseline", [], |r| r.get::<_, i64>(0)).unwrap_or(0) == 0
}

pub fn remember_autostart(
    conn: &Connection,
    key: &str,
    source: &str,
    name: &str,
    command: &str,
) -> Result<(), String> {
    conn.execute(
        "INSERT INTO autostart_baseline (key, source, name, command, first_seen)
         VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(key) DO NOTHING",
        params![key, source, name, command, now()],
    )
    .map_err(wrap)?;
    Ok(())
}

// --- action log -----------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ActionRecord {
    pub id: i64,
    pub timestamp: i64,
    pub action: String,
    pub target: String,
    pub reason: Option<String>,
    pub reversible: bool,
    pub reverted: bool,
}

pub fn record_action(
    conn: &Connection,
    action: &str,
    target: &str,
    reason: Option<&str>,
    reversible: bool,
) -> Result<i64, String> {
    conn.execute(
        "INSERT INTO action_log (timestamp, action, target, reason, reversible, reverted)
         VALUES (?1, ?2, ?3, ?4, ?5, 0)",
        params![now(), action, target, reason, if reversible { 1 } else { 0 }],
    )
    .map_err(wrap)?;
    Ok(conn.last_insert_rowid())
}

pub fn list_actions(conn: &Connection, limit: u32) -> Result<Vec<ActionRecord>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT id, timestamp, action, target, reason, reversible, reverted
             FROM action_log ORDER BY timestamp DESC, id DESC LIMIT ?1",
        )
        .map_err(wrap)?;
    let rows = stmt
        .query_map(params![limit], |row| {
            Ok(ActionRecord {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                action: row.get(2)?,
                target: row.get(3)?,
                reason: row.get(4)?,
                reversible: row.get::<_, i64>(5)? != 0,
                reverted: row.get::<_, i64>(6)? != 0,
            })
        })
        .map_err(wrap)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(wrap)
}

pub fn get_action(conn: &Connection, id: i64) -> Result<Option<ActionRecord>, String> {
    let actions = list_actions(conn, 100_000)?;
    Ok(actions.into_iter().find(|a| a.id == id))
}

pub fn mark_action_reverted(conn: &Connection, id: i64) -> Result<(), String> {
    conn.execute("UPDATE action_log SET reverted = 1 WHERE id = ?1", params![id]).map_err(wrap)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_is_cached_only_while_size_and_mtime_hold_still() {
        let conn = open_memory();
        put_file(&conn, "/tmp/a.bin", "hash-1", 100, 1_000).unwrap();

        assert!(cached_file(&conn, "/tmp/a.bin", 100, 1_000).is_some());
        // Touched: same size, later mtime.
        assert!(cached_file(&conn, "/tmp/a.bin", 100, 1_001).is_none());
        // Grown: same mtime, different size.
        assert!(cached_file(&conn, "/tmp/a.bin", 101, 1_000).is_none());
        // Never seen.
        assert!(cached_file(&conn, "/tmp/b.bin", 100, 1_000).is_none());
    }

    #[test]
    fn a_changed_file_loses_the_verdict_that_described_its_old_contents() {
        let conn = open_memory();
        put_file(&conn, "/tmp/a.bin", "hash-1", 100, 1_000).unwrap();
        put_verdict(&conn, "hash-1", 12).unwrap();
        assert_eq!(cached_file(&conn, "/tmp/a.bin", 100, 1_000).unwrap().vt_verdict, Some(12));

        // Same path, new contents.
        put_file(&conn, "/tmp/a.bin", "hash-2", 140, 2_000).unwrap();
        assert_eq!(cached_file(&conn, "/tmp/a.bin", 140, 2_000).unwrap().vt_verdict, None);
    }

    #[test]
    fn rewriting_identical_contents_keeps_the_verdict() {
        let conn = open_memory();
        put_file(&conn, "/tmp/a.bin", "hash-1", 100, 1_000).unwrap();
        put_verdict(&conn, "hash-1", 3).unwrap();

        // Copied back over itself: new mtime, same bytes. Asking VirusTotal
        // again about a hash it just answered for wastes the whole budget.
        put_file(&conn, "/tmp/a.bin", "hash-1", 100, 5_000).unwrap();
        assert_eq!(cached_file(&conn, "/tmp/a.bin", 100, 5_000).unwrap().vt_verdict, Some(3));
    }

    #[test]
    fn the_same_hash_under_two_names_needs_one_lookup() {
        let conn = open_memory();
        put_file(&conn, "/tmp/one.bin", "shared", 10, 1).unwrap();
        put_file(&conn, "/tmp/two.bin", "shared", 10, 2).unwrap();
        put_verdict(&conn, "shared", 7).unwrap();

        assert_eq!(verdict_for_hash(&conn, "shared", 86_400), Some(7));
        assert_eq!(cached_file(&conn, "/tmp/two.bin", 10, 2).unwrap().vt_verdict, Some(7));
    }

    #[test]
    fn a_stale_verdict_is_not_reused() {
        let conn = open_memory();
        put_file(&conn, "/tmp/a.bin", "hash-1", 10, 1).unwrap();
        put_verdict(&conn, "hash-1", 1).unwrap();
        // Anything checked less than zero seconds ago: nothing qualifies.
        assert_eq!(verdict_for_hash(&conn, "hash-1", -1), None);
    }

    #[test]
    fn an_address_is_new_exactly_once() {
        let conn = open_memory();
        assert!(observe_ip(&conn, "185.220.101.7").unwrap().is_new);
        assert!(!observe_ip(&conn, "185.220.101.7").unwrap().is_new);
    }

    #[test]
    fn trust_survives_being_seen_again() {
        let conn = open_memory();
        observe_ip(&conn, "1.1.1.1").unwrap();
        set_ip_trust(&conn, "1.1.1.1", true, Some("resolver")).unwrap();

        let seen = observe_ip(&conn, "1.1.1.1").unwrap();
        assert!(seen.trusted);
        assert_eq!(seen.label.as_deref(), Some("resolver"));
        assert_eq!(list_trusted_ips(&conn).unwrap().len(), 1);
    }

    #[test]
    fn the_allowlist_holds_hashes_and_forgets_them_on_request() {
        let conn = open_memory();
        assert!(!is_allowed(&conn, "abc"));
        allow_hash(&conn, "abc", Some("my own build")).unwrap();
        assert!(is_allowed(&conn, "abc"));
        remove_allowed(&conn, "abc").unwrap();
        assert!(!is_allowed(&conn, "abc"));
    }

    #[test]
    fn actions_are_logged_newest_first_and_can_be_marked_undone() {
        let conn = open_memory();
        let first = record_action(&conn, "block_ip", "185.220.101.7", Some("unknown"), true).unwrap();
        record_action(&conn, "quarantine", "/tmp/x", None, true).unwrap();

        let list = list_actions(&conn, 10).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].action, "quarantine");

        mark_action_reverted(&conn, first).unwrap();
        assert!(get_action(&conn, first).unwrap().unwrap().reverted);
    }

    #[test]
    fn the_autostart_baseline_starts_empty_and_remembers_what_it_was_told() {
        let conn = open_memory();
        assert!(autostart_baseline_is_empty(&conn));
        remember_autostart(&conn, "xdg:steam.desktop", "xdg", "Steam", "/usr/bin/steam").unwrap();
        assert!(!autostart_baseline_is_empty(&conn));
        assert!(autostart_is_known(&conn, "xdg:steam.desktop"));
        assert!(!autostart_is_known(&conn, "xdg:other.desktop"));
    }

    #[test]
    fn the_integrity_baseline_is_set_once_and_then_updated_on_demand() {
        let conn = open_memory();
        assert!(baseline_hash(&conn, "/etc/hosts").is_none());
        set_baseline(&conn, "/etc/hosts", "aaa").unwrap();
        assert_eq!(baseline_hash(&conn, "/etc/hosts").as_deref(), Some("aaa"));
        set_baseline(&conn, "/etc/hosts", "bbb").unwrap();
        assert_eq!(baseline_hash(&conn, "/etc/hosts").as_deref(), Some("bbb"));
    }
}
