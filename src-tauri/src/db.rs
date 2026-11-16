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
const SCHEMA_VERSION: i64 = 5;

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
    // The window, a scheduled scan and the decoy may each hold the file for a
    // moment; waiting beats failing.
    conn.busy_timeout(std::time::Duration::from_secs(5)).map_err(wrap)?;
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

        -- What each in-scope packaged file hashed to, keyed by size and change time.
        CREATE TABLE IF NOT EXISTS package_cache (
            path    TEXT PRIMARY KEY,
            size    INTEGER NOT NULL,
            ctime   INTEGER NOT NULL,
            digest  TEXT NOT NULL
        );

        -- Packaged files that differ from their package on purpose.
        CREATE TABLE IF NOT EXISTS package_accepted (
            path        TEXT PRIMARY KEY,
            digest      TEXT NOT NULL,
            accepted_at INTEGER NOT NULL
        );

        -- What each check took as normal, by check: kernel modules, browser
        -- extensions, accounts, files in watched folders.
        CREATE TABLE IF NOT EXISTS baseline (
            kind       TEXT NOT NULL,
            key        TEXT NOT NULL,
            value      TEXT NOT NULL,
            first_seen INTEGER NOT NULL,
            PRIMARY KEY (kind, key)
        );

        -- Every problem a scan has reported, by what stays the same about it.
        CREATE TABLE IF NOT EXISTS issue_history (
            fingerprint TEXT PRIMARY KEY,
            kind        TEXT NOT NULL,
            first_seen  INTEGER NOT NULL,
            last_seen   INTEGER NOT NULL,
            times_seen  INTEGER NOT NULL,
            set_aside   INTEGER
        );

        -- What each recent scan reported, for reports and comparisons.
        CREATE TABLE IF NOT EXISTS scan_issues (
            scan_id     INTEGER NOT NULL,
            fingerprint TEXT NOT NULL,
            kind        TEXT NOT NULL,
            severity    TEXT NOT NULL,
            title       TEXT NOT NULL,
            location    TEXT NOT NULL,
            detail      TEXT,
            first_seen  INTEGER NOT NULL,
            times_seen  INTEGER NOT NULL,
            set_aside   INTEGER NOT NULL
        );

        -- Addresses in the firewall's sets, and when an automatic block lifts.
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip         TEXT PRIMARY KEY,
            blocked_at INTEGER NOT NULL,
            expires_at INTEGER
        );

        -- What the machine held at the last scan, by kind: files, startup
        -- entries, accounts, packages.
        CREATE TABLE IF NOT EXISTS machine_state (
            kind  TEXT NOT NULL,
            key   TEXT NOT NULL,
            value TEXT NOT NULL,
            PRIMARY KEY (kind, key)
        );

        -- How it differed from the scan before, kept for the same scans as
        -- their issues.
        CREATE TABLE IF NOT EXISTS machine_changes (
            scan_id INTEGER NOT NULL,
            kind    TEXT NOT NULL,
            key     TEXT NOT NULL,
            before  TEXT,
            after   TEXT
        );

        -- Who connected to the decoy port, and when.
        CREATE TABLE IF NOT EXISTS decoy_hits (
            at   INTEGER NOT NULL,
            ip   TEXT NOT NULL,
            port INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS decoy_hits_time ON decoy_hits (at);
        CREATE INDEX IF NOT EXISTS scan_issues_scan ON scan_issues (scan_id);
        CREATE INDEX IF NOT EXISTS machine_changes_scan ON machine_changes (scan_id);
        CREATE INDEX IF NOT EXISTS action_log_time ON action_log (timestamp DESC);
        CREATE INDEX IF NOT EXISTS scan_history_time ON scan_history (timestamp DESC);
        "#,
    )
    .map_err(wrap)?;

    // Version 2: what the rules found in a file, and which rules found it.
    add_column(conn, "file_cache", "content", "TEXT")?;
    add_column(conn, "file_cache", "content_version", "TEXT")?;

    conn.execute(
        "INSERT INTO meta (key, value) VALUES ('schema_version', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![SCHEMA_VERSION.to_string()],
    )
    .map_err(wrap)?;

    Ok(())
}

/// Adds a column to a table that predates it.
fn add_column(conn: &Connection, table: &str, column: &str, kind: &str) -> Result<(), String> {
    let exists = conn
        .prepare(&format!("SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1"))
        .and_then(|mut stmt| stmt.exists(params![column]))
        .map_err(wrap)?;
    if !exists {
        conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {kind}")).map_err(wrap)?;
    }
    Ok(())
}

// --- file cache -----------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CachedFile {
    pub sha256: String,
    /// Engines that called it malicious, or `None` if never asked.
    pub vt_verdict: Option<i64>,
    pub vt_checked: Option<i64>,
    /// What the rules found, as JSON, and the rules version that found it.
    pub content: Option<String>,
    pub content_version: Option<String>,
}

/// The cached record for a file, if path, size and mtime all still match.
pub fn cached_file(conn: &Connection, path: &str, size: u64, mtime: i64) -> Option<CachedFile> {
    conn.query_row(
        "SELECT sha256, vt_verdict, vt_checked, content, content_version FROM file_cache
         WHERE path = ?1 AND size = ?2 AND mtime = ?3",
        params![path, size as i64, mtime],
        |row| {
            Ok(CachedFile {
                sha256: row.get(0)?,
                vt_verdict: row.get(1)?,
                vt_checked: row.get(2)?,
                content: row.get(3)?,
                content_version: row.get(4)?,
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
                               THEN file_cache.vt_checked ELSE NULL END,
             content = CASE WHEN file_cache.sha256 = excluded.sha256
                            THEN file_cache.content ELSE NULL END,
             content_version = CASE WHEN file_cache.sha256 = excluded.sha256
                                    THEN file_cache.content_version ELSE NULL END",
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

/// Stores what the rules found in a file.
pub fn put_content(conn: &Connection, path: &str, version: &str, content: &str) -> Result<(), String> {
    conn.execute(
        "UPDATE file_cache SET content = ?2, content_version = ?3 WHERE path = ?1",
        params![path, content, version],
    )
    .map_err(wrap)?;
    Ok(())
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

pub fn ip_trusted(conn: &Connection, ip: &str) -> bool {
    conn.query_row("SELECT 1 FROM known_ips WHERE ip = ?1 AND trusted = 1", params![ip], |_| Ok(()))
        .optional()
        .ok()
        .flatten()
        .is_some()
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

/// Scans whose issues are kept; older ones keep only their counts.
const SCANS_KEPT: i64 = 100;

#[derive(Debug, Clone, Serialize)]
pub struct ScanRecord {
    pub id: i64,
    pub timestamp: i64,
    pub files_checked: i64,
    pub issues_found: i64,
}

/// Records a scan and says which row it got.
pub fn record_scan(conn: &Connection, files_checked: u32, issues_found: usize) -> Result<i64, String> {
    conn.execute(
        "INSERT INTO scan_history (timestamp, files_checked, issues_found) VALUES (?1, ?2, ?3)",
        params![now(), files_checked as i64, issues_found as i64],
    )
    .map_err(wrap)?;
    Ok(conn.last_insert_rowid())
}

fn row_to_scan(row: &rusqlite::Row) -> rusqlite::Result<ScanRecord> {
    Ok(ScanRecord {
        id: row.get(0)?,
        timestamp: row.get(1)?,
        files_checked: row.get(2).unwrap_or(0),
        issues_found: row.get(3).unwrap_or(0),
    })
}

pub fn recent_scans(conn: &Connection, limit: u32) -> Result<Vec<ScanRecord>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT id, timestamp, files_checked, issues_found FROM scan_history
             ORDER BY timestamp DESC, id DESC LIMIT ?1",
        )
        .map_err(wrap)?;
    let rows = stmt.query_map(params![limit], row_to_scan).map_err(wrap)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(wrap)
}

pub fn get_scan(conn: &Connection, id: i64) -> Result<Option<ScanRecord>, String> {
    conn.query_row(
        "SELECT id, timestamp, files_checked, issues_found FROM scan_history WHERE id = ?1",
        params![id],
        row_to_scan,
    )
    .optional()
    .map_err(wrap)
}

/// An issue as a past scan reported it.
#[derive(Debug, Clone, Serialize)]
pub struct StoredIssue {
    pub fingerprint: String,
    pub kind: String,
    pub severity: String,
    pub title: String,
    pub location: String,
    pub detail: Option<String>,
    pub first_seen: i64,
    pub times_seen: u32,
    pub set_aside: bool,
}

/// Keeps what a scan reported, and forgets the issues of scans past the limit.
pub fn record_scan_issues(conn: &Connection, scan_id: i64, issues: &[StoredIssue]) -> Result<(), String> {
    let tx = conn.unchecked_transaction().map_err(wrap)?;
    {
        let mut stmt = tx
            .prepare(
                "INSERT INTO scan_issues (scan_id, fingerprint, kind, severity, title, location, detail,
                 first_seen, times_seen, set_aside) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )
            .map_err(wrap)?;
        for issue in issues {
            stmt.execute(params![
                scan_id,
                issue.fingerprint,
                issue.kind,
                issue.severity,
                issue.title,
                issue.location,
                issue.detail,
                issue.first_seen,
                issue.times_seen,
                issue.set_aside as i64
            ])
            .map_err(wrap)?;
        }
    }
    for table in ["scan_issues", "machine_changes"] {
        tx.execute(
            &format!(
                "DELETE FROM {table} WHERE scan_id NOT IN
                 (SELECT id FROM scan_history ORDER BY timestamp DESC, id DESC LIMIT ?1)"
            ),
            params![SCANS_KEPT],
        )
        .map_err(wrap)?;
    }
    tx.commit().map_err(wrap)
}

// --- the machine between scans --------------------------------------------

/// What the last scan recorded for a kind, or `None` before the first.
pub fn machine_state(conn: &Connection, kind: &str) -> Result<Option<std::collections::BTreeMap<String, String>>, String> {
    let started = conn
        .query_row("SELECT 1 FROM meta WHERE key = ?1", params![format!("state:{kind}")], |_| Ok(()))
        .optional()
        .map_err(wrap)?
        .is_some();
    if !started {
        return Ok(None);
    }
    let mut stmt = conn.prepare("SELECT key, value FROM machine_state WHERE kind = ?1").map_err(wrap)?;
    let rows = stmt.query_map(params![kind], |row| Ok((row.get(0)?, row.get(1)?))).map_err(wrap)?;
    rows.collect::<Result<_, _>>().map(Some).map_err(wrap)
}

/// One key that appeared, went or changed.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MachineChange {
    pub kind: String,
    pub key: String,
    /// `None` when it appeared.
    pub before: Option<String>,
    /// `None` when it went.
    pub after: Option<String>,
}

/// Replaces what is recorded for a kind and keeps how it changed.
pub fn put_machine_state(
    conn: &Connection,
    scan_id: i64,
    kind: &str,
    now: &std::collections::BTreeMap<String, String>,
    changes: &[MachineChange],
) -> Result<(), String> {
    let tx = conn.unchecked_transaction().map_err(wrap)?;
    tx.execute("DELETE FROM machine_state WHERE kind = ?1", params![kind]).map_err(wrap)?;
    {
        let mut insert = tx
            .prepare("INSERT INTO machine_state (kind, key, value) VALUES (?1, ?2, ?3)")
            .map_err(wrap)?;
        for (key, value) in now {
            insert.execute(params![kind, key, value]).map_err(wrap)?;
        }
        let mut change = tx
            .prepare("INSERT INTO machine_changes (scan_id, kind, key, before, after) VALUES (?1, ?2, ?3, ?4, ?5)")
            .map_err(wrap)?;
        for c in changes {
            change.execute(params![scan_id, c.kind, c.key, c.before, c.after]).map_err(wrap)?;
        }
    }
    tx.execute(
        "INSERT INTO meta (key, value) VALUES (?1, '1') ON CONFLICT(key) DO NOTHING",
        params![format!("state:{kind}")],
    )
    .map_err(wrap)?;
    tx.commit().map_err(wrap)
}

/// Every change recorded by the scans after `older` up to `newer`, oldest first.
pub fn machine_changes(conn: &Connection, older: i64, newer: i64) -> Result<Vec<MachineChange>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT kind, key, before, after FROM machine_changes
             WHERE scan_id > ?1 AND scan_id <= ?2 ORDER BY scan_id, rowid",
        )
        .map_err(wrap)?;
    let rows = stmt
        .query_map(params![older, newer], |row| {
            Ok(MachineChange { kind: row.get(0)?, key: row.get(1)?, before: row.get(2)?, after: row.get(3)? })
        })
        .map_err(wrap)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(wrap)
}

pub fn scan_issues(conn: &Connection, scan_id: i64) -> Result<Vec<StoredIssue>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT fingerprint, kind, severity, title, location, detail, first_seen, times_seen, set_aside
             FROM scan_issues WHERE scan_id = ?1 ORDER BY rowid",
        )
        .map_err(wrap)?;
    let rows = stmt
        .query_map(params![scan_id], |row| {
            Ok(StoredIssue {
                fingerprint: row.get(0)?,
                kind: row.get(1)?,
                severity: row.get(2)?,
                title: row.get(3)?,
                location: row.get(4)?,
                detail: row.get(5)?,
                first_seen: row.get(6)?,
                times_seen: row.get::<_, i64>(7)? as u32,
                set_aside: row.get::<_, i64>(8)? != 0,
            })
        })
        .map_err(wrap)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(wrap)
}

// --- issue history --------------------------------------------------------

/// What the history knew about an issue before this sighting.
#[derive(Debug, Clone, PartialEq)]
pub struct Sighting {
    pub first_seen: i64,
    pub times_seen: u32,
    pub set_aside: bool,
}

/// Counts one more sighting of an issue and returns its history.
pub fn observe_issue(conn: &Connection, fingerprint: &str, kind: &str, at: i64) -> Result<Sighting, String> {
    conn.execute(
        "INSERT INTO issue_history (fingerprint, kind, first_seen, last_seen, times_seen)
         VALUES (?1, ?2, ?3, ?3, 1)
         ON CONFLICT(fingerprint) DO UPDATE SET last_seen = excluded.last_seen,
             times_seen = issue_history.times_seen + 1",
        params![fingerprint, kind, at],
    )
    .map_err(wrap)?;
    issue_sighting(conn, fingerprint)?.ok_or_else(|| "The issue history lost a row.".to_string())
}

pub fn issue_sighting(conn: &Connection, fingerprint: &str) -> Result<Option<Sighting>, String> {
    conn.query_row(
        "SELECT first_seen, times_seen, set_aside FROM issue_history WHERE fingerprint = ?1",
        params![fingerprint],
        |row| {
            Ok(Sighting {
                first_seen: row.get(0)?,
                times_seen: row.get::<_, i64>(1)? as u32,
                set_aside: row.get::<_, Option<i64>>(2)?.is_some(),
            })
        },
    )
    .optional()
    .map_err(wrap)
}

/// Sets an issue aside, or brings it back.
pub fn set_issue_aside(conn: &Connection, fingerprint: &str, kind: &str, aside: bool) -> Result<(), String> {
    let stamp = now();
    conn.execute(
        "INSERT INTO issue_history (fingerprint, kind, first_seen, last_seen, times_seen, set_aside)
         VALUES (?1, ?2, ?3, ?3, 1, ?4)
         ON CONFLICT(fingerprint) DO UPDATE SET set_aside = excluded.set_aside",
        params![fingerprint, kind, stamp, if aside { Some(stamp) } else { None }],
    )
    .map_err(wrap)?;
    Ok(())
}

// --- the decoy port -------------------------------------------------------

/// Hits kept; older ones go first.
const DECOY_KEPT: i64 = 10_000;

pub fn record_decoy_hit(conn: &Connection, ip: &str, port: u16) -> Result<(), String> {
    conn.execute("INSERT INTO decoy_hits (at, ip, port) VALUES (?1, ?2, ?3)", params![now(), ip, port as i64])
        .map_err(wrap)?;
    conn.execute(
        "DELETE FROM decoy_hits WHERE rowid <= (SELECT MAX(rowid) FROM decoy_hits) - ?1",
        params![DECOY_KEPT],
    )
    .map_err(wrap)?;
    Ok(())
}

/// Per address since a moment: how many times, the last time, the last port.
pub fn decoy_hits_since(conn: &Connection, since: i64) -> Result<Vec<(String, u32, i64, u16)>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT ip, COUNT(*), MAX(at), (SELECT port FROM decoy_hits d WHERE d.ip = h.ip ORDER BY at DESC LIMIT 1)
             FROM decoy_hits h WHERE at >= ?1 GROUP BY ip ORDER BY MAX(at) DESC",
        )
        .map_err(wrap)?;
    let rows = stmt
        .query_map(params![since], |row| {
            Ok((row.get(0)?, row.get::<_, i64>(1)? as u32, row.get(2)?, row.get::<_, i64>(3)? as u16))
        })
        .map_err(wrap)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(wrap)
}

// --- blocked addresses ----------------------------------------------------

/// Notes that an address went into the firewall, until `expires_at` or for good.
pub fn put_block(conn: &Connection, ip: &str, expires_at: Option<i64>) -> Result<(), String> {
    conn.execute(
        "INSERT INTO blocked_ips (ip, blocked_at, expires_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(ip) DO UPDATE SET blocked_at = excluded.blocked_at, expires_at = excluded.expires_at",
        params![ip, now(), expires_at],
    )
    .map_err(wrap)?;
    Ok(())
}

pub fn remove_block(conn: &Connection, ip: &str) -> Result<(), String> {
    conn.execute("DELETE FROM blocked_ips WHERE ip = ?1", params![ip]).map_err(wrap)?;
    Ok(())
}

/// When the block on an address lifts: `Some(None)` for never, `None` for no block.
pub fn block_expiry(conn: &Connection, ip: &str) -> Option<Option<i64>> {
    conn.query_row("SELECT expires_at FROM blocked_ips WHERE ip = ?1", params![ip], |r| r.get(0))
        .optional()
        .ok()
        .flatten()
}

/// Whether an address is blocked at this moment.
#[cfg(test)]
fn is_blocked(conn: &Connection, ip: &str, at: i64) -> bool {
    match block_expiry(conn, ip) {
        Some(None) => true,
        Some(Some(expires)) => expires > at,
        None => false,
    }
}

/// Automatic blocks whose time is up.
pub fn expired_blocks(conn: &Connection, at: i64) -> Result<Vec<String>, String> {
    let mut stmt = conn
        .prepare("SELECT ip FROM blocked_ips WHERE expires_at IS NOT NULL AND expires_at <= ?1")
        .map_err(wrap)?;
    let rows = stmt.query_map(params![at], |r| r.get(0)).map_err(wrap)?;
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

/// Forgets a watched file, after the user confirmed it was removed on purpose.
pub fn remove_baseline(conn: &Connection, path: &str) -> Result<(), String> {
    conn.execute("DELETE FROM integrity_baseline WHERE path = ?1", params![path]).map_err(wrap)?;
    Ok(())
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

// --- package check --------------------------------------------------------

/// The digest a packaged file had when its size and change time were these.
pub fn package_digest(conn: &Connection, path: &str, size: u64, ctime: i64) -> Option<String> {
    conn.query_row(
        "SELECT digest FROM package_cache WHERE path = ?1 AND size = ?2 AND ctime = ?3",
        params![path, size as i64, ctime],
        |r| r.get(0),
    )
    .optional()
    .ok()
    .flatten()
}

pub fn put_package_digest(conn: &Connection, path: &str, size: u64, ctime: i64, digest: &str) -> Result<(), String> {
    conn.execute(
        "INSERT INTO package_cache (path, size, ctime, digest) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(path) DO UPDATE SET size = excluded.size, ctime = excluded.ctime, digest = excluded.digest",
        params![path, size as i64, ctime, digest],
    )
    .map_err(wrap)?;
    Ok(())
}

/// The contents the user confirmed for a file that differs from its package.
pub fn package_accepted(conn: &Connection, path: &str) -> Option<String> {
    conn.query_row("SELECT digest FROM package_accepted WHERE path = ?1", params![path], |r| r.get(0))
        .optional()
        .ok()
        .flatten()
}

pub fn accept_package_file(conn: &Connection, path: &str, digest: &str) -> Result<(), String> {
    conn.execute(
        "INSERT INTO package_accepted (path, digest, accepted_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(path) DO UPDATE SET digest = excluded.digest, accepted_at = excluded.accepted_at",
        params![path, digest, now()],
    )
    .map_err(wrap)?;
    Ok(())
}

// --- the generic baseline -------------------------------------------------

/// What a check recorded for this key, if it has seen it before.
pub fn baseline_value(conn: &Connection, kind: &str, key: &str) -> Option<String> {
    conn.query_row("SELECT value FROM baseline WHERE kind = ?1 AND key = ?2", params![kind, key], |r| r.get(0))
        .optional()
        .ok()
        .flatten()
}

/// Everything a check has recorded, key to value.
pub fn baseline_entries(conn: &Connection, kind: &str) -> Vec<(String, String)> {
    let Ok(mut stmt) = conn.prepare("SELECT key, value FROM baseline WHERE kind = ?1 AND key != ''") else {
        return Vec::new();
    };
    stmt.query_map(params![kind], |r| Ok((r.get(0)?, r.get(1)?)))
        .map(|rows| rows.flatten().collect())
        .unwrap_or_default()
}

/// Whether a check has recorded anything yet, which tells a first run apart.
pub fn baseline_started(conn: &Connection, kind: &str) -> bool {
    conn.query_row("SELECT 1 FROM baseline WHERE kind = ?1 LIMIT 1", params![kind], |_| Ok(()))
        .optional()
        .ok()
        .flatten()
        .is_some()
}

pub fn set_baseline_value(conn: &Connection, kind: &str, key: &str, value: &str) -> Result<(), String> {
    conn.execute(
        "INSERT INTO baseline (kind, key, value, first_seen) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(kind, key) DO UPDATE SET value = excluded.value",
        params![kind, key, value, now()],
    )
    .map_err(wrap)?;
    Ok(())
}

/// Marks a check as started even when it found nothing to record.
pub fn mark_baseline_started(conn: &Connection, kind: &str) -> Result<(), String> {
    set_baseline_value(conn, kind, "", "")
}

// --- autostart baseline ---------------------------------------------------

pub fn autostart_is_known(conn: &Connection, key: &str) -> bool {
    conn.query_row("SELECT 1 FROM autostart_baseline WHERE key = ?1", params![key], |_| Ok(()))
        .optional()
        .ok()
        .flatten()
        .is_some()
}

/// Whether a 0.2 baseline already holds entries from this source.
pub fn autostart_source_recorded(conn: &Connection, source: &str) -> bool {
    conn.query_row("SELECT 1 FROM autostart_baseline WHERE source = ?1 LIMIT 1", params![source], |_| Ok(()))
        .optional()
        .ok()
        .flatten()
        .is_some()
}

#[cfg(test)]
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
    conn.query_row(
        "SELECT id, timestamp, action, target, reason, reversible, reverted FROM action_log WHERE id = ?1",
        params![id],
        |row| {
            Ok(ActionRecord {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                action: row.get(2)?,
                target: row.get(3)?,
                reason: row.get(4)?,
                reversible: row.get::<_, i64>(5)? != 0,
                reverted: row.get::<_, i64>(6)? != 0,
            })
        },
    )
    .optional()
    .map_err(wrap)
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
    fn what_the_rules_found_goes_with_the_contents_it_describes() {
        let conn = open_memory();
        put_file(&conn, "/tmp/a.sh", "hash-1", 10, 1).unwrap();
        put_content(&conn, "/tmp/a.sh", "v1", "{}").unwrap();
        assert_eq!(cached_file(&conn, "/tmp/a.sh", 10, 1).unwrap().content_version.as_deref(), Some("v1"));

        put_file(&conn, "/tmp/a.sh", "hash-1", 10, 2).unwrap();
        assert_eq!(cached_file(&conn, "/tmp/a.sh", 10, 2).unwrap().content.as_deref(), Some("{}"));

        put_file(&conn, "/tmp/a.sh", "hash-2", 11, 3).unwrap();
        assert!(cached_file(&conn, "/tmp/a.sh", 11, 3).unwrap().content.is_none());
    }

    #[test]
    fn a_database_from_before_the_rules_gains_the_new_columns() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE file_cache (path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
                 mtime INTEGER NOT NULL, vt_verdict INTEGER, vt_checked INTEGER);
                 INSERT INTO file_cache VALUES ('/tmp/x', 'h', 1, 1, 3, 100);",
            )
            .unwrap();
        }
        let conn = open_at(&path).unwrap();
        let cached = cached_file(&conn, "/tmp/x", 1, 1).unwrap();
        assert_eq!(cached.vt_verdict, Some(3));
        assert!(cached.content.is_none());
        // Opening twice must not try to add the columns again.
        drop(conn);
        open_at(&path).unwrap();
    }

    #[test]
    fn the_generic_baseline_keeps_checks_apart() {
        let conn = open_memory();
        assert!(!baseline_started(&conn, "module"));
        set_baseline_value(&conn, "module", "nvidia", "PO").unwrap();
        assert!(baseline_started(&conn, "module"));
        assert!(!baseline_started(&conn, "extension"));
        assert_eq!(baseline_value(&conn, "module", "nvidia").as_deref(), Some("PO"));
        set_baseline_value(&conn, "module", "nvidia", "O").unwrap();
        assert_eq!(baseline_value(&conn, "module", "nvidia").as_deref(), Some("O"));

        mark_baseline_started(&conn, "extension").unwrap();
        assert!(baseline_started(&conn, "extension"));
    }

    #[test]
    fn an_issue_counts_its_sightings_and_keeps_being_set_aside() {
        let conn = open_memory();
        let first = observe_issue(&conn, "fp", "rule_match", 100).unwrap();
        assert_eq!(first, Sighting { first_seen: 100, times_seen: 1, set_aside: false });

        set_issue_aside(&conn, "fp", "rule_match", true).unwrap();
        let second = observe_issue(&conn, "fp", "rule_match", 200).unwrap();
        assert_eq!(second, Sighting { first_seen: 100, times_seen: 2, set_aside: true });

        set_issue_aside(&conn, "fp", "rule_match", false).unwrap();
        assert!(!issue_sighting(&conn, "fp").unwrap().unwrap().set_aside);
    }

    #[test]
    fn only_the_latest_scans_keep_their_issues() {
        let conn = open_memory();
        let issue = |n: usize| StoredIssue {
            fingerprint: format!("fp{n}"),
            kind: "rule_match".into(),
            severity: "warning".into(),
            title: "t".into(),
            location: "l".into(),
            detail: None,
            first_seen: 1,
            times_seen: 1,
            set_aside: false,
        };
        let mut ids = Vec::new();
        for n in 0..(SCANS_KEPT as usize + 3) {
            let id = record_scan(&conn, 1, 1).unwrap();
            record_scan_issues(&conn, id, &[issue(n)]).unwrap();
            ids.push(id);
        }
        assert!(scan_issues(&conn, ids[0]).unwrap().is_empty());
        assert_eq!(scan_issues(&conn, *ids.last().unwrap()).unwrap()[0].fingerprint, format!("fp{}", ids.len() - 1));
        assert_eq!(get_scan(&conn, ids[0]).unwrap().unwrap().id, ids[0], "the counts stay");
    }

    #[test]
    fn an_automatic_block_lifts_and_a_manual_one_does_not() {
        let conn = open_memory();
        put_block(&conn, "203.0.113.5", Some(1_000)).unwrap();
        put_block(&conn, "203.0.113.6", None).unwrap();
        assert!(is_blocked(&conn, "203.0.113.5", 999));
        assert!(!is_blocked(&conn, "203.0.113.5", 1_000));
        assert!(is_blocked(&conn, "203.0.113.6", i64::MAX));
        assert!(!is_blocked(&conn, "203.0.113.7", 0));
        assert_eq!(expired_blocks(&conn, 1_000).unwrap(), vec!["203.0.113.5".to_string()]);
        remove_block(&conn, "203.0.113.5").unwrap();
        assert!(block_expiry(&conn, "203.0.113.5").is_none());
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
