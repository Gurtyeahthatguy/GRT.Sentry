//! Files the user has vouched for.
//!
//! Keyed by hash, never by path: a trusted file replaced by another one has a
//! different hash and inherits no trust.
//!
//! Distinct from the hash cache in `db.rs`, which avoids recomputing the hash
//! of an unchanged file. This avoids reporting a file at all.

use rusqlite::Connection;

use crate::actionlog;
use crate::db::{self, AllowEntry};

/// A SHA-256 as this program writes them: 64 lowercase hex characters.
fn is_valid_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn add(conn: &Connection, sha256: &str, label: Option<&str>) -> Result<(), String> {
    let hash = sha256.trim().to_ascii_lowercase();
    if !is_valid_hash(&hash) {
        return Err("That is not a SHA-256 hash.".to_string());
    }
    db::allow_hash(conn, &hash, label.filter(|l| !l.trim().is_empty()))?;
    actionlog::record(conn, actionlog::kind::TRUST_FILE, &hash, label, true);
    Ok(())
}

pub fn remove(conn: &Connection, sha256: &str) -> Result<(), String> {
    let hash = sha256.trim().to_ascii_lowercase();
    db::remove_allowed(conn, &hash)?;
    actionlog::record(conn, actionlog::kind::UNTRUST_FILE, &hash, None, false);
    Ok(())
}

pub fn contains(conn: &Connection, sha256: &str) -> bool {
    db::is_allowed(conn, &sha256.trim().to_ascii_lowercase())
}

pub fn list(conn: &Connection) -> Result<Vec<AllowEntry>, String> {
    db::list_allowed(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn a_trusted_hash_is_remembered_and_logged() {
        let conn = crate::db::open_memory();
        add(&conn, HASH, Some("my own build")).unwrap();

        assert!(contains(&conn, HASH));
        assert_eq!(list(&conn).unwrap().len(), 1);
        assert_eq!(actionlog::list(&conn, 10).unwrap()[0].action, actionlog::kind::TRUST_FILE);
    }

    #[test]
    fn case_and_surrounding_space_do_not_create_a_second_entry() {
        let conn = crate::db::open_memory();
        add(&conn, &HASH.to_uppercase(), None).unwrap();
        assert!(contains(&conn, &format!("  {HASH}  ")));
        assert_eq!(list(&conn).unwrap().len(), 1);
    }

    #[test]
    fn something_that_is_not_a_hash_is_refused() {
        let conn = crate::db::open_memory();
        assert!(add(&conn, "trust me", None).is_err());
        assert!(add(&conn, "abc123", None).is_err());
        assert!(list(&conn).unwrap().is_empty());
    }

    #[test]
    fn trust_can_be_withdrawn() {
        let conn = crate::db::open_memory();
        add(&conn, HASH, None).unwrap();
        remove(&conn, HASH).unwrap();
        assert!(!contains(&conn, HASH));
    }
}
