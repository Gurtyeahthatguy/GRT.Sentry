//! Runs Tauri's build step and packs the detection rules into the binary.
//!
//! The rules are stored XORed with one byte. That is not secrecy, they are in
//! the repository in plain text: it keeps the release binary from carrying the
//! patterns it looks for, which would make it match its own rules and look
//! like malware to every other scanner.

use std::path::Path;

/// Shared with `rules.rs`.
const KEY: u8 = 0xA5;

fn main() {
    pack_rules();
    tauri_build::build()
}

fn pack_rules() {
    let dir = Path::new("rules");
    println!("cargo:rerun-if-changed=rules");

    let mut files: Vec<_> = std::fs::read_dir(dir)
        .expect("the rules directory")
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "yar"))
        .collect();
    files.sort();

    let mut text = String::new();
    for path in files {
        println!("cargo:rerun-if-changed={}", path.display());
        text.push_str(&std::fs::read_to_string(&path).expect("a readable rule file"));
        text.push('\n');
    }

    let packed: Vec<u8> = text.bytes().map(|b| b ^ KEY).collect();
    let out = Path::new(&std::env::var("OUT_DIR").unwrap()).join("rules.bin");
    std::fs::write(out, packed).expect("OUT_DIR is writable");
}
