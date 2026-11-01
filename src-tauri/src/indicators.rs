//! The user's own rules and indicators of compromise.
//!
//! Both live in the configuration directory and change only when the user
//! edits them, never from the network: `rules/*.yar` for YARA rules, and
//! `indicators.txt` for hashes, file names, paths and addresses, one per line.
//!
//! The user's rules are compiled at the start of a scan and dropped at its
//! end, since a large set has no business staying in memory between scans.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use sha2::{Digest, Sha256};

/// One line of the indicators file.
#[derive(Debug, Clone, PartialEq)]
enum Indicator {
    Sha256(String),
    /// Matched against a file's name, ignoring case.
    Name(String),
    /// An exact path, or a folder when it ends with a separator.
    Path(String),
    Network { address: IpAddr, prefix: u8 },
}

#[derive(Debug, Clone, Default)]
pub struct Indicators {
    entries: Vec<(Indicator, String)>,
}

pub fn indicators_path() -> PathBuf {
    crate::paths::config_dir().join("indicators.txt")
}

pub fn rules_dir() -> PathBuf {
    crate::paths::config_dir().join("rules")
}

/// Reads `a.b.c.d`, `a.b.c.d/n` and the IPv6 equivalents.
fn parse_network(text: &str) -> Option<(IpAddr, u8)> {
    let (address, prefix) = match text.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix.parse::<u8>().ok()?)),
        None => (text, None),
    };
    let address: IpAddr = address.parse().ok()?;
    let full = if address.is_ipv4() { 32 } else { 128 };
    let prefix = prefix.unwrap_or(full);
    (prefix <= full).then_some((address, prefix))
}

fn in_network(ip: &IpAddr, network: &IpAddr, prefix: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            u32::from(*a) & mask == u32::from(*b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
            u128::from(*a) & mask == u128::from(*b) & mask
        }
        _ => false,
    }
}

impl Indicators {
    /// One indicator per line, its kind told by its shape. Anything after the
    /// first space is a note, shown when it matches.
    pub fn parse(text: &str) -> Self {
        let entries = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter_map(|line| {
                let (value, note) = match line.split_once(char::is_whitespace) {
                    Some((value, note)) => (value, note.trim().to_string()),
                    None => (line, line.to_string()),
                };
                let indicator = if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
                    Indicator::Sha256(value.to_ascii_lowercase())
                } else if let Some((address, prefix)) = parse_network(value) {
                    Indicator::Network { address, prefix }
                } else if value.starts_with('/') || value.starts_with('~') || value.get(1..3) == Some(":\\") {
                    let expanded = crate::paths::expand_tilde(value).to_string_lossy().into_owned();
                    let folder = value.ends_with('/') || value.ends_with('\\');
                    Indicator::Path(if folder && !expanded.ends_with(['/', '\\']) { format!("{expanded}/") } else { expanded })
                } else if value.contains('/') || value.contains('\\') {
                    return None;
                } else {
                    Indicator::Name(value.to_ascii_lowercase())
                };
                Some((indicator, note))
            })
            .collect();
        Self { entries }
    }

    pub fn load() -> Self {
        std::fs::read_to_string(indicators_path()).map(|t| Self::parse(&t)).unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    fn find(&self, test: impl Fn(&Indicator) -> bool) -> Option<String> {
        self.entries.iter().find(|(i, _)| test(i)).map(|(_, note)| note.clone())
    }

    pub fn match_hash(&self, sha256: &str) -> Option<String> {
        self.find(|i| matches!(i, Indicator::Sha256(h) if h.eq_ignore_ascii_case(sha256)))
    }

    pub fn match_name(&self, name: &str) -> Option<String> {
        let name = name.to_ascii_lowercase();
        self.find(|i| matches!(i, Indicator::Name(n) if *n == name))
    }

    pub fn match_path(&self, path: &str) -> Option<String> {
        self.find(|i| match i {
            Indicator::Path(p) if p.ends_with(['/', '\\']) => path.starts_with(p.as_str()),
            Indicator::Path(p) => path == p,
            _ => false,
        })
    }

    /// A file by its path, its name or its hash.
    pub fn match_file(&self, path: &str, sha256: &str) -> Option<String> {
        let name = std::path::Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        self.match_hash(sha256).or_else(|| self.match_path(path)).or_else(|| self.match_name(&name))
    }

    pub fn match_ip(&self, ip: &IpAddr) -> Option<String> {
        self.find(|i| matches!(i, Indicator::Network { address, prefix } if in_network(ip, address, *prefix)))
    }
}

/// The user's rules, compiled for one scan.
#[derive(Default)]
pub struct OwnRules {
    pub rules: Option<Arc<yara_x::Rules>>,
    /// Files that compiled.
    pub files: usize,
    /// Changes whenever a rule file does, so cached results are redone.
    pub version: String,
    pub errors: Vec<String>,
}

pub fn load_rules() -> OwnRules {
    let Ok(entries) = std::fs::read_dir(rules_dir()) else { return OwnRules::default() };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()).is_some_and(|e| e == "yar" || e == "yara"))
        .collect();
    files.sort();

    let mut compiler = yara_x::Compiler::new();
    // A namespace per file, so two files may name a rule the same way.
    let mut hasher = Sha256::new();
    let mut compiled = 0;
    let mut errors = Vec::new();
    for (index, file) in files.iter().enumerate() {
        let Ok(text) = std::fs::read_to_string(file) else { continue };
        hasher.update(file.to_string_lossy().as_bytes());
        hasher.update(text.as_bytes());
        compiler.new_namespace(&format!("own{index}"));
        match compiler.add_source(yara_x::SourceCode::from(text.as_str()).with_origin(file.to_string_lossy().as_ref())) {
            Ok(_) => compiled += 1,
            Err(e) => errors.push(format!("{} does not compile: {e}", file.display())),
        }
    }
    if compiled == 0 {
        return OwnRules { errors, ..Default::default() };
    }
    OwnRules {
        rules: Some(Arc::new(compiler.build())),
        files: compiled,
        version: format!("{:x}", hasher.finalize())[..16].to_string(),
        errors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_line_is_read_by_its_shape() {
        let text = "# comment\n\
                    ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad known dropper\n\
                    203.0.113.0/24 command server\n\
                    2001:db8::1\n\
                    /opt/evil/\n\
                    /usr/bin/xmr\n\
                    Invoice.PDF.exe\n\
                    not/a/path\n";
        let ind = Indicators::parse(text);
        assert_eq!(ind.len(), 6);

        assert_eq!(ind.match_hash("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD").as_deref(), Some("known dropper"));
        assert_eq!(ind.match_ip(&"203.0.113.77".parse().unwrap()).as_deref(), Some("command server"));
        assert!(ind.match_ip(&"203.0.114.1".parse().unwrap()).is_none());
        assert!(ind.match_ip(&"2001:db8::1".parse().unwrap()).is_some());
        assert!(ind.match_path("/opt/evil/bin/run").is_some());
        assert!(ind.match_path("/opt/evilness").is_none());
        assert!(ind.match_path("/usr/bin/xmr").is_some());
        assert!(ind.match_path("/usr/bin/xmrig").is_none());
        assert!(ind.match_name("invoice.pdf.exe").is_some());
        assert!(ind.match_file("/home/u/Downloads/Invoice.pdf.exe", "00").is_some());
    }

    #[test]
    fn a_zero_prefix_matches_everything_of_its_family_only() {
        let ind = Indicators::parse("0.0.0.0/0 any\n");
        assert!(ind.match_ip(&"8.8.8.8".parse().unwrap()).is_some());
        assert!(ind.match_ip(&"::1".parse().unwrap()).is_none());
    }

    #[test]
    fn the_users_rules_compile_and_a_broken_file_is_named() {
        let dir = tempfile::tempdir().unwrap();
        let _env = crate::testenv::isolated_config_dir(dir.path());
        let rules = rules_dir();
        std::fs::create_dir_all(&rules).unwrap();
        std::fs::write(rules.join("mine.yar"), "rule my_marker { strings: $a = \"GRT-TEST-MARKER\" condition: $a }").unwrap();
        std::fs::write(rules.join("broken.yar"), "rule nope { condition: ").unwrap();

        let own = load_rules();
        assert_eq!(own.files, 1);
        assert_eq!(own.errors.len(), 1);
        assert!(own.errors[0].contains("broken.yar"));
        assert_eq!(own.version.len(), 16);
    }

    #[test]
    fn no_rules_folder_means_no_rules_and_no_complaint() {
        let dir = tempfile::tempdir().unwrap();
        let _env = crate::testenv::isolated_config_dir(dir.path());
        let own = load_rules();
        assert!(own.rules.is_none() && own.errors.is_empty());
    }
}
