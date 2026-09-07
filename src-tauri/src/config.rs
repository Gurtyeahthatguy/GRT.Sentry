//! The configuration file, `~/.config/grt-sentry/config.toml`.
//!
//! It holds the VirusTotal API key, so it is always written with mode 0600 and
//! its directory with 0700, whether a key is present or not.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{paths, platform};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Config {
    /// VirusTotal API key. Without it the file scanner reports itself
    /// unavailable and the other modules carry on.
    pub virustotal_api_key: Option<String>,

    /// Directories a quick scan walks. Never the whole disk.
    pub scan_paths: Vec<String>,

    /// Files larger than this are skipped.
    pub max_file_size_mb: u64,

    /// When false, only executables and archives are considered.
    pub deep_scan: bool,

    /// Quarantine automatically above this many detections. Off by default.
    pub auto_quarantine: bool,
    pub auto_quarantine_threshold: u32,

    /// Seconds between VirusTotal requests. The free tier allows four a
    /// minute, which is 15 seconds.
    pub vt_interval_seconds: u64,

    /// Upper bound on VirusTotal lookups in one scan. The rest queue for the
    /// next run.
    pub vt_budget_per_scan: u32,

    /// Refresh interval for the connections tab, in seconds. 0 disables it,
    /// which is the default.
    pub connection_refresh_seconds: u32,

    /// Watch the scan directories with inotify. Off by default.
    pub watch_folders: bool,

    /// System files whose hash is tracked between scans.
    pub integrity_paths: Vec<String>,

    /// Authentication log, and the failures from one address it takes to
    /// report it.
    pub auth_log_path: String,
    pub failed_login_threshold: u32,

    /// Run a quick scan as soon as the window opens.
    pub scan_on_startup: bool,

    /// "system", "light" or "dark".
    pub theme: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            virustotal_api_key: None,
            scan_paths: platform::default_scan_paths(),
            max_file_size_mb: 100,
            deep_scan: false,
            auto_quarantine: false,
            auto_quarantine_threshold: 10,
            vt_interval_seconds: 15,
            vt_budget_per_scan: 40,
            connection_refresh_seconds: 0,
            watch_folders: false,
            integrity_paths: platform::default_integrity_paths(),
            auth_log_path: platform::default_auth_log(),
            failed_login_threshold: 5,
            scan_on_startup: true,
            theme: "system".to_string(),
        }
    }
}

impl Config {
    /// Reads the file, falling back to defaults.
    ///
    /// A malformed file is left alone rather than overwritten, so a hand edit
    /// can be corrected.
    pub fn load() -> Self {
        let path = paths::config_path();
        let Ok(text) = fs::read_to_string(&path) else {
            return Config::default();
        };
        match toml::from_str::<Config>(&text) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("grt-sentry: {} is not valid TOML ({e}); using defaults", path.display());
                Config::default()
            }
        }
    }

    /// Writes the file with 0600, through a temporary file in the same
    /// directory.
    pub fn save(&self) -> Result<(), String> {
        let dir = paths::config_dir();
        fs::create_dir_all(&dir).map_err(|e| format!("Cannot create {}: {e}", dir.display()))?;
        platform::restrict_directory(&dir)
            .map_err(|e| format!("Cannot set permissions on {}: {e}", dir.display()))?;

        let text = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        let final_path = paths::config_path();
        let temp_path: PathBuf = dir.join("config.toml.tmp");

        {
            let mut file = fs::File::create(&temp_path)
                .map_err(|e| format!("Cannot write {}: {e}", temp_path.display()))?;
            // Restricted before the key is written, not after.
            platform::restrict_file(&file).map_err(|e| e.to_string())?;
            file.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
        }

        fs::rename(&temp_path, &final_path)
            .map_err(|e| format!("Cannot replace {}: {e}", final_path.display()))?;
        Ok(())
    }

    /// The key, when there is one that is not blank.
    pub fn api_key(&self) -> Option<String> {
        self.virustotal_api_key
            .as_ref()
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
    }

    pub fn max_file_bytes(&self) -> u64 {
        self.max_file_size_mb.saturating_mul(1024 * 1024)
    }
}

/// The configuration as the frontend receives it.
///
/// The key itself never travels. The settings tab is told whether one is set
/// and how it ends, which is enough to tell two keys apart.
#[derive(Serialize, Clone, Debug)]
pub struct ConfigView {
    pub api_key_set: bool,
    pub api_key_hint: Option<String>,
    pub scan_paths: Vec<String>,
    pub max_file_size_mb: u64,
    pub deep_scan: bool,
    pub auto_quarantine: bool,
    pub auto_quarantine_threshold: u32,
    pub vt_interval_seconds: u64,
    pub vt_budget_per_scan: u32,
    pub connection_refresh_seconds: u32,
    pub watch_folders: bool,
    pub integrity_paths: Vec<String>,
    pub auth_log_path: String,
    pub failed_login_threshold: u32,
    pub scan_on_startup: bool,
    pub theme: String,
}

impl From<&Config> for ConfigView {
    fn from(c: &Config) -> Self {
        let key = c.api_key();
        Self {
            api_key_set: key.is_some(),
            api_key_hint: key.map(|k| {
                let tail: String = k.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
                format!("…{tail}")
            }),
            scan_paths: c.scan_paths.clone(),
            max_file_size_mb: c.max_file_size_mb,
            deep_scan: c.deep_scan,
            auto_quarantine: c.auto_quarantine,
            auto_quarantine_threshold: c.auto_quarantine_threshold,
            vt_interval_seconds: c.vt_interval_seconds,
            vt_budget_per_scan: c.vt_budget_per_scan,
            connection_refresh_seconds: c.connection_refresh_seconds,
            watch_folders: c.watch_folders,
            integrity_paths: c.integrity_paths.clone(),
            auth_log_path: c.auth_log_path.clone(),
            failed_login_threshold: c.failed_login_threshold,
            scan_on_startup: c.scan_on_startup,
            theme: c.theme.clone(),
        }
    }
}

/// What the settings tab is allowed to change.
///
/// Every field is optional and only the ones that arrive are applied, so a
/// single toggle can be sent without echoing the whole configuration.
#[derive(Deserialize, Debug, Default)]
pub struct ConfigUpdate {
    /// `Some("")` clears the stored key, `None` leaves it alone.
    pub virustotal_api_key: Option<String>,
    pub scan_paths: Option<Vec<String>>,
    pub max_file_size_mb: Option<u64>,
    pub deep_scan: Option<bool>,
    pub auto_quarantine: Option<bool>,
    pub auto_quarantine_threshold: Option<u32>,
    pub vt_interval_seconds: Option<u64>,
    pub vt_budget_per_scan: Option<u32>,
    pub connection_refresh_seconds: Option<u32>,
    pub watch_folders: Option<bool>,
    pub integrity_paths: Option<Vec<String>>,
    pub auth_log_path: Option<String>,
    pub failed_login_threshold: Option<u32>,
    pub scan_on_startup: Option<bool>,
    pub theme: Option<String>,
}

impl ConfigUpdate {
    /// Applies the fields that were sent, clamping the numeric ones.
    pub fn apply(self, config: &mut Config) {
        if let Some(key) = self.virustotal_api_key {
            let key = key.trim().to_string();
            config.virustotal_api_key = if key.is_empty() { None } else { Some(key) };
        }
        if let Some(paths) = self.scan_paths {
            config.scan_paths = paths.into_iter().filter(|p| !p.trim().is_empty()).collect();
        }
        if let Some(v) = self.max_file_size_mb {
            config.max_file_size_mb = v.clamp(1, 4096);
        }
        if let Some(v) = self.deep_scan {
            config.deep_scan = v;
        }
        if let Some(v) = self.auto_quarantine {
            config.auto_quarantine = v;
        }
        if let Some(v) = self.auto_quarantine_threshold {
            config.auto_quarantine_threshold = v.clamp(1, 100);
        }
        if let Some(v) = self.vt_interval_seconds {
            config.vt_interval_seconds = v.clamp(15, 3600);
        }
        if let Some(v) = self.vt_budget_per_scan {
            config.vt_budget_per_scan = v.clamp(1, 500);
        }
        if let Some(v) = self.connection_refresh_seconds {
            config.connection_refresh_seconds = if v == 0 { 0 } else { v.clamp(5, 3600) };
        }
        if let Some(v) = self.watch_folders {
            config.watch_folders = v;
        }
        if let Some(paths) = self.integrity_paths {
            config.integrity_paths = paths.into_iter().filter(|p| !p.trim().is_empty()).collect();
        }
        if let Some(v) = self.auth_log_path {
            config.auth_log_path = v;
        }
        if let Some(v) = self.failed_login_threshold {
            config.failed_login_threshold = v.clamp(1, 1000);
        }
        if let Some(v) = self.scan_on_startup {
            config.scan_on_startup = v;
        }
        if let Some(v) = self.theme {
            if ["system", "light", "dark"].contains(&v.as_str()) {
                config.theme = v;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_never_reaches_the_view_but_its_presence_does() {
        let config = Config { virustotal_api_key: Some("abcd1234efgh5678".into()), ..Default::default() };
        let view = ConfigView::from(&config);
        assert!(view.api_key_set);
        assert_eq!(view.api_key_hint.as_deref(), Some("…5678"));

        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("abcd1234efgh"));
    }

    #[test]
    fn an_empty_key_is_no_key() {
        let config = Config { virustotal_api_key: Some("   ".into()), ..Default::default() };
        assert!(config.api_key().is_none());
    }

    #[test]
    fn an_update_touches_only_the_fields_it_carries() {
        let mut config = Config { deep_scan: true, ..Default::default() };
        let original_paths = config.scan_paths.clone();

        ConfigUpdate { auto_quarantine: Some(true), ..Default::default() }.apply(&mut config);

        assert!(config.auto_quarantine);
        assert!(config.deep_scan, "an absent field must not be reset");
        assert_eq!(config.scan_paths, original_paths);
    }

    #[test]
    fn a_request_interval_below_the_free_tier_limit_is_raised_to_it() {
        let mut config = Config::default();
        ConfigUpdate { vt_interval_seconds: Some(0), ..Default::default() }.apply(&mut config);
        assert_eq!(config.vt_interval_seconds, 15);
    }

    #[test]
    fn clearing_the_key_is_possible_but_only_explicitly() {
        let mut config = Config { virustotal_api_key: Some("key".into()), ..Default::default() };
        ConfigUpdate { virustotal_api_key: Some(String::new()), ..Default::default() }.apply(&mut config);
        assert!(config.virustotal_api_key.is_none());
    }
}
