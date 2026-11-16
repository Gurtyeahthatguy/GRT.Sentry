//! Where GRT Sentry keeps its files.
//!
//! The roots come from `platform`, which knows the convention of each system.
//! The window, the scheduled scan and the tests all read the same answers from
//! here.

use std::path::PathBuf;

use crate::platform;

/// Name used for every per-application directory.
const APP_DIR: &str = "grt-sentry";

/// Database, quarantine and downloaded GeoIP data.
pub fn data_dir() -> PathBuf {
    platform::data_dir().join(APP_DIR)
}

/// The configuration file's directory.
pub fn config_dir() -> PathBuf {
    platform::config_dir().join(APP_DIR)
}

pub fn database_path() -> PathBuf {
    data_dir().join("sentry.db")
}

pub fn quarantine_dir() -> PathBuf {
    data_dir().join("quarantine")
}

pub fn config_path() -> PathBuf {
    config_dir().join("config.toml")
}

/// Everywhere the GeoLite2 database might be, user copy first.
pub fn geoip_candidates(bundled: Option<PathBuf>) -> Vec<PathBuf> {
    let mut out = vec![
        data_dir().join("GeoLite2-City.mmdb"),
        PathBuf::from("/usr/share/grt-sentry/GeoLite2-City.mmdb"),
        PathBuf::from("/usr/share/GeoIP/GeoLite2-City.mmdb"),
    ];
    if let Some(bundled) = bundled {
        out.insert(1, bundled);
    }
    out
}

/// Expands a leading `~` in a configured path.
/// The file a path leads to, through any link, written as people write it:
/// Windows' `\\?\C:\` form loses its prefix.
pub fn real_path(path: &str) -> std::io::Result<PathBuf> {
    let real = std::fs::canonicalize(path)?;
    let text = real.to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => Ok(PathBuf::from(rest)),
        _ => Ok(real),
    }
}

pub fn expand_tilde(path: &str) -> PathBuf {
    let home = || {
        std::env::var_os("HOME").map(PathBuf::from).filter(|p| p.is_absolute()).unwrap_or_else(platform::home_dir)
    };

    if path == "~" {
        return home();
    }
    match path.strip_prefix("~/") {
        Some(rest) => home().join(rest),
        None => PathBuf::from(path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tilde_expands_only_at_the_start() {
        let home = expand_tilde("~");
        assert_eq!(expand_tilde("~/Downloads"), home.join("Downloads"));
        // A tilde in the middle is part of the name.
        assert_eq!(expand_tilde("/tmp/a~b"), PathBuf::from("/tmp/a~b"));
    }

    #[test]
    fn every_path_sits_under_the_application_directory() {
        assert!(database_path().starts_with(data_dir()));
        assert!(quarantine_dir().starts_with(data_dir()));
        assert!(config_path().starts_with(config_dir()));
        assert!(data_dir().ends_with(APP_DIR));
    }

    #[test]
    fn user_copy_of_the_geoip_database_wins_over_the_bundled_one() {
        let list = geoip_candidates(Some(PathBuf::from("/opt/app/GeoLite2-City.mmdb")));
        assert!(list[0].starts_with(data_dir()));
        assert_eq!(list[1], PathBuf::from("/opt/app/GeoLite2-City.mmdb"));
    }
}
