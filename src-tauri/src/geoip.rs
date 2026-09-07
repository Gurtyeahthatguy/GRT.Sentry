//! Turning an address into a place, without asking anybody.
//!
//! An online lookup service would learn every address this machine talks to,
//! so the lookup runs here against MaxMind's published data file.
//!
//! The database is opened once at startup and kept in the shared state. It is
//! tens of megabytes, and reopening it per lookup would reread all of it for
//! every row of the connections table.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use maxminddb::{geoip2, Reader};
use serde::Serialize;

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct GeoInfo {
    pub lat: f64,
    pub lon: f64,
    pub city: Option<String>,
    pub country: Option<String>,
    pub country_code: Option<String>,
}

impl GeoInfo {
    /// "Amsterdam, Netherlands", or the country alone, or nothing.
    pub fn label(&self) -> String {
        match (&self.city, &self.country) {
            (Some(city), Some(country)) => format!("{city}, {country}"),
            (Some(city), None) => city.clone(),
            (None, Some(country)) => country.clone(),
            (None, None) => "unknown location".to_string(),
        }
    }
}

/// Where the bundled database ends up once the program is installed.
///
/// Used by the headless scan, which has no `AppHandle` to ask.
pub fn bundled_guess() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let name = exe.file_name()?.to_string_lossy().into_owned();

    let candidates = [
        dir.join("resources/GeoLite2-City.mmdb"),
        // A .deb and an AppImage both put resources under the *product* name,
        // spaces included: /usr/lib/GRT Sentry/resources/. The binary name is
        // tried as well, since that is what a hand-made package tends to use.
        dir.join("../lib/GRT Sentry/resources/GeoLite2-City.mmdb"),
        dir.join(format!("../lib/{name}/resources/GeoLite2-City.mmdb")),
        dir.join("../lib/grt-sentry/resources/GeoLite2-City.mmdb"),
        // The source tree, during development.
        dir.join("../../resources/GeoLite2-City.mmdb"),
    ];
    candidates.into_iter().find(|c| c.is_file())
}

pub struct GeoDb {
    reader: Reader<Vec<u8>>,
    path: PathBuf,
}

impl GeoDb {
    pub fn open(path: &Path) -> Result<Self, String> {
        let reader = Reader::open_readfile(path)
            .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
        Ok(Self { reader, path: path.to_path_buf() })
    }

    /// Opens the first database that exists among the usual locations.
    ///
    /// A missing database costs the connections table one column and must not
    /// stop the program starting, so this returns `None` rather than an error.
    pub fn discover(bundled: Option<PathBuf>) -> Option<Self> {
        for candidate in crate::paths::geoip_candidates(bundled) {
            if candidate.is_file() {
                match GeoDb::open(&candidate) {
                    Ok(db) => return Some(db),
                    Err(e) => eprintln!("grt-sentry: {e}"),
                }
            }
        }
        None
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Where the network announcing this address is registered.
    ///
    /// Private addresses return `None` without a lookup.
    pub fn lookup(&self, ip_str: &str) -> Option<GeoInfo> {
        let ip: IpAddr = ip_str.parse().ok()?;
        if is_private(&ip) {
            return None;
        }

        let record: geoip2::City = self.reader.lookup(ip).ok()?;
        let location = record.location?;

        Some(GeoInfo {
            lat: location.latitude?,
            lon: location.longitude?,
            city: record.city.and_then(|c| c.names).and_then(|n| n.get("en").map(|s| s.to_string())),
            country: record
                .country
                .as_ref()
                .and_then(|c| c.names.as_ref())
                .and_then(|n| n.get("en").map(|s| s.to_string())),
            country_code: record.country.and_then(|c| c.iso_code.map(|s| s.to_string())),
        })
    }
}

/// Addresses that never leave this machine or this network.
///
/// There is nothing to look up for them, and a connection to the router is not
/// a stranger.
pub fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => {
            // An IPv4 address in IPv6 form: judge the address inside.
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_private_v4(&mapped);
            }
            is_private_v6(v6)
        }
    }
}

fn is_private_v4(ip: &Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    ip.is_private()            // 10/8, 172.16/12, 192.168/16
        || ip.is_loopback()    // 127/8
        || ip.is_link_local()  // 169.254/16
        || ip.is_broadcast()
        || ip.is_unspecified() // 0.0.0.0
        || ip.is_multicast()
        || ip.is_documentation()
        || a == 0
        // Carrier-grade NAT, 100.64/10, which is what a hotspot hands out.
        || (a == 100 && (64..128).contains(&b))
}

fn is_private_v6(ip: &Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (first & 0xfe00) == 0xfc00 // fc00::/7, unique local
        || (first & 0xffc0) == 0xfe80 // fe80::/10, link local
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn the_home_network_is_never_treated_as_the_internet() {
        for private in ["192.168.1.1", "10.0.0.5", "172.16.0.1", "172.31.255.255", "127.0.0.1", "169.254.1.1", "100.64.0.1", "0.0.0.0"] {
            assert!(is_private(&ip(private)), "{private} should count as private");
        }
        for public in ["8.8.8.8", "185.220.101.7", "1.1.1.1", "172.32.0.1", "100.128.0.1"] {
            assert!(!is_private(&ip(public)), "{public} should count as public");
        }
    }

    #[test]
    fn ipv6_private_ranges_and_mapped_addresses() {
        for private in ["::1", "fe80::1", "fd00::1", "::ffff:192.168.1.1"] {
            assert!(is_private(&ip(private)), "{private} should count as private");
        }
        for public in ["2606:4700:4700::1111", "::ffff:8.8.8.8"] {
            assert!(!is_private(&ip(public)), "{public} should count as public");
        }
    }

    #[test]
    fn a_missing_database_is_not_an_error() {
        // Nothing at these paths, so discovery returns None rather than
        // failing.
        let _env = crate::testenv::isolated_data_dir(std::path::Path::new("/nonexistent-grt-sentry-test"));
        let found = GeoDb::discover(Some(PathBuf::from("/nonexistent-grt-sentry-test/x.mmdb")));
        assert!(found.is_none());
    }

    #[test]
    fn a_label_survives_missing_pieces() {
        let full = GeoInfo { lat: 1.0, lon: 2.0, city: Some("Amsterdam".into()), country: Some("Netherlands".into()), country_code: Some("NL".into()) };
        assert_eq!(full.label(), "Amsterdam, Netherlands");

        let country_only = GeoInfo { city: None, ..full.clone() };
        assert_eq!(country_only.label(), "Netherlands");

        let nothing = GeoInfo { city: None, country: None, ..full };
        assert_eq!(nothing.label(), "unknown location");
    }
}
