//! Browser extensions, and the ones that did not come from a store.
//!
//! An extension sees every page the browser opens, which makes it a better
//! foothold than most programs. Firefox keeps its list in `extensions.json`,
//! the Chromium family in `Preferences`; both say where each extension came
//! from.
//!
//! One installed outside the store, unpacked from a folder, sideloaded by
//! another program or forced in by a policy, is reported until it is accepted.
//! One from the store is recorded the first time and mentioned only when it
//! is new.

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde_json::Value;

use crate::db;
use crate::platform::{self, BrowserKind};
use crate::state::{Action, Finding, Issue, IssueKind, IssueTarget, Severity};

const KIND: &str = "extension";

/// Permissions that let an extension read or change more than its own page.
const BROAD: &[&str] = &[
    "<all_urls>", "*://*/*", "http://*/*", "https://*/*", "webRequest", "webRequestBlocking", "nativeMessaging",
    "proxy", "debugger", "cookies", "history", "management", "clipboardRead", "privacy", "downloads",
];

#[derive(Debug, Clone, PartialEq)]
pub struct Extension {
    pub browser: String,
    pub profile: String,
    pub id: String,
    pub name: String,
    /// `None` when it came from the browser's store.
    pub outside_store: Option<String>,
    pub broad_permissions: Vec<String>,
}

impl Extension {
    fn key(&self) -> String {
        format!("{}:{}:{}", self.browser, self.profile, self.id)
    }
}

fn strings(value: &Value) -> Vec<String> {
    value.as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default()
}

fn broad(permissions: &[String]) -> Vec<String> {
    let mut out: Vec<String> = permissions.iter().filter(|p| BROAD.contains(&p.as_str())).cloned().collect();
    out.sort();
    out.dedup();
    out
}

/// Firefox's `extensions.json`.
pub fn parse_firefox(text: &str, browser: &str, profile: &str) -> Vec<Extension> {
    let Ok(json) = serde_json::from_str::<Value>(text) else { return vec![] };
    let Some(addons) = json["addons"].as_array() else { return vec![] };

    addons
        .iter()
        .filter_map(|addon| {
            if addon["type"].as_str() != Some("extension") {
                return None;
            }
            let location = addon["location"].as_str().unwrap_or("");
            // Firefox's own, shipped inside the browser.
            if location.starts_with("app-builtin") || location == "app-system-defaults" || location == "app-system-addons" {
                return None;
            }
            let signed = addon["signedState"].as_i64();
            let source = addon["installTelemetryInfo"]["source"].as_str().unwrap_or("");

            let outside_store = if location.starts_with("app-system-") || location == "app-global" {
                Some(format!("placed by another program ({location})"))
            } else if source == "enterprise-policy" {
                Some("forced in by a policy".to_string())
            } else if signed.is_none_or(|s| s < 2) {
                Some("not signed by Mozilla".to_string())
            } else if source == "file-url" {
                Some("installed from a file".to_string())
            } else {
                None
            };

            let mut permissions = strings(&addon["userPermissions"]["permissions"]);
            permissions.extend(strings(&addon["userPermissions"]["origins"]));
            let id = addon["id"].as_str()?.to_string();
            Some(Extension {
                browser: browser.to_string(),
                profile: profile.to_string(),
                name: addon["defaultLocale"]["name"].as_str().map(String::from).unwrap_or_else(|| id.clone()),
                id,
                outside_store,
                broad_permissions: broad(&permissions),
            })
        })
        .collect()
}

/// A Chromium profile's `Preferences` or `Secure Preferences`, with the
/// profile directory for manifests the preferences leave out.
pub fn parse_chromium(text: &str, browser: &str, profile_dir: &Path) -> Vec<Extension> {
    let Ok(json) = serde_json::from_str::<Value>(text) else { return vec![] };
    let Some(settings) = json["extensions"]["settings"].as_object() else { return vec![] };
    let profile = profile_dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();

    settings
        .iter()
        .filter_map(|(id, entry)| {
            let location = entry["location"].as_i64().unwrap_or(0);
            // 5 and 10 are the browser's own components.
            if location == 5 || location == 10 {
                return None;
            }
            let from_store = entry["from_webstore"].as_bool().unwrap_or(false);
            let outside_store = match location {
                4 => Some("loaded unpacked from a folder".to_string()),
                8 => Some("loaded from the command line".to_string()),
                7 | 9 => Some("forced in by a policy".to_string()),
                2 | 3 | 6 if !from_store => Some("placed by another program".to_string()),
                1 if !from_store => Some("installed from a file".to_string()),
                _ => None,
            };

            let manifest = if entry["manifest"].is_object() {
                entry["manifest"].clone()
            } else {
                read_manifest(&profile_dir.join("Extensions").join(id)).unwrap_or(Value::Null)
            };
            let mut permissions = strings(&manifest["permissions"]);
            permissions.extend(strings(&manifest["host_permissions"]));
            let name = manifest["name"]
                .as_str()
                .filter(|n| !n.starts_with("__MSG_"))
                .map(String::from)
                .unwrap_or_else(|| id.clone());

            Some(Extension {
                browser: browser.to_string(),
                profile: profile.clone(),
                id: id.clone(),
                name,
                outside_store,
                broad_permissions: broad(&permissions),
            })
        })
        .collect()
}

/// The manifest of the newest installed version of an extension.
fn read_manifest(dir: &Path) -> Option<Value> {
    let mut versions: Vec<PathBuf> = std::fs::read_dir(dir).ok()?.flatten().map(|e| e.path()).collect();
    versions.sort();
    let text = std::fs::read_to_string(versions.last()?.join("manifest.json")).ok()?;
    serde_json::from_str(&text).ok()
}

/// Every extension in every profile of every browser on this account.
pub fn collect() -> Vec<Extension> {
    let mut out = Vec::new();
    for (browser, kind, root) in platform::browser_roots() {
        let Ok(entries) = std::fs::read_dir(&root) else { continue };
        for profile in entries.flatten().map(|e| e.path()).filter(|p| p.is_dir()) {
            let name = profile.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            match kind {
                BrowserKind::Firefox => {
                    if let Ok(text) = std::fs::read_to_string(profile.join("extensions.json")) {
                        out.extend(parse_firefox(&text, &browser, &name));
                    }
                }
                BrowserKind::Chromium => {
                    let mut seen = Vec::new();
                    for file in ["Secure Preferences", "Preferences"] {
                        let Ok(text) = std::fs::read_to_string(profile.join(file)) else { continue };
                        for extension in parse_chromium(&text, &browser, &profile) {
                            if !seen.contains(&extension.id) {
                                seen.push(extension.id.clone());
                                out.push(extension);
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

pub fn findings(conn: &Connection) -> Vec<Finding> {
    findings_for(conn, &collect())
}

pub fn findings_for(conn: &Connection, extensions: &[Extension]) -> Vec<Finding> {
    let first_run = !db::baseline_started(conn, KIND);
    let mut findings = Vec::new();

    for extension in extensions {
        let key = extension.key();
        if db::baseline_value(conn, KIND, &key).is_some() {
            continue;
        }
        if extension.outside_store.is_none() {
            let _ = db::set_baseline_value(conn, KIND, &key, "store");
            if first_run {
                continue;
            }
        }
        findings.push(finding(extension));
    }

    if first_run {
        let _ = db::mark_baseline_started(conn, KIND);
    }
    findings
}

fn finding(extension: &Extension) -> Finding {
    let permissions = if extension.broad_permissions.is_empty() {
        String::new()
    } else {
        format!("\n\nIt may use: {}.", extension.broad_permissions.join(", "))
    };
    let (severity, title, detail) = match &extension.outside_store {
        Some(how) => (
            Severity::Warning,
            format!("{} extension from outside the store: {}", extension.browser, extension.name),
            format!(
                "{} was {how}, not installed from the browser's store, which reviews what it lists. A company that manages its browsers and a developer testing their own work both do this; so does adware that wants to be impossible to remove.{permissions}\n\n\
                 Profile: {}. Identifier: {}. If you did not put it there, remove it from the browser's extensions page.",
                extension.name, extension.profile, extension.id
            ),
        ),
        None => (
            if extension.broad_permissions.is_empty() { Severity::Info } else { Severity::Warning },
            format!("New {} extension: {}", extension.browser, extension.name),
            format!(
                "{} was installed from the store since the last scan.{permissions}\n\nProfile: {}. Identifier: {}.",
                extension.name, extension.profile, extension.id
            ),
        ),
    };

    Finding::new(
        Issue {
            kind: IssueKind::BrowserExtension,
            severity,
            title,
            location: format!("{} · {}", extension.browser, extension.profile),
            detail: Some(detail),
            actions: vec![Action::new("trust", "Expected", false), Action::ignore()],
            ..Default::default()
        },
        IssueTarget::Baseline { kind: KIND.to_string(), key: extension.key(), value: "accepted".to_string() },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIREFOX: &str = r#"{"addons":[
        {"id":"adguardadblocker@adguard.com","type":"extension","location":"app-profile","signedState":2,
         "installTelemetryInfo":{"source":"amo"},"defaultLocale":{"name":"AdGuard AdBlocker"},
         "userPermissions":{"permissions":["tabs","webRequest"],"origins":["<all_urls>"]}},
        {"id":"webcompat@mozilla.org","type":"extension","location":"app-builtin-addons","defaultLocale":{"name":"Web Compatibility"}},
        {"id":"default-theme@mozilla.org","type":"theme","location":"app-builtin"},
        {"id":"helper@cheap-deals.example","type":"extension","location":"app-system-share","signedState":2,
         "defaultLocale":{"name":"Deal Finder"},"userPermissions":{"origins":["<all_urls>"]}},
        {"id":"dev@me","type":"extension","location":"app-profile","signedState":0,
         "installTelemetryInfo":{"source":"file-url"},"defaultLocale":{"name":"My test"}}
    ]}"#;

    #[test]
    fn firefox_records_say_where_each_extension_came_from() {
        let found = parse_firefox(FIREFOX, "Firefox", "default");
        assert_eq!(found.len(), 3, "built-in extensions and themes are left out");

        let adguard = found.iter().find(|e| e.name == "AdGuard AdBlocker").unwrap();
        assert!(adguard.outside_store.is_none());
        assert_eq!(adguard.broad_permissions, vec!["<all_urls>", "webRequest"]);

        let sideloaded = found.iter().find(|e| e.name == "Deal Finder").unwrap();
        assert!(sideloaded.outside_store.as_ref().unwrap().contains("another program"));

        let unsigned = found.iter().find(|e| e.name == "My test").unwrap();
        assert!(unsigned.outside_store.as_ref().unwrap().contains("not signed"));
    }

    #[test]
    fn chromium_records_read_the_location_and_fall_back_to_the_manifest_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("Default");
        let manifest_dir = profile.join("Extensions/abcdefghijklmnopabcdefghijklmnop/1.2.0_0");
        std::fs::create_dir_all(&manifest_dir).unwrap();
        std::fs::write(manifest_dir.join("manifest.json"), r#"{"name":"Unpacked Thing","permissions":["nativeMessaging"],"host_permissions":["<all_urls>"]}"#).unwrap();

        let prefs = r#"{"extensions":{"settings":{
            "abcdefghijklmnopabcdefghijklmnop":{"location":4},
            "nmmhkkegccagdldgiimedpiccmgmieda":{"location":5,"manifest":{"name":"Chrome Web Store Payments"}},
            "cjpalhdlnbpafiamejdnhcphjbkeiagm":{"location":1,"from_webstore":true,"manifest":{"name":"uBlock Origin","permissions":["webRequest"]}},
            "pppppppppppppppppppppppppppppppp":{"location":9,"manifest":{"name":"Forced"}}
        }}}"#;
        let found = parse_chromium(prefs, "Chrome", &profile);
        assert_eq!(found.len(), 3);

        let unpacked = found.iter().find(|e| e.name == "Unpacked Thing").unwrap();
        assert!(unpacked.outside_store.as_ref().unwrap().contains("unpacked"));
        assert_eq!(unpacked.broad_permissions, vec!["<all_urls>", "nativeMessaging"]);
        assert!(found.iter().find(|e| e.name == "uBlock Origin").unwrap().outside_store.is_none());
        assert!(found.iter().find(|e| e.name == "Forced").unwrap().outside_store.as_ref().unwrap().contains("policy"));
    }

    #[test]
    fn store_extensions_are_recorded_and_outside_ones_reported_until_accepted() {
        let conn = crate::db::open_memory();
        let mut list = parse_firefox(FIREFOX, "Firefox", "default");

        let first = findings_for(&conn, &list);
        assert_eq!(first.len(), 2, "the two from outside the store, not AdGuard");
        assert!(first.iter().all(|f| f.issue.severity == Severity::Warning));

        // Accepting one keeps it quiet; the other keeps being reported.
        let IssueTarget::Baseline { kind, key, value } = &first[0].target else { panic!() };
        crate::db::set_baseline_value(&conn, kind, key, value).unwrap();
        assert_eq!(findings_for(&conn, &list).len(), 1);

        // A new store extension is mentioned once.
        list.push(Extension {
            browser: "Firefox".into(),
            profile: "default".into(),
            id: "new@store".into(),
            name: "New One".into(),
            outside_store: None,
            broad_permissions: vec![],
        });
        let later = findings_for(&conn, &list);
        assert!(later.iter().any(|f| f.issue.title == "New Firefox extension: New One" && f.issue.severity == Severity::Info));
        assert!(!findings_for(&conn, &list).iter().any(|f| f.issue.title.contains("New One")));
    }

    #[test]
    fn a_broken_record_yields_nothing_rather_than_an_error() {
        assert!(parse_firefox("{not json", "Firefox", "x").is_empty());
        assert!(parse_chromium("[]", "Chrome", Path::new("/nowhere")).is_empty());
    }
}
