//! Whether Windows Defender is doing its job, on Windows.
//!
//! GRT Sentry scans on demand; Defender is what watches in between. A machine
//! where it was switched off, or stopped updating, has lost its guard
//! whatever any scan says, and that is usually the first thing malware does.

use serde::Deserialize;

use crate::platform;
use crate::state::{Action, Finding, Issue, IssueKind, Severity};

/// Signatures older than this have stopped updating.
const STALE_DAYS: u32 = 7;

#[derive(Deserialize, Debug, Default, PartialEq)]
#[serde(rename_all = "PascalCase", default)]
pub struct Status {
    #[serde(rename = "AMRunningMode")]
    pub running_mode: Option<String>,
    pub antivirus_enabled: Option<bool>,
    pub real_time_protection_enabled: Option<bool>,
    pub antivirus_signature_age: Option<u32>,
    pub is_tamper_protected: Option<bool>,
}

pub fn parse(json: &str) -> Option<Status> {
    serde_json::from_str(json.trim()).ok()
}

fn note(severity: Severity, title: &str, detail: &str) -> Finding {
    Finding::note(Issue {
        kind: IssueKind::WeakConfiguration,
        severity,
        title: title.to_string(),
        location: "Windows Defender".to_string(),
        detail: Some(detail.to_string()),
        actions: vec![Action::ignore()],
        ..Default::default()
    })
}

/// What is wrong with Defender's state, if anything.
pub fn judge(status: &Status) -> Vec<Finding> {
    let mode = status.running_mode.as_deref().unwrap_or("Normal");
    if mode.contains("Passive") || mode.contains("Not running") {
        return vec![note(
            Severity::Info,
            "Defender is not the antivirus in charge",
            &format!("Defender runs in \"{mode}\", which Windows sets when another antivirus is installed. That one is now the guard between scans."),
        )];
    }
    let mut out = Vec::new();
    if status.antivirus_enabled == Some(false) {
        out.push(note(
            Severity::Warning,
            "Defender's antivirus is switched off",
            "Nothing checks files between scans. Switching Defender off is the first thing much malware does, so if it was not you, find out what did. Windows Security, Virus and threat protection, turns it back on.",
        ));
    } else if status.real_time_protection_enabled == Some(false) {
        out.push(note(
            Severity::Warning,
            "Defender's real-time protection is off",
            "Files are no longer checked as they arrive. Windows Security, Virus and threat protection, Manage settings, turns it back on; it also switches itself back on after a while unless a policy keeps it off.",
        ));
    }
    if let Some(days) = status.antivirus_signature_age.filter(|d| *d > STALE_DAYS) {
        out.push(note(
            Severity::Warning,
            &format!("Defender's signatures are {days} days old"),
            "They normally update every day through Windows Update. Updates that stopped are a fault worth fixing, and sometimes something blocking them on purpose.",
        ));
    }
    if status.is_tamper_protected == Some(false) {
        out.push(note(
            Severity::Info,
            "Defender's tamper protection is off",
            "With it on, a program running as administrator cannot switch Defender off. It is in Windows Security, Virus and threat protection, Manage settings.",
        ));
    }
    out
}

pub fn findings() -> Vec<Finding> {
    match platform::defender_status() {
        None => Vec::new(),
        Some(Ok(json)) => match parse(&json) {
            Some(status) => judge(&status),
            None => vec![note(Severity::Info, "Defender's state could not be read", "Get-MpComputerStatus answered in a form this program does not know.")],
        },
        Some(Err(e)) => vec![note(Severity::Info, "Defender's state could not be read", &e)],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_healthy_defender_says_nothing() {
        let status = parse(r#"{"AMRunningMode":"Normal","AntivirusEnabled":true,"RealTimeProtectionEnabled":true,"AntivirusSignatureAge":0,"IsTamperProtected":true}"#).unwrap();
        assert!(judge(&status).is_empty());
    }

    #[test]
    fn switched_off_or_stale_is_a_warning() {
        let status = parse(r#"{"AMRunningMode":"Normal","AntivirusEnabled":true,"RealTimeProtectionEnabled":false,"AntivirusSignatureAge":12,"IsTamperProtected":false}"#).unwrap();
        let titles: Vec<String> = judge(&status).iter().map(|f| f.issue.title.clone()).collect();
        assert_eq!(
            titles,
            vec!["Defender's real-time protection is off", "Defender's signatures are 12 days old", "Defender's tamper protection is off"]
        );
    }

    #[test]
    fn another_antivirus_in_charge_is_information() {
        let status = parse(r#"{"AMRunningMode":"Passive Mode","AntivirusEnabled":false,"RealTimeProtectionEnabled":false}"#).unwrap();
        let found = judge(&status);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].issue.severity, Severity::Info);
    }
}
