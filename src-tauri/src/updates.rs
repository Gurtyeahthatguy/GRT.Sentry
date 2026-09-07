//! Packages with an update waiting.
//!
//! A machine that has not been updated in six months is running published
//! holes with exploits already written for them, which is a likelier problem
//! than an infected file in a download folder.
//!
//! Nothing is installed automatically. The list and the command are shown, and
//! the decision stays with the user.

use crate::platform;
use crate::state::{Action, Finding, Issue, IssueKind, IssueTarget, Severity};

/// One issue for the whole set of pending security updates.
pub fn findings() -> Vec<Finding> {
    if !platform::updates_tool_available() {
        return vec![Finding::note(Issue {
            kind: IssueKind::ModuleUnavailable,
            severity: Severity::Info,
            title: "Update check unavailable".to_string(),
            location: platform::update_tool_name().to_string(),
            detail: Some(format!(
                "This module reads the list of pending updates from {}, which is not installed here. Check for updates the way this system does.",
                platform::update_tool_name()
            )),
            actions: vec![Action::ignore()],
            ..Default::default()
        })];
    }

    let packages = match platform::security_updates() {
        Ok(packages) => packages,
        Err(e) => {
            return vec![Finding::note(Issue {
                kind: IssueKind::ModuleUnavailable,
                severity: Severity::Info,
                title: "Could not read the list of updates".to_string(),
                location: platform::update_tool_name().to_string(),
                detail: Some(e),
                actions: vec![Action::ignore()],
                ..Default::default()
            })];
        }
    };

    let mut findings = Vec::new();

    if !packages.is_empty() {
        let sample: Vec<&str> = packages.iter().take(12).map(|s| s.as_str()).collect();
        let remainder = packages.len().saturating_sub(sample.len());

        let mut detail = format!("{}:\n\n{}", platform::updates_heading(), sample.join(", "));
        if remainder > 0 {
            detail.push_str(&format!(", and {remainder} more"));
        }
        detail.push_str(&format!(
            "\n\nInstall them with:\n\n    {}\n\n\
             GRT Sentry installs nothing itself. The list is only as fresh as the \
             package index, so there may be more than this.",
            platform::update_command()
        ));

        // Ten or more outstanding fixes is not an ordinary state of affairs.
        let severity = if packages.len() >= 10 { Severity::Critical } else { Severity::Warning };

        findings.push(Finding::new(
            Issue {
                kind: IssueKind::OutdatedSecurityPackage,
                severity,
                title: format!(
                    "{} package{} waiting for an update",
                    packages.len(),
                    if packages.len() == 1 { "" } else { "s" }
                ),
                location: "System packages".to_string(),
                detail: Some(detail),
                actions: vec![Action::new("list_packages", "Show the whole list", false), Action::ignore()],
                ..Default::default()
            },
            IssueTarget::Packages { names: packages },
        ));
    }

    if platform::reboot_required() {
        findings.push(Finding::note(Issue {
            kind: IssueKind::OutdatedSecurityPackage,
            severity: Severity::Warning,
            title: "A restart is needed to finish applying updates".to_string(),
            location: "System".to_string(),
            detail: Some(
                "Updates have been installed but are not in use yet, typically a kernel or a library that running programs still hold the old copy of. Until the machine restarts, the fix is on disk and not in effect."
                    .to_string(),
            ),
            actions: vec![Action::ignore()],
            ..Default::default()
        }));
    }

    findings
}
