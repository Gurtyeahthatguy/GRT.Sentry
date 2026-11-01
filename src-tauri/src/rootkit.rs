//! What a rootkit hides, found by asking the kernel twice.
//!
//! A rootkit that filters the process list, the socket table or the module
//! list still has to leave the thing itself working, so a second, more direct
//! question gets an answer the first one did not. A process that answers at
//! /proc/PID but is missing from the listing, a port that cannot be bound but
//! holds no visible socket, a module in /sys/module that /proc/modules leaves
//! out: each is a lie told by something on the machine.
//!
//! Kernel modules built outside the kernel, such as graphics drivers, are
//! ordinary. They are recorded on the first scan and only a new one is
//! reported.

use rusqlite::Connection;

use crate::db;
use crate::platform::{self, HiddenProcess, KernelModules};
use crate::state::{Action, Finding, Issue, IssueKind, IssueTarget, Severity};

const MODULES: &str = "module";

pub fn findings(conn: &Connection) -> Vec<Finding> {
    let mut findings = Vec::new();

    match platform::hidden_processes() {
        Some(hidden) => findings.extend(hidden.iter().map(hidden_process_finding)),
        None => findings.push(unavailable("Hidden processes are not looked for here", platform::SYSTEM_NAME)),
    }

    match platform::hidden_ports() {
        Some(ports) => findings.extend(ports.iter().map(|p| hidden_port_finding(*p))),
        None => findings.push(unavailable("Hidden ports are not looked for here", platform::SYSTEM_NAME)),
    }

    if let Some(modules) = platform::kernel_modules() {
        findings.extend(module_findings(conn, &modules));
    }

    findings
}

fn unavailable(title: &str, system: &str) -> Finding {
    Finding::note(Issue {
        kind: IssueKind::ModuleUnavailable,
        severity: Severity::Info,
        title: title.to_string(),
        location: "Rootkits".to_string(),
        detail: Some(format!(
            "{system} offers no second listing to compare the first against, so this check has nothing to work with."
        )),
        actions: vec![Action::ignore()],
        ..Default::default()
    })
}

fn hidden_process_finding(process: &HiddenProcess) -> Finding {
    Finding::new(
        Issue {
            kind: IssueKind::HiddenActivity,
            severity: Severity::Critical,
            title: format!("A process is hiding: {} (pid {})", process.name, process.pid),
            location: format!("/proc/{}", process.pid),
            detail: Some(format!(
                "The kernel answers for process {} at /proc/{}, and the listing of /proc leaves it out. Nothing legitimate does that: it is what a rootkit that filters directory reads looks like from inside.\n\n\
                 Treat the machine as compromised. Programs on it, this one included, may be lied to in other ways too; investigate from outside it, booted from a live USB.",
                process.pid, process.pid
            )),
            actions: vec![Action::ignore()],
            ..Default::default()
        },
        IssueTarget::Informational,
    )
}

fn hidden_port_finding(port: u16) -> Finding {
    Finding::new(
        Issue {
            kind: IssueKind::HiddenActivity,
            severity: Severity::Critical,
            title: format!("A port is held by nothing visible: TCP {port}"),
            location: format!("TCP port {port}"),
            detail: Some(format!(
                "Binding TCP port {port} fails because something holds it, and no socket in the kernel's table uses it, checked twice. A program that listens and hides its socket is a backdoor waiting for a connection.\n\n\
                 Treat the machine as compromised and investigate from outside it."
            )),
            actions: vec![Action::ignore()],
            ..Default::default()
        },
        IssueTarget::Informational,
    )
}

/// Hidden modules always; modules built outside the kernel when they are new.
pub fn module_findings(conn: &Connection, modules: &KernelModules) -> Vec<Finding> {
    let mut findings = Vec::new();
    let first_run = !db::baseline_started(conn, MODULES);

    for (name, taint) in &modules.sysfs {
        if !modules.listed.iter().any(|l| l == name) {
            findings.push(Finding::new(
                Issue {
                    kind: IssueKind::HiddenActivity,
                    severity: Severity::Critical,
                    title: format!("A kernel module is hiding: {name}"),
                    location: format!("/sys/module/{name}"),
                    detail: Some(format!(
                        "{name} is loaded, as /sys/module shows, and missing from /proc/modules, the list every tool reads. Removing itself from that list is the first thing a kernel rootkit does.\n\n\
                         Treat the machine as compromised and investigate from outside it."
                    )),
                    actions: vec![Action::ignore()],
                    ..Default::default()
                },
                IssueTarget::Informational,
            ));
            continue;
        }

        // O is out of tree and E unsigned; the rest is the kernel's own.
        if !taint.contains('O') && !taint.contains('E') {
            continue;
        }
        if db::baseline_value(conn, MODULES, name).is_some() {
            continue;
        }
        if first_run {
            let _ = db::set_baseline_value(conn, MODULES, name, taint);
            continue;
        }
        let unsigned = taint.contains('E');
        findings.push(Finding::new(
            Issue {
                kind: IssueKind::KernelModule,
                severity: if unsigned { Severity::Critical } else { Severity::Warning },
                title: format!("New kernel module from outside the kernel: {name}"),
                location: format!("/sys/module/{name}"),
                detail: Some(format!(
                    "{name} was built outside the kernel{} and was not loaded at the last scan. A new graphics or virtualisation driver explains it; otherwise code running inside the kernel is the most dangerous kind there is.\n\n\
                     modinfo {name} says where its file is and who signed it.",
                    if unsigned { ", carries no valid signature," } else { "" }
                )),
                actions: vec![Action::new("trust", "Expected", false), Action::ignore()],
                ..Default::default()
            },
            IssueTarget::Baseline { kind: MODULES.to_string(), key: name.clone(), value: taint.clone() },
        ));
    }

    if first_run {
        let _ = db::mark_baseline_started(conn, MODULES);
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn modules(listed: &[&str], sysfs: &[(&str, &str)]) -> KernelModules {
        KernelModules {
            listed: listed.iter().map(|s| s.to_string()).collect(),
            sysfs: sysfs.iter().map(|(n, t)| (n.to_string(), t.to_string())).collect(),
        }
    }

    #[test]
    fn a_module_missing_from_the_list_is_a_rootkit() {
        let conn = crate::db::open_memory();
        let found = module_findings(&conn, &modules(&["ext4"], &[("ext4", ""), ("diamorphine", "OE")]));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].issue.kind, IssueKind::HiddenActivity);
        assert_eq!(found[0].issue.severity, Severity::Critical);
    }

    #[test]
    fn drivers_built_outside_the_kernel_are_recorded_once_and_new_ones_reported() {
        let conn = crate::db::open_memory();
        let today = modules(&["nvidia", "ext4"], &[("nvidia", "PO"), ("ext4", "")]);
        assert!(module_findings(&conn, &today).is_empty(), "the first scan records");
        assert!(module_findings(&conn, &today).is_empty(), "the second has nothing new");

        let tomorrow = modules(&["nvidia", "ext4", "vboxdrv", "sneaky"], &[("nvidia", "PO"), ("ext4", ""), ("vboxdrv", "O"), ("sneaky", "OE")]);
        let found = module_findings(&conn, &tomorrow);
        assert_eq!(found.len(), 2);
        let sneaky = found.iter().find(|f| f.issue.title.contains("sneaky")).unwrap();
        assert_eq!(sneaky.issue.severity, Severity::Critical, "unsigned as well as out of tree");
        let vbox = found.iter().find(|f| f.issue.title.contains("vboxdrv")).unwrap();
        assert_eq!(vbox.issue.severity, Severity::Warning);
    }

    #[test]
    fn a_machine_with_no_modules_outside_the_kernel_still_starts_its_baseline() {
        let conn = crate::db::open_memory();
        module_findings(&conn, &modules(&["ext4"], &[("ext4", "")]));
        let later = modules(&["ext4", "new"], &[("ext4", ""), ("new", "O")]);
        assert_eq!(module_findings(&conn, &later).len(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn on_this_machine_nothing_is_hidden() {
        assert_eq!(platform::hidden_processes().map(|h| h.len()), Some(0));
        let modules = platform::kernel_modules().unwrap();
        assert!(modules.sysfs.iter().all(|(n, _)| modules.listed.contains(n)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_port_held_by_a_visible_listener_is_not_hidden() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        if port < platform::hidden_port_floor() {
            return;
        }
        let hidden = platform::hidden_ports().unwrap();
        assert!(!hidden.contains(&port));
    }
}
