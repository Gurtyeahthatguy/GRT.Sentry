// The Status tab: one verdict, then the list of things to decide about.

import { api, dialog, listen } from "./api.js";
import {
  askWhereToSave,
  button,
  clear,
  dateStamp,
  el,
  errorText,
  formatCount,
  formatSize,
  timeAgo,
  toast,
} from "./ui.js";

let scanning = false;

const nodes = {};

export function initStatus() {
  nodes.mark = document.getElementById("verdict-mark");
  nodes.line = document.getElementById("verdict-line");
  nodes.detail = document.getElementById("verdict-detail");
  nodes.counters = document.getElementById("counters");
  nodes.issues = document.getElementById("issues");
  nodes.progress = document.getElementById("progress");
  nodes.progressFill = document.getElementById("progress-fill");
  nodes.progressText = document.getElementById("progress-text");
  nodes.scan = document.getElementById("btn-scan");
  nodes.cancel = document.getElementById("btn-cancel");

  nodes.scan.addEventListener("click", () => runScan(() => api.quickScan()));
  nodes.cancel.addEventListener("click", () => api.cancelScan());

  document.getElementById("btn-scan-folder").addEventListener("click", scanFolder);
  document.getElementById("btn-scan-file").addEventListener("click", checkOneFile);

  listen("scan-progress", (event) => showProgress(event.payload));
  listen("scan-finished", (event) => {
    setScanning(false);
    render(event.payload);
  });
  listen("scan-failed", (event) => {
    setScanning(false);
    toast(errorText(event.payload), true);
  });

  // A scan started at launch by the backend shows up through these events.
  listen("file-appeared", (event) => {
    toast(`Something new arrived: ${event.payload}`);
  });
  listen("decoy-touched", (event) => {
    toast(`${event.payload.ip} knocked on the decoy port ${event.payload.port}.`, true);
  });

  api.currentStatus().then(render).catch(() => {});
}

export function refreshStatus() {
  return api.currentStatus().then(render).catch(() => {});
}

async function runScan(start) {
  if (scanning) return;
  setScanning(true);
  try {
    render(await start());
  } catch (error) {
    toast(errorText(error), true);
  } finally {
    setScanning(false);
  }
}

async function scanFolder() {
  const chosen = await dialog.open({ directory: true, multiple: false, title: "Choose a folder to scan" });
  if (!chosen) return;
  runScan(() => api.fullScan([chosen]));
}

async function checkOneFile() {
  const chosen = await dialog.open({ multiple: false, title: "Choose a file to check" });
  if (!chosen) return;

  toast("Reading the file and checking it…");
  try {
    const report = await api.scanFile(chosen);
    describeFileReport(report);
  } catch (error) {
    toast(errorText(error), true);
  }
}

function describeFileReport(report) {
  clear(nodes.issues);

  const card = el("div", "issue is-info");
  card.append(el("div", "issue-title", report.path.split(/[\\/]/).pop()));
  card.append(el("div", "issue-location", report.path));

  const lines = [];
  if (report.trusted) {
    lines.push("You have marked this file as trusted, so it is not reported.");
  }

  if (report.rule_hits.length === 0) {
    lines.push("No rule matches it.");
  } else {
    const count = report.rule_hits.length;
    lines.push(`${count} rule${count === 1 ? "" : "s"} match${count === 1 ? "es" : ""} it.`);
  }
  if (report.members > 0) {
    lines.push(`It is an archive, and ${formatCount(report.members)} file${report.members === 1 ? " was" : "s were"} looked at inside.`);
  }
  for (const sentence of report.unchecked) lines.push(sentence);

  if (!report.asked_virustotal) {
    lines.push("VirusTotal was not asked, because no API key is set.");
  } else if (!report.known) {
    lines.push("VirusTotal has never seen this file. That is normal for something you made yourself.");
  } else if (report.malicious === 0) {
    lines.push(report.total ? `No engine flags it, out of ${report.total}.` : "No engine flags it.");
  } else {
    lines.push(
      report.total ? `${report.malicious} of ${report.total} engines flag it.` : `${report.malicious} engines flag it.`
    );
  }

  lines.push(formatSize(report.size), `SHA-256: ${report.sha256}`);
  card.append(el("div", "issue-detail", lines.join("\n")));
  nodes.issues.append(card);

  if (report.issue) {
    nodes.issues.append(renderIssue(report.issue));
  }
}

function setScanning(value) {
  scanning = value;
  nodes.scan.disabled = value;
  nodes.cancel.hidden = !value;
  nodes.progress.hidden = !value;

  if (value) {
    nodes.mark.className = "verdict-mark is-working";
    nodes.line.textContent = "Checking…";
    nodes.detail.textContent = "Files, connections, processes, startup entries, logins, extensions and the system itself.";
  } else {
    nodes.progressFill.style.width = "0";
    nodes.progressText.textContent = "";
  }
}

function showProgress(progress) {
  if (!scanning) setScanning(true);

  const percent = progress.total > 0 ? Math.round((progress.current / progress.total) * 100) : 0;
  nodes.progressFill.style.width = `${percent}%`;

  const phase = {
    collecting: "Looking for files",
    hashing: "Reading",
    checking: "Asking VirusTotal",
    connections: "Connections",
    updates: "Updates",
    autostart: "Startup entries",
    logins: "Logins",
    integrity: "System files",
    packages: "System programs",
    processes: "Processes",
    extensions: "Browser extensions",
    rootkits: "Rootkits",
    privileges: "Privileged files",
    folders: "System folders",
    settings: "Settings that matter",
    done: "Finishing",
  }[progress.phase] || progress.phase;

  const counter = progress.total > 0 ? ` ${progress.current}/${progress.total}` : "";
  nodes.progressText.textContent = `${phase}${counter}: ${progress.message}`;
}

function render(status) {
  if (!status) return;

  const serious = status.issues.filter((issue) => issue.severity !== "info" && !issue.set_aside);
  const aside = status.issues.filter((issue) => issue.set_aside);
  const worst = serious.some((issue) => issue.severity === "critical") ? "critical" : "warning";

  if (serious.length === 0) {
    nodes.mark.className = "verdict-mark is-clean";
    nodes.line.textContent = status.last_scan ? "Nothing needs attention" : "Not scanned yet";
    nodes.detail.textContent = status.last_scan
      ? "Files, connections, processes, startup entries, logins, extensions and the system itself were all checked."
      : "Press Scan now to check this machine.";
  } else {
    nodes.mark.className = `verdict-mark is-${worst}`;
    nodes.line.textContent = `${serious.length} thing${serious.length === 1 ? "" : "s"} need${serious.length === 1 ? "s" : ""} attention`;
    const fresh = status.new_issues || 0;
    nodes.detail.textContent =
      fresh === 0
        ? "None of them is new: earlier scans reported each one. Each says what it is and what you can do."
        : `${fresh === serious.length ? "All" : fresh} new since the last scan. Each one below says what it is and what you can do about it.`;
  }

  const parts = [];
  if (status.last_scan) parts.push(`Last scan ${timeAgo(status.last_scan)}`);
  parts.push(`${formatCount(status.files_checked)} files checked`);
  parts.push(`${formatCount(status.active_connections)} connections`);
  if (status.queued_files > 0) parts.push(`${formatCount(status.queued_files)} waiting for a verdict`);
  if (status.changes > 0) parts.push(`${formatCount(status.changes)} changes on the machine since the scan before, in History`);
  nodes.counters.textContent = parts.join(" · ");

  clear(nodes.issues);
  if (status.issues.length === 0) return;

  for (const issue of status.issues.filter((i) => !i.set_aside)) {
    nodes.issues.append(renderIssue(issue));
  }

  // Still there, still counted in the history, never in the verdict.
  if (aside.length > 0) {
    const group = el("details", "aside-group");
    group.append(el("summary", null, `Set aside (${aside.length})`));
    for (const issue of aside) group.append(renderIssue(issue));
    nodes.issues.append(group);
  }
}

/** "New", or how long it has been reported. */
function history(issue) {
  if (!issue.times_seen) return null;
  if (issue.times_seen <= 1) return el("span", "badge is-new", "new");
  const age = Date.now() / 1000 - issue.first_seen;
  const since = age < 86400 ? `first ${timeAgo(issue.first_seen)}` : `since ${new Date(issue.first_seen * 1000).toLocaleDateString()}`;
  return el("span", "badge", `seen in ${issue.times_seen} scans, ${since}`);
}

function renderIssue(issue) {
  const card = el("div", `issue is-${issue.severity}${issue.set_aside ? " is-aside" : ""}`);
  const title = el("div", "issue-title", issue.title);
  const seen = history(issue);
  if (seen) title.append(seen);
  card.append(title);
  card.append(el("div", "issue-location", issue.location));
  if (issue.detail) card.append(el("div", "issue-detail", issue.detail));

  const actions = el("div", "issue-actions");
  const result = el("div", "issue-result");
  result.hidden = true;

  const offered = issue.set_aside
    ? [{ id: "bring_back", label: "Bring back", destructive: false }]
    : issue.actions;
  for (const action of offered) {
    actions.append(
      button(action.label, () => act(issue, action, card, result, actions), action.destructive ? "danger" : "")
    );
  }
  if (issue.kind !== "module_unavailable") {
    actions.append(button("Save as evidence…", () => saveEvidence(issue)));
  }

  card.append(actions, result);
  return card;
}

async function saveEvidence(issue) {
  const path = await askWhereToSave(
    dialog,
    "Save the evidence",
    `grt-sentry-evidence-${dateStamp()}.zip`,
    "zip",
    "ZIP archive"
  );
  if (!path) return;
  try {
    toast(await api.exportEvidence(issue.id, path));
  } catch (error) {
    toast(errorText(error), true);
  }
}

async function act(issue, action, card, result, actions) {
  if (action.destructive) {
    const consequence = {
      block_ip: "It can be lifted from the action log in the Quarantine tab.",
      upload_vt:
        "The file's contents go to VirusTotal, which keeps them and shares them with security companies. That cannot be taken back.",
    }[action.id] || "This cannot be undone.";
    const confirmed = await dialog.ask(`${action.label}: ${issue.location}\n\n${consequence}`, {
      title: action.label,
      kind: "warning",
    });
    if (!confirmed) return;
  }

  for (const node of actions.children) node.disabled = true;

  try {
    const message = await api.resolveIssue(issue.id, action.id, null);

    // "Show the whole list" answers in place and resolves nothing.
    if (action.id === "list_packages") {
      result.hidden = false;
      result.className = "issue-result";
      result.textContent = message;
      for (const node of actions.children) node.disabled = false;
      return;
    }

    // Everything else redraws the list without the issue, so the confirmation
    // goes to the toast, which outlives the card.
    toast(message);
    refreshStatus();
  } catch (error) {
    result.hidden = false;
    result.className = "issue-result is-error";
    result.textContent = errorText(error);
    for (const node of actions.children) node.disabled = false;
  }
}
