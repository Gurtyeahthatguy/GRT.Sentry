// The Status tab: one verdict, then the list of things to decide about.

import { api, dialog, listen } from "./api.js";
import { button, clear, el, errorText, formatCount, formatSize, timeAgo, toast } from "./ui.js";

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
  card.append(el("div", "issue-title", report.path.split("/").pop()));
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
    nodes.detail.textContent = "Files, connections, updates, startup entries, logins and system files.";
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
    done: "Finishing",
  }[progress.phase] || progress.phase;

  const counter = progress.total > 0 ? ` ${progress.current}/${progress.total}` : "";
  nodes.progressText.textContent = `${phase}${counter}: ${progress.message}`;
}

function render(status) {
  if (!status) return;

  const serious = status.issues.filter((issue) => issue.severity !== "info");
  const worst = serious.some((issue) => issue.severity === "critical") ? "critical" : "warning";

  if (serious.length === 0) {
    nodes.mark.className = "verdict-mark is-clean";
    nodes.line.textContent = status.last_scan ? "Nothing needs attention" : "Not scanned yet";
    nodes.detail.textContent = status.last_scan
      ? "Files, connections, updates, startup entries, system files and system programs were all checked."
      : "Press Scan now to check this machine.";
  } else {
    nodes.mark.className = `verdict-mark is-${worst}`;
    nodes.line.textContent = `${serious.length} thing${serious.length === 1 ? "" : "s"} need${serious.length === 1 ? "s" : ""} attention`;
    nodes.detail.textContent = "Each one below says what it is and what you can do about it.";
  }

  const parts = [];
  if (status.last_scan) parts.push(`Last scan ${timeAgo(status.last_scan)}`);
  parts.push(`${formatCount(status.files_checked)} files checked`);
  parts.push(`${formatCount(status.active_connections)} connections`);
  if (status.queued_files > 0) parts.push(`${formatCount(status.queued_files)} waiting for a verdict`);
  nodes.counters.textContent = parts.join(" · ");

  clear(nodes.issues);
  if (status.issues.length === 0) return;

  for (const issue of status.issues) {
    nodes.issues.append(renderIssue(issue));
  }
}

function renderIssue(issue) {
  const card = el("div", `issue is-${issue.severity}`);
  card.append(el("div", "issue-title", issue.title));
  card.append(el("div", "issue-location", issue.location));
  if (issue.detail) card.append(el("div", "issue-detail", issue.detail));

  const actions = el("div", "issue-actions");
  const result = el("div", "issue-result");
  result.hidden = true;

  for (const action of issue.actions) {
    actions.append(
      button(action.label, () => act(issue, action, card, result, actions), action.destructive ? "danger" : "")
    );
  }

  card.append(actions, result);
  return card;
}

async function act(issue, action, card, result, actions) {
  if (action.destructive) {
    const confirmed = await dialog.ask(`${action.label}: ${issue.location}\n\nThis cannot be undone.`, {
      title: action.label,
      kind: "warning",
    });
    if (!confirmed) return;
  }

  for (const node of actions.children) node.disabled = true;

  try {
    const message = await api.resolveIssue(issue.id, action.id, null);

    if (action.id === "ignore") {
      card.remove();
      return;
    }

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
