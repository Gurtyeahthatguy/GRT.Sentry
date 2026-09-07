// The Settings tab, and the facts about this installation underneath it.

import { api } from "./api.js";
import { clear, el, errorText, formatCount, formatTime, toast } from "./ui.js";
import { setAutoRefresh } from "./connections.js";

let current = null;

export function initSettings(onThemeChange) {
  document.getElementById("btn-save-settings").addEventListener("click", () => save(onThemeChange));
  document.getElementById("btn-save-key").addEventListener("click", saveKey);
  document.getElementById("btn-clear-key").addEventListener("click", clearKey);
  document.getElementById("btn-save-schedule").addEventListener("click", saveSchedule);
  document.getElementById("watch-folders").addEventListener("change", toggleWatcher);
}

export async function load() {
  try {
    current = await api.getConfig();
    fill(current);
  } catch (error) {
    toast(errorText(error), true);
  }
  await loadFacts();
}

function fill(config) {
  document.getElementById("api-key").value = "";
  document.getElementById("api-key-hint").textContent = config.api_key_set
    ? `A key is set, ending ${config.api_key_hint}. Type a new one to replace it.`
    : "No key is set. The file scanner is the only module that needs one; everything else works without.";

  document.getElementById("vt-interval").value = config.vt_interval_seconds;
  document.getElementById("vt-budget").value = config.vt_budget_per_scan;
  document.getElementById("scan-paths").value = config.scan_paths.join("\n");
  document.getElementById("max-size").value = config.max_file_size_mb;
  document.getElementById("deep-scan").checked = config.deep_scan;
  document.getElementById("scan-on-startup").checked = config.scan_on_startup;
  document.getElementById("watch-folders").checked = config.watch_folders;
  document.getElementById("auto-quarantine").checked = config.auto_quarantine;
  document.getElementById("auto-threshold").value = config.auto_quarantine_threshold;
  document.getElementById("auth-log").value = config.auth_log_path;
  document.getElementById("login-threshold").value = config.failed_login_threshold;
  document.getElementById("integrity-paths").value = config.integrity_paths.join("\n");
  document.getElementById("refresh-seconds").value = config.connection_refresh_seconds;
  document.getElementById("theme").value = config.theme;

  setAutoRefresh(config.connection_refresh_seconds);
}

function lines(id) {
  return document
    .getElementById(id)
    .value.split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

function number(id) {
  const value = Number(document.getElementById(id).value);
  return Number.isFinite(value) ? value : undefined;
}

async function save(onThemeChange) {
  const update = {
    scan_paths: lines("scan-paths"),
    integrity_paths: lines("integrity-paths"),
    max_file_size_mb: number("max-size"),
    deep_scan: document.getElementById("deep-scan").checked,
    scan_on_startup: document.getElementById("scan-on-startup").checked,
    auto_quarantine: document.getElementById("auto-quarantine").checked,
    auto_quarantine_threshold: number("auto-threshold"),
    vt_interval_seconds: number("vt-interval"),
    vt_budget_per_scan: number("vt-budget"),
    connection_refresh_seconds: number("refresh-seconds"),
    auth_log_path: document.getElementById("auth-log").value.trim(),
    failed_login_threshold: number("login-threshold"),
    theme: document.getElementById("theme").value,
  };

  try {
    current = await api.setConfig(update);
    fill(current);
    onThemeChange(current.theme);
    document.getElementById("settings-saved").textContent = "Saved.";
    setTimeout(() => {
      document.getElementById("settings-saved").textContent = "";
    }, 2500);
  } catch (error) {
    toast(errorText(error), true);
  }
}

// The key travels on its own, so a stray click on Save cannot wipe it.
async function saveKey() {
  const key = document.getElementById("api-key").value.trim();
  if (!key) {
    toast("Type the key first.", true);
    return;
  }
  try {
    current = await api.setConfig({ virustotal_api_key: key });
    fill(current);
    toast("Key saved. It is kept in a file only you can read.");
  } catch (error) {
    toast(errorText(error), true);
  }
}

async function clearKey() {
  try {
    current = await api.setConfig({ virustotal_api_key: "" });
    fill(current);
    toast("Key removed.");
  } catch (error) {
    toast(errorText(error), true);
  }
}

async function toggleWatcher(event) {
  const enabled = event.target.checked;
  try {
    await api.setWatcher(enabled);
    toast(enabled ? "Watching the scan folders." : "No longer watching.");
  } catch (error) {
    event.target.checked = false;
    toast(errorText(error), true);
  }
  loadFacts();
}

async function saveSchedule() {
  const choice = document.getElementById("schedule-frequency").value;
  try {
    const status = await api.setSchedule(choice !== "off", choice === "off" ? null : choice);
    showSchedule(status);
    toast(choice === "off" ? "Scheduled scan switched off." : `Scheduled scan set to ${choice}.`);
  } catch (error) {
    toast(errorText(error), true);
  }
}

function showSchedule(schedule) {
  const node = document.getElementById("schedule-status");
  const select = document.getElementById("schedule-frequency");

  if (!schedule.supported) {
    node.textContent = "This system has no systemd user session, so a scheduled scan cannot be installed from here.";
    select.disabled = true;
    return;
  }

  select.value = schedule.enabled && schedule.frequency ? schedule.frequency : "off";
  node.textContent = schedule.enabled
    ? `On${schedule.next_run ? `. Next: ${schedule.next_run}` : "."} The scan runs without a window and sends a notification only if something needs attention.`
    : "Off. A scheduled scan runs the same checks in the background and notifies you only when something is found.";
}

async function loadFacts() {
  const list = document.getElementById("system-facts");
  clear(list);

  let info;
  try {
    info = await api.systemInfo();
  } catch (error) {
    list.append(el("dt", null, "error"), el("dd", null, errorText(error)));
    return;
  }

  showSchedule(info.schedule);

  const facts = [
    ["version", info.version],
    ["system", info.system],
    ["database", info.database_path],
    ["configuration", info.config_path],
    ["quarantine", info.quarantine_path],
    ["files in cache", formatCount(info.cached_files)],
    ["files in quarantine", formatCount(info.quarantined_files)],
    ["geolocation data", info.geoip_available ? info.geoip_path : "not installed, so connections show no place"],
    [
      "firewall",
      info.firewall_available
        ? info.firewall_note
        : `${info.firewall_note} is not available, so blocking an address will not work`,
    ],
    [
      "administrator rights",
      info.elevation_available
        ? info.elevation_note
        : `not available: ${info.elevation_note}. Blocking an address and closing a connection need it.`,
    ],
    [
      "folder watcher",
      info.watched_folders.length > 0 ? `watching ${info.watched_folders.join(", ")}` : "off",
    ],
  ];

  for (const [name, value] of facts) {
    list.append(el("dt", null, name), el("dd", null, value));
  }

  if (info.recent_scans.length > 0) {
    const recent = info.recent_scans
      .slice(0, 5)
      .map((scan) => `${formatTime(scan.timestamp)}: ${scan.files_checked} files, ${scan.issues_found} issues`)
      .join("\n");
    list.append(el("dt", null, "recent scans"), el("dd", null, recent));
  }
}
