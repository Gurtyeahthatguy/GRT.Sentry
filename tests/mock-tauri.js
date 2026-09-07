// A stand-in for the Tauri runtime, so the interface can be opened in an
// ordinary browser with plausible data in it.
//
// Run it with scripts/preview-ui.sh, which injects it into a copy of src/.
// It is never part of a build: src/index.html does not reference it.
const now = Math.floor(Date.now() / 1000);

const status = {
  clean: false,
  last_scan: now - 120,
  files_checked: 1204,
  active_connections: 14,
  queued_files: 37,
  issues: [
    {
      id: "a", kind: "malicious_file", severity: "critical",
      title: "Malicious file: flagged by 34 engines",
      location: "/home/user/Downloads/setup_installer.exe",
      detail: "34 of 71 engines call this file malicious. At this level it is not a difference of opinion between scanners.",
      actions: [
        { id: "quarantine", label: "Quarantine", destructive: false },
        { id: "delete", label: "Delete", destructive: true },
        { id: "trust", label: "Trust this file", destructive: false },
        { id: "ignore", label: "Ignore", destructive: false },
      ],
    },
    {
      id: "b", kind: "suspicious_connection", severity: "warning",
      title: "Connection to an address seen for the first time",
      location: "node (pid 4821) to 185.220.101.7:9001",
      detail: "The address is announced from Amsterdam, Netherlands (52.37, 4.89). That is where the network routing the connection is registered, not where a person is.\nPort 9001 is not one of the ports everyday software normally uses.",
      actions: [
        { id: "close_connection", label: "Close connection", destructive: true },
        { id: "block_ip", label: "Block address", destructive: true },
        { id: "kill_process", label: "Stop process", destructive: true },
        { id: "trust", label: "Trust", destructive: false },
        { id: "ignore", label: "Ignore", destructive: false },
      ],
    },
    {
      id: "c", kind: "module_unavailable", severity: "info",
      title: "No VirusTotal API key is set",
      location: "GRT Sentry",
      detail: "Files were hashed but not checked against any engine.",
      actions: [{ id: "ignore", label: "Ignore", destructive: false }],
    },
  ],
};

const connections = Array.from({ length: 130 }, (_, i) => ({
  protocol: i % 3 === 0 ? "udp" : "tcp",
  local_addr: "192.168.1.20", local_port: 40000 + i,
  remote_addr: i % 4 === 0 ? "192.168.1.1" : `185.220.101.${i % 250}`,
  remote_port: [443, 80, 53, 9001][i % 4],
  state: "Established",
  pid: i % 5 === 0 ? null : 4800 + i,
  process_name: i % 5 === 0 ? null : ["firefox", "node", "curl", "thunderbird"][i % 4],
  location: i % 4 === 0 ? null : { lat: 52.37, lon: 4.89, city: "Amsterdam", country: "Netherlands", country_code: "NL" },
  is_new: i % 7 === 0, trusted: i % 11 === 0, private: i % 4 === 0, label: null,
}));

const responses = {
  quick_scan: status,
  full_scan: status,
  current_status: status,
  cancel_scan: null,
  list_connections: connections,
  list_quarantine: [{
    id: "q1", original_path: "/home/user/Downloads/dodgy.run",
    quarantine_path: "/home/user/.local/share/grt-sentry/quarantine/q1.bin",
    sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    quarantined_at: now - 8000, reason: "flagged by 34 engines", original_mode: 493,
  }],
  list_action_log: [
    { id: 2, timestamp: now - 7000, action: "quarantine", target: "/home/user/Downloads/dodgy.run", reason: "flagged", reversible: true, reverted: false, description: "Quarantined /home/user/Downloads/dodgy.run" },
    { id: 1, timestamp: now - 9000, action: "block_ip", target: "185.220.101.7", reason: null, reversible: true, reverted: true, description: "Blocked 185.220.101.7" },
  ],
  list_allowlist: [{ sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", label: "my own build", added_at: now - 90000 }],
  list_trusted_ips: [{ ip: "1.1.1.1", first_seen: now - 900000, last_seen: now, label: "resolver", trusted: true }],
  get_config: {
    api_key_set: true, api_key_hint: "…5678",
    scan_paths: ["/home/user/Downloads", "/home/user/Desktop", "/tmp"],
    max_file_size_mb: 100, deep_scan: false, auto_quarantine: false, auto_quarantine_threshold: 10,
    vt_interval_seconds: 15, vt_budget_per_scan: 40, connection_refresh_seconds: 0, watch_folders: false,
    integrity_paths: ["/etc/passwd", "/etc/hosts"], auth_log_path: "/var/log/auth.log",
    failed_login_threshold: 5, scan_on_startup: true, theme: "system",
  },
  system_info: {
    version: "0.1.0", system: "Linux",
    geoip_available: true, geoip_path: "/usr/share/grt-sentry/GeoLite2-City.mmdb",
    elevation_available: true, elevation_note: "pkexec", elevated: false,
    firewall_available: true, firewall_note: "nftables, through scripts/setup-nftables.sh",
    database_path: "/home/user/.local/share/grt-sentry/sentry.db",
    config_path: "/home/user/.config/grt-sentry/config.toml",
    quarantine_path: "/home/user/.local/share/grt-sentry/quarantine",
    cached_files: 2519, quarantined_files: 1,
    recent_scans: [{ timestamp: now - 120, files_checked: 1204, issues_found: 2 }],
    schedule: { installed: true, enabled: true, frequency: "daily", next_run: "Tue 03:00", supported: true },
    watched_folders: [],
  },
  close_connection: "The connection to 185.220.101.7:443 is closed.",
  resolve_issue: "Done.",
  set_config: null,
};

window.__TAURI__ = {
  core: {
    invoke: (name, args) => {
      window.__calls = window.__calls || [];
      window.__calls.push([name, args]);
      if (name === "set_config") return Promise.resolve(responses.get_config);
      return Promise.resolve(responses[name] === undefined ? null : responses[name]);
    },
  },
  event: { listen: () => Promise.resolve(() => {}) },
  dialog: { open: () => Promise.resolve(null), ask: () => Promise.resolve(true), message: () => Promise.resolve() },
};
