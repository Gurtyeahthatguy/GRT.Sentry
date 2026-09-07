// The only place that talks to the backend.
//
// Nothing here reaches the filesystem or the network. The webview has no
// permission to, and neither the HTTP nor the shell plugin is compiled into
// the binary.

const { invoke } = window.__TAURI__.core;
export const { listen } = window.__TAURI__.event;
export const dialog = window.__TAURI__.dialog;

export const api = {
  quickScan: () => invoke("quick_scan"),
  fullScan: (paths) => invoke("full_scan", { paths }),
  cancelScan: () => invoke("cancel_scan"),
  currentStatus: () => invoke("current_status"),
  scanFile: (path) => invoke("scan_file", { path }),

  listConnections: () => invoke("list_connections"),
  closeConnection: (socket) => invoke("close_connection", { socket }),

  resolveIssue: (issueId, action, note) => invoke("resolve_issue", { issueId, action, note }),

  listQuarantine: () => invoke("list_quarantine"),
  restoreFromQuarantine: (id) => invoke("restore_from_quarantine", { id }),
  deleteFromQuarantine: (id) => invoke("delete_from_quarantine", { id }),

  trustIp: (ip, label) => invoke("trust_ip", { ip, label }),
  untrustIp: (ip) => invoke("untrust_ip", { ip }),
  listTrustedIps: () => invoke("list_trusted_ips"),

  listAllowlist: () => invoke("list_allowlist"),
  removeFromAllowlist: (sha256) => invoke("remove_from_allowlist", { sha256 }),

  listActionLog: (limit) => invoke("list_action_log", { limit }),
  revertAction: (id) => invoke("revert_action", { id }),

  listAutostart: () => invoke("list_autostart"),

  getConfig: () => invoke("get_config"),
  setConfig: (update) => invoke("set_config", { update }),
  systemInfo: () => invoke("system_info"),
  setSchedule: (enabled, frequency) => invoke("set_schedule", { enabled, frequency }),
  setWatcher: (enabled) => invoke("set_watcher", { enabled }),
};
