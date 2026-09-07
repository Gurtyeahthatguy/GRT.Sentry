// Startup and the tab strip.

import { api } from "./api.js";
import { initStatus, refreshStatus } from "./status.js";
import { initConnections, load as loadConnections } from "./connections.js";
import { load as loadQuarantine } from "./quarantine.js";
import { initSettings, load as loadSettings } from "./settings.js";
import { errorText, toast } from "./ui.js";

const loaders = {
  status: refreshStatus,
  connections: loadConnections,
  quarantine: loadQuarantine,
  settings: loadSettings,
};

function applyTheme(theme) {
  // "system" sets nothing and lets the stylesheet's media query decide.
  if (theme === "light" || theme === "dark") {
    document.documentElement.setAttribute("data-theme", theme);
  } else {
    document.documentElement.removeAttribute("data-theme");
  }
}

function selectTab(name) {
  for (const tab of document.querySelectorAll(".tab")) {
    tab.classList.toggle("is-active", tab.dataset.tab === name);
  }
  for (const panel of document.querySelectorAll(".panel")) {
    panel.classList.toggle("is-active", panel.id === `panel-${name}`);
  }
  const load = loaders[name];
  if (load) Promise.resolve(load()).catch((error) => toast(errorText(error), true));
}

function initTabs() {
  document.getElementById("tabs").addEventListener("click", (event) => {
    const tab = event.target.closest(".tab");
    if (tab) selectTab(tab.dataset.tab);
  });

  // Ctrl+1 to Ctrl+4 change tab.
  window.addEventListener("keydown", (event) => {
    if (!event.ctrlKey || event.shiftKey || event.altKey) return;
    const index = ["1", "2", "3", "4"].indexOf(event.key);
    if (index === -1) return;
    event.preventDefault();
    selectTab(["status", "connections", "quarantine", "settings"][index]);
  });
}

async function start() {
  initTabs();
  initStatus();
  initConnections();
  initSettings(applyTheme);

  try {
    const config = await api.getConfig();
    applyTheme(config.theme);
  } catch (error) {
    // An unreadable configuration is not a reason to show nothing.
    console.error(error);
  }

  try {
    const info = await api.systemInfo();
    document.getElementById("version").textContent = `version ${info.version}`;
  } catch (error) {
    console.error(error);
  }
}

start();
