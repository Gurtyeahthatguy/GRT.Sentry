// The Connections tab: what this machine is talking to.

import { api, dialog } from "./api.js";
import { button, clear, el, errorText, paginate, toast } from "./ui.js";

const PAGE_SIZE = 60;

let all = [];
let timer = null;

export function initConnections() {
  document.getElementById("btn-refresh-connections").addEventListener("click", () => load());
  document.getElementById("connection-filter").addEventListener("input", draw);
  document.getElementById("hide-private").addEventListener("change", draw);
}

/** Reads the current sockets, when the tab is opened. */
export async function load() {
  try {
    all = await api.listConnections();
    draw();
  } catch (error) {
    toast(errorText(error), true);
  }
}

/**
 * Starts or stops the optional refresh.
 *
 * Zero means never, which is the default.
 */
export function setAutoRefresh(seconds) {
  clearInterval(timer);
  timer = null;
  if (seconds > 0) {
    timer = setInterval(() => {
      if (document.getElementById("panel-connections").classList.contains("is-active")) load();
    }, seconds * 1000);
  }
}

function draw() {
  const body = document.getElementById("connections-body");
  const pager = document.getElementById("connections-pager");
  const needle = document.getElementById("connection-filter").value.trim().toLowerCase();
  const hidePrivate = document.getElementById("hide-private").checked;

  const rows = all.filter((c) => {
    if (hidePrivate && c.private) return false;
    if (!needle) return true;
    const haystack = [
      c.process_name || "",
      c.remote_addr,
      String(c.remote_port),
      c.state,
      c.location ? `${c.location.city || ""} ${c.location.country || ""}` : "",
    ]
      .join(" ")
      .toLowerCase();
    return haystack.includes(needle);
  });

  document.getElementById("connection-count").textContent =
    `${rows.length} of ${all.length} sockets`;

  paginate(rows, PAGE_SIZE, pager, (page) => {
    clear(body);
    if (page.length === 0) {
      const row = el("tr");
      const cell = el("td", "empty", "Nothing to show.");
      cell.colSpan = 6;
      row.append(cell);
      body.append(row);
      return;
    }
    for (const connection of page) body.append(renderRow(connection));
  });
}

function renderRow(c) {
  const row = el("tr");

  const process = el("td", null, c.process_name || "unidentified");
  if (c.pid) process.append(el("span", "badge", `pid ${c.pid}`));
  row.append(process);

  const address = el("td", "mono", c.remote_addr);
  if (c.is_new) address.append(el("span", "badge is-new", "new"));
  if (c.trusted && !c.private) address.append(el("span", "badge is-trusted", "trusted"));
  if (c.private) address.append(el("span", "badge", "local"));
  row.append(address);

  row.append(el("td", "mono", `${c.remote_port}/${c.protocol}`));
  row.append(el("td", null, c.state));

  const place = c.location
    ? `${c.location.city ? `${c.location.city}, ` : ""}${c.location.country || ""} · ${c.location.lat.toFixed(2)}, ${c.location.lon.toFixed(2)}`
    : c.private
      ? "local network"
      : "not known";
  row.append(el("td", null, place));

  const actions = el("td");

  // Ends one conversation and leaves the program running. The kernel does it,
  // which needs administrator rights, so a dialog appears.
  actions.append(
    button(
      "Close",
      async () => {
        const confirmed = await dialog.ask(
          `Close the connection from ${c.process_name || "an unidentified process"} to ${c.remote_addr}:${c.remote_port}?\n\n` +
            "The program stays running and may open a new one straight away. To stop that, block the address.",
          { title: "Close connection", kind: "warning" }
        );
        if (!confirmed) return;

        try {
          toast(
            await api.closeConnection({
              protocol: c.protocol,
              local_addr: c.local_addr,
              local_port: c.local_port,
              remote_addr: c.remote_addr,
              remote_port: c.remote_port,
            })
          );
          load();
        } catch (error) {
          toast(errorText(error), true);
        }
      },
      "danger"
    )
  );

  if (!c.private && !c.trusted) {
    actions.append(
      button("Trust", async () => {
        try {
          await api.trustIp(c.remote_addr, c.process_name || null);
          toast(`${c.remote_addr} will not be reported again.`);
          load();
        } catch (error) {
          toast(errorText(error), true);
        }
      })
    );
  }
  row.append(actions);

  return row;
}
