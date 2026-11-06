// The Quarantine tab: isolated files, what has been done, and what is trusted.

import { api, dialog } from "./api.js";
import {
  askWhereToSave,
  button,
  clear,
  dateStamp,
  el,
  errorText,
  formatCount,
  formatSize,
  formatTime,
  timeAgo,
  toast,
} from "./ui.js";

export async function load() {
  await Promise.all([loadQuarantine(), loadLog(), loadAllowlist(), loadTrustedIps()]);
}

async function loadQuarantine() {
  const container = document.getElementById("quarantine-list");
  clear(container);

  let entries = [];
  try {
    entries = await api.listQuarantine();
  } catch (error) {
    container.append(el("div", "empty", errorText(error)));
    return;
  }

  if (entries.length === 0) {
    container.append(el("div", "empty", "Nothing is in quarantine."));
    return;
  }

  for (const entry of entries) {
    const card = el("div", "card");
    const main = el("div", "card-main");
    main.append(el("div", "card-title", entry.original_path));
    main.append(
      el(
        "div",
        "card-sub",
        `${timeAgo(entry.quarantined_at)} · ${entry.reason || "no reason recorded"} · ${entry.sha256.slice(0, 16)}…`
      )
    );
    card.append(main);
    const inside = el("div", "inspection");
    inside.hidden = true;

    const actions = el("div", "card-actions");
    actions.append(
      button("Look inside", async () => {
        if (!inside.hidden) {
          inside.hidden = true;
          return;
        }
        try {
          showInspection(inside, await api.inspectQuarantined(entry.id));
        } catch (error) {
          toast(errorText(error), true);
        }
      })
    );
    actions.append(
      button("Save as evidence…", async () => {
        const path = await askWhereToSave(
          dialog,
          "Save the evidence",
          `grt-sentry-evidence-${dateStamp()}.zip`,
          "zip",
          "ZIP archive"
        );
        if (!path) return;
        try {
          toast(await api.exportQuarantineEvidence(entry.id, path));
        } catch (error) {
          toast(errorText(error), true);
        }
      })
    );
    actions.append(
      button("Put back", async () => {
        try {
          const where = await api.restoreFromQuarantine(entry.id);
          toast(`Restored to ${where}`);
          load();
        } catch (error) {
          toast(errorText(error), true);
        }
      })
    );
    actions.append(
      button(
        "Delete for good",
        async () => {
          const confirmed = await dialog.ask(
            `Delete ${entry.original_path} permanently?\n\nThe file cannot be recovered afterwards.`,
            { title: "Delete for good", kind: "warning" }
          );
          if (!confirmed) return;
          try {
            await api.deleteFromQuarantine(entry.id);
            toast("Deleted.");
            load();
          } catch (error) {
            toast(errorText(error), true);
          }
        },
        "danger"
      )
    );
    card.append(actions);
    container.append(card, inside);
  }
}

/** What the file is, read as bytes and never run. */
function showInspection(node, seen) {
  clear(node);
  node.hidden = false;

  const facts = el("dl", "facts");
  const add = (name, value) => facts.append(el("dt", null, name), el("dd", null, value));
  add("what it is", seen.kind);
  if (seen.disguise) add("its name", seen.disguise);
  add("size", formatSize(seen.size));
  add("SHA-256", seen.sha256);
  add("MD5", seen.md5);
  add(
    "entropy",
    `${seen.entropy} bits per byte${seen.entropy > 7.5 ? ", which is what compressed or encrypted contents look like" : ""}`
  );
  if (seen.members > 0) add("inside", `${formatCount(seen.members)} files in the archive`);
  add(
    "rules",
    seen.hits.length === 0 ? "none matches" : seen.hits.map((h) => `${h.title}${h.member ? ` (in ${h.member})` : ""}`).join("\n")
  );
  for (const note of seen.unchecked) add("not checked", note);
  node.append(facts);

  if (seen.notable.length > 0) {
    node.append(el("h3", null, "Strings worth a look"));
    node.append(el("pre", "strings", seen.notable.join("\n")));
  }
  node.append(
    el(
      "h3",
      null,
      seen.strings_total > seen.strings.length
        ? `Readable strings, the first ${formatCount(seen.strings.length)} of ${formatCount(seen.strings_total)}`
        : `Readable strings (${formatCount(seen.strings_total)})`
    )
  );
  node.append(el("pre", "strings", seen.strings.join("\n") || "none"));
}

async function loadLog() {
  const container = document.getElementById("action-log");
  clear(container);

  let entries = [];
  try {
    entries = await api.listActionLog(200);
  } catch (error) {
    container.append(el("div", "empty", errorText(error)));
    return;
  }

  if (entries.length === 0) {
    container.append(el("div", "empty", "GRT Sentry has not changed anything yet."));
    return;
  }

  for (const entry of entries) {
    const line = el("div", `log-line${entry.reverted ? " is-reverted" : ""}`);
    line.append(el("span", "log-time", formatTime(entry.timestamp)));

    const text = el("span", "log-text", entry.description);
    if (entry.reason) text.append(el("span", "badge", entry.reason));
    line.append(text);

    if (entry.reversible && !entry.reverted) {
      line.append(
        button("Undo", async () => {
          try {
            toast(await api.revertAction(entry.id));
            load();
          } catch (error) {
            toast(errorText(error), true);
          }
        })
      );
    }
    container.append(line);
  }
}

async function loadAllowlist() {
  const container = document.getElementById("allowlist");
  clear(container);

  let entries = [];
  try {
    entries = await api.listAllowlist();
  } catch (error) {
    container.append(el("div", "empty", errorText(error)));
    return;
  }

  if (entries.length === 0) {
    container.append(el("div", "empty", "No file has been marked as trusted."));
    return;
  }

  for (const entry of entries) {
    const card = el("div", "card");
    const main = el("div", "card-main");
    main.append(el("div", "card-title", entry.label || "(no note)"));
    main.append(el("div", "card-sub", `${entry.sha256} · added ${timeAgo(entry.added_at)}`));
    card.append(main);

    const actions = el("div", "card-actions");
    actions.append(
      button("Stop trusting", async () => {
        try {
          await api.removeFromAllowlist(entry.sha256);
          load();
        } catch (error) {
          toast(errorText(error), true);
        }
      })
    );
    card.append(actions);
    container.append(card);
  }
}

async function loadTrustedIps() {
  const container = document.getElementById("trusted-ips");
  clear(container);

  let entries = [];
  try {
    entries = await api.listTrustedIps();
  } catch (error) {
    container.append(el("div", "empty", errorText(error)));
    return;
  }

  if (entries.length === 0) {
    container.append(el("div", "empty", "No address has been marked as expected."));
    return;
  }

  for (const entry of entries) {
    const card = el("div", "card");
    const main = el("div", "card-main");
    main.append(el("div", "card-title", entry.ip));
    main.append(
      el("div", "card-sub", `${entry.label || "no note"} · first seen ${timeAgo(entry.first_seen)}`)
    );
    card.append(main);

    const actions = el("div", "card-actions");
    actions.append(
      button("Stop trusting", async () => {
        try {
          await api.untrustIp(entry.ip);
          load();
        } catch (error) {
          toast(errorText(error), true);
        }
      })
    );
    card.append(actions);
    container.append(card);
  }
}
