// The History tab: past scans, each as a report, and what changed between two.

import { api, dialog } from "./api.js";
import { askWhereToSave, button, clear, dateStamp, el, errorText, formatCount, formatTime, toast } from "./ui.js";

export async function load() {
  const list = document.getElementById("scan-list");
  clear(list);

  let scans = [];
  try {
    scans = await api.listScans(50);
  } catch (error) {
    list.append(el("div", "empty", errorText(error)));
    return;
  }

  if (scans.length === 0) {
    list.append(el("div", "empty", "No scan has been run yet."));
    return;
  }

  scans.forEach((scan, index) => {
    const card = el("div", "card");
    const main = el("div", "card-main");
    main.append(el("div", "card-title", formatTime(scan.timestamp)));
    const things = scan.issues_found === 1 ? "1 thing needed attention" : `${formatCount(scan.issues_found)} things needed attention`;
    main.append(el("div", "card-sub", `${formatCount(scan.files_checked)} files checked · ${things}`));
    card.append(main);

    const actions = el("div", "card-actions");
    actions.append(button("Report", () => showReport(scan)));
    actions.append(button("Save report…", () => saveReport(scan)));
    const previous = scans[index + 1];
    if (previous) actions.append(button("What changed", () => showComparison(previous, scan)));
    if (index > 1) actions.append(button("Since then", () => showComparison(scan, scans[0])));
    card.append(actions);
    list.append(card);
  });
}

function output() {
  const node = document.getElementById("history-output");
  clear(node);
  node.hidden = false;
  return node;
}

async function showReport(scan) {
  try {
    const text = await api.scanReport(scan.id);
    const node = output();
    node.append(el("pre", "report", text));
    node.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    toast(errorText(error), true);
  }
}

async function saveReport(scan) {
  const path = await askWhereToSave(
    dialog,
    "Save the report",
    `grt-sentry-report-${dateStamp(scan.timestamp)}.txt`,
    "txt",
    "Text"
  );
  if (!path) return;
  try {
    toast(await api.exportReport(scan.id, path));
  } catch (error) {
    toast(errorText(error), true);
  }
}

function changeList(title, issues) {
  const section = el("div", "change-list");
  section.append(el("h3", null, `${title} (${issues.length})`));
  if (issues.length === 0) {
    section.append(el("div", "empty", "Nothing."));
    return section;
  }
  for (const issue of issues) {
    const line = el("div", `change is-${issue.severity}`);
    line.append(el("div", "issue-title", issue.title));
    line.append(el("div", "issue-location", issue.location));
    section.append(line);
  }
  return section;
}

async function showComparison(older, newer) {
  let comparison;
  try {
    comparison = await api.compareScans(older.id, newer.id);
  } catch (error) {
    toast(errorText(error), true);
    return;
  }

  const node = output();
  node.append(el("h2", null, `${formatTime(newer.timestamp)} against ${formatTime(older.timestamp)}`));
  node.append(
    el(
      "p",
      "dim",
      `${comparison.appeared.length} appeared, ${comparison.gone.length} gone, ${comparison.unchanged} in both.`
    )
  );
  node.append(changeList("Appeared", comparison.appeared), changeList("Gone", comparison.gone));

  const machine = el("div", "change-list");
  machine.append(el("h3", null, "Changes on the machine"));
  if (comparison.changes.length === 0) {
    machine.append(el("div", "empty", "Startup entries, accounts, packages and the files in the scan folders are as they were."));
  }
  for (const group of comparison.changes) {
    machine.append(el("div", "issue-title", group.heading));
    machine.append(el("pre", "report", group.lines.join("\n")));
  }
  node.append(machine);
  node.append(
    button("Save the comparison…", async () => {
      const path = await askWhereToSave(
        dialog,
        "Save the comparison",
        `grt-sentry-changes-${dateStamp(newer.timestamp)}.txt`,
        "txt",
        "Text"
      );
      if (!path) return;
      try {
        toast(await api.exportComparison(older.id, newer.id, path));
      } catch (error) {
        toast(errorText(error), true);
      }
    })
  );
  node.scrollIntoView({ behavior: "smooth", block: "start" });
}
