// Building elements, formatting, and the toast.
//
// No template engine, and no innerHTML with data in it. Every value that comes
// from the machine is set through textContent, so a file with markup in its
// name stays a file with an odd name.

export function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

export function button(label, onClick, className) {
  const node = el("button", className, label);
  node.addEventListener("click", onClick);
  return node;
}

/** "3 minutes ago", or a full date once it is older than a day. */
export function timeAgo(timestamp) {
  if (!timestamp) return "never";
  const seconds = Math.floor(Date.now() / 1000) - timestamp;
  if (seconds < 45) return "just now";
  if (seconds < 90) return "a minute ago";
  if (seconds < 3600) return `${Math.round(seconds / 60)} minutes ago`;
  if (seconds < 7200) return "an hour ago";
  if (seconds < 86400) return `${Math.round(seconds / 3600)} hours ago`;
  return new Date(timestamp * 1000).toLocaleString();
}

export function formatTime(timestamp) {
  if (!timestamp) return "";
  return new Date(timestamp * 1000).toLocaleString();
}

export function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} kB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

/** Thousands separated, in the desktop's own convention. */
export function formatCount(value) {
  return Number(value || 0).toLocaleString();
}

let toastTimer = null;

export function toast(message, isError) {
  const node = document.getElementById("toast");
  node.textContent = message;
  node.classList.toggle("is-error", Boolean(isError));
  node.classList.remove("is-fading");
  node.hidden = false;

  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    node.classList.add("is-fading");
    setTimeout(() => { node.hidden = true; }, 250);
  }, isError ? 7000 : 3500);
}

/** The message a rejected command carries, whatever shape it arrived in. */
export function errorText(error) {
  if (typeof error === "string") return error;
  if (error && typeof error.message === "string") return error.message;
  return String(error);
}

/**
 * Renders a long list a page at a time.
 *
 * Two thousand rows in the DOM is what makes an old machine crawl, so one page
 * is kept in the document and swapped.
 */
export function paginate(items, pageSize, pager, renderPage) {
  let page = 0;
  const pages = Math.max(1, Math.ceil(items.length / pageSize));

  function draw() {
    const start = page * pageSize;
    renderPage(items.slice(start, start + pageSize));

    clear(pager);
    if (pages <= 1) return;

    const previous = button("Previous", () => { page = Math.max(0, page - 1); draw(); });
    previous.disabled = page === 0;
    const next = button("Next", () => { page = Math.min(pages - 1, page + 1); draw(); });
    next.disabled = page >= pages - 1;

    pager.append(previous, el("span", "dim", `Page ${page + 1} of ${pages}`), next);
  }

  draw();
}
