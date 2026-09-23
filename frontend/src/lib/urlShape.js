/**
 * Client-side URL shape summary for the analyzer page.
 *
 * Pure string parsing with the same JavaScript URL API — no network, no
 * verdicts. It previews what the backend will normalize and extract; the
 * backend remains the single source of truth.
 */

/** Mirror of the backend's normalize_url: make bare input parseable. */
export function normalizePreview(raw) {
  if (!raw) return "";
  let u = String(raw).trim();
  if (!u) return "";
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(u)) {
    u = (u.startsWith("//") ? "https:" : "https://") + u;
  } else if (/^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(:\d{1,5})?([/?#]|$)/.test(u)) {
    u = `https://${u}`;
  } else if (/^https?:\/\//i.test(u) === false && /^https?:/i.test(u)) {
    const i = u.indexOf(":");
    u = `${u.slice(0, i)}://${u.slice(i + 1).replace(/^\/+/, "")}`;
  }
  return u;
}

/** Safe decomposition of an absolute http(s) URL; null fields when absent. */
export function urlShape(raw) {
  const normalized = normalizePreview(raw);
  if (!normalized) return null;
  let u;
  try {
    u = new URL(normalized);
  } catch {
    return null;
  }
  const host = u.hostname.toLowerCase();
  const labels = host.split(".").filter(Boolean);
  return {
    normalized,
    scheme: u.protocol.replace(":", ""),
    hostname: host,
    port: u.port ? Number(u.port) : null,
    path: u.pathname,
    query: u.search,
    fragment: u.hash,
    https: u.protocol === "https:",
    isIp:
      /^\d{1,3}(\.\d{1,3}){3}$/.test(host) ||
      (host.startsWith("[") && host.endsWith("]")),
    subdomainDepth: Math.max(0, labels.length - 2),
    pathLength: u.pathname.length,
    specialChars: (normalized.match(/[^a-zA-Z0-9]/g) || []).length,
    labels,
  };
}
