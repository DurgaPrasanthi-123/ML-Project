/**
 * API client for the phishing detection backend.
 *
 * Base URL resolution:
 * - VITE_API_URL (build-time env, e.g. https://phishing-api.onrender.com)
 * - empty/undefined -> same-origin relative paths ("/api/v1/..."), which works
 *   with the Vite dev proxy (local dev) and the nginx container (production).
 *
 * Only non-secret configuration may be exposed via VITE_* variables — this
 * file must never receive API keys, tokens, or DB credentials.
 */

const API_BASE = (import.meta.env.VITE_API_URL || "").replace(/\/+$/, "");

const PREDICT_TIMEOUT_MS = 30_000;
const HISTORY_TIMEOUT_MS = 15_000;
const META_TIMEOUT_MS = 15_000;

export class ApiError extends Error {
  constructor(message, { status = 0, detail = null } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

/** Extract a human-readable message from FastAPI's error shapes. */
function extractDetail(status, payload) {
  if (!payload) return null;
  const d = payload.detail;
  if (typeof d === "string") return d;
  if (Array.isArray(d)) {
    // 422 validation errors: [{loc, msg, type}, ...]
    return d.map((e) => e.msg || String(e)).join("; ");
  }
  return null;
}

async function parseBody(res) {
  try {
    return await res.json();
  } catch {
    return null;
  }
}

async function request(path, { method = "GET", body, timeoutMs = 15_000, signal } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const onAbort = () => controller.abort();
  signal?.addEventListener("abort", onAbort);

  let res;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method,
      headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
  } catch (err) {
    if (signal?.aborted || controller.signal.aborted) {
      throw new ApiError(signal?.aborted ? "Request cancelled." : "The request timed out.", {
        status: 0,
      });
    }
    throw new ApiError("Cannot reach the analysis service. Check your connection and try again.");
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", onAbort);
  }

  const payload = await parseBody(res);
  if (!res.ok) {
    const detail = extractDetail(res.status, payload);
    throw new ApiError(detail || `Request failed (${res.status}).`, {
      status: res.status,
      detail,
    });
  }
  return payload;
}

/** POST /api/v1/predict — analyze one URL. */
export function predictUrl(url, { signal } = {}) {
  return request("/api/v1/predict", {
    method: "POST",
    body: { url },
    timeoutMs: PREDICT_TIMEOUT_MS,
    signal,
  });
}

/** GET /api/v1/history — paginated scan history, newest first. */
export function fetchHistory({ page = 1, pageSize = 10, prediction } = {}, { signal } = {}) {
  const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
  if (prediction) params.set("prediction", prediction);
  return request(`/api/v1/history?${params.toString()}`, {
    timeoutMs: HISTORY_TIMEOUT_MS,
    signal,
  });
}

/**
 * GET /api/v1/history/stats — totals per verdict and per risk band, aggregated
 * server-side over the whole scan history (one request, no page walking).
 */
export function fetchHistoryStats({ signal } = {}) {
  return request("/api/v1/history/stats", { timeoutMs: HISTORY_TIMEOUT_MS, signal });
}

/** GET /api/v1/model-info — model metadata, evaluation metrics, scan counters. */
export function fetchModelInfo({ signal } = {}) {
  return request("/api/v1/model-info", { timeoutMs: META_TIMEOUT_MS, signal });
}

/** GET /api/v1/health — liveness + model + database status. */
export function fetchHealth({ signal } = {}) {
  return request("/api/v1/health", { timeoutMs: META_TIMEOUT_MS, signal });
}

export const API_BASE_URL = API_BASE;
