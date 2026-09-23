import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, API_BASE_URL, fetchHistory, predictUrl } from "../api.js";

function jsonResponse(body, { status = 200 } = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  };
}

describe("api client", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("uses same-origin base when VITE_API_URL is unset", () => {
    expect(API_BASE_URL).toBe("");
  });

  it("POSTs {url} to /api/v1/predict with JSON headers", async () => {
    fetch.mockResolvedValueOnce(jsonResponse({ prediction: "PHISHING" }));
    await predictUrl("https://example.com");
    expect(fetch).toHaveBeenCalledTimes(1);
    const [url, opts] = fetch.mock.calls[0];
    expect(url).toBe("/api/v1/predict");
    expect(opts.method).toBe("POST");
    expect(opts.headers["Content-Type"]).toBe("application/json");
    expect(JSON.parse(opts.body)).toEqual({ url: "https://example.com" });
  });

  it("resolves with the parsed payload on success", async () => {
    const payload = { prediction: "LEGITIMATE", confidence: 97.5, risk_score: 3 };
    fetch.mockResolvedValueOnce(jsonResponse(payload));
    await expect(predictUrl("https://example.com")).resolves.toEqual(payload);
  });

  it("surfaces FastAPI string detail on error responses", async () => {
    fetch.mockResolvedValueOnce(
      jsonResponse({ detail: "Private, reserved, or internal network addresses cannot be analyzed." }, { status: 400 })
    );
    const err = await predictUrl("http://127.0.0.1/").catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(400);
    expect(err.message).toMatch(/cannot be analyzed/);
  });

  it("joins 422 validation arrays into one message", async () => {
    fetch.mockResolvedValueOnce(
      jsonResponse(
        { detail: [{ msg: "String should have at least 4 characters" }, { msg: "url must not contain whitespace" }] },
        { status: 422 }
      )
    );
    const err = await predictUrl("ab").catch((e) => e);
    expect(err.status).toBe(422);
    expect(err.message).toContain("at least 4 characters");
    expect(err.message).toContain("whitespace");
  });

  it("falls back to a status message when the error body is not JSON", async () => {
    fetch.mockResolvedValueOnce({ ok: false, status: 502, json: async () => { throw new Error("no json"); } });
    const err = await predictUrl("https://example.com").catch((e) => e);
    expect(err.message).toBe("Request failed (502).");
  });

  it("maps network failures to a friendly ApiError", async () => {
    fetch.mockRejectedValueOnce(new TypeError("Failed to fetch"));
    const err = await predictUrl("https://example.com").catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(0);
    expect(err.message).toMatch(/Cannot reach the analysis service/);
  });

  it("requests paginated history with query params", async () => {
    fetch.mockResolvedValueOnce(jsonResponse({ items: [], total: 0, page: 2, pages: 1 }));
    await fetchHistory({ page: 2, pageSize: 5, prediction: "PHISHING" });
    const [url] = fetch.mock.calls[0];
    expect(url).toBe("/api/v1/history?page=2&page_size=5&prediction=PHISHING");
  });

  it("omits the prediction param when no filter is given", async () => {
    fetch.mockResolvedValueOnce(jsonResponse({ items: [], total: 0, page: 1, pages: 1 }));
    await fetchHistory({ page: 1, pageSize: 10 });
    const [url] = fetch.mock.calls[0];
    expect(url).toBe("/api/v1/history?page=1&page_size=10");
  });
});
