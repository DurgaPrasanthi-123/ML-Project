import { describe, expect, it, vi, afterEach, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "../App.jsx";

function jsonResponse(body, { status = 200 } = {}) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

const sampleModelInfo = {
  model_name: "XGBoost", model_version: "3.0.0", trained_at: "2026-09-23T05:36:07Z",
  dataset: { total: 218472 }, metrics: { accuracy: 0.991 }, comparison: [],
  thresholds: { phishing_threshold: 0.75, suspicious_threshold: 0.35 },
  feature_names: [], global_feature_importance: [],
  history: { enabled: true, total_scans: 2, phishing_detected: 1 },
};

const sampleHistory = {
  items: [{
    id: 41, url: "https://en.wikipedia.org/wiki/Machine_learning",
    normalized_url: "https://en.wikipedia.org/wiki/Machine_learning", url_hash: "a".repeat(64),
    prediction: "LEGITIMATE", confidence: 96.4, risk_score: 4, probability_phishing: 0.036,
    model_name: "XGBoost", model_version: "3.0.0", created_at: "2026-09-23T12:00:00+00:00",
  }],
  total: 1, page: 1, page_size: 10, pages: 1,
};

beforeEach(() => {
  window.location.hash = "#/dashboard";
  vi.stubGlobal("fetch", vi.fn((url) => {
    const u = String(url);
    if (u.startsWith("/api/v1/history")) return Promise.resolve(jsonResponse(sampleHistory));
    if (u === "/api/v1/predict") return Promise.resolve(jsonResponse({ prediction: "LEGITIMATE" }));
    if (u === "/api/v1/model-info") return Promise.resolve(jsonResponse(sampleModelInfo));
    throw new Error(`unexpected fetch: ${url}`);
  }));
});

afterEach(() => {
  vi.unstubAllGlobals();
  window.location.hash = "";
});

describe("debug nav 2", () => {
  it("waits for history then clicks nav", async () => {
    render(<App />);
    await screen.findByText(/wikipedia\.org\/wiki\/Machine_learning/);

    const link = screen.getByRole("link", { name: "Security Guide" });
    await userEvent.click(link);
    console.log("HASH:", JSON.stringify(window.location.hash));
    await new Promise((r) => setTimeout(r, 200));
    console.log("BODY:", document.body.textContent.slice(0, 600).replace(/\s+/g, " "));
    const el = await screen.findByText(/spot a suspicious URL/i);
    expect(el).toBeInTheDocument();
  });
});
