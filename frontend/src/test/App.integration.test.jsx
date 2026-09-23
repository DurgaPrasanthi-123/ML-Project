import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "../App.jsx";

function jsonResponse(body, { status = 200 } = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  };
}

const PREDICT_URL = "/api/v1/predict";

const samplePrediction = {
  url: "https://en.wikipedia.org/wiki/Machine_learning",
  normalized_url: "https://en.wikipedia.org/wiki/Machine_learning",
  prediction: "LEGITIMATE",
  confidence: 96.4,
  risk_score: 4,
  risk_level: "Legitimate",
  probability_phishing: 0.036,
  contributing_features: [
    { feature: "has_https", impact: -1.42, direction: "legitimate" },
    { feature: "url_length", impact: 0.31, direction: "phishing" },
  ],
  guardrail_flags: [],
  dns_check: { checked: true, exists: true },
  model_version: "3.0.0",
  model_name: "XGBoost",
  scan_id: 41,
};

const sampleModelInfo = {
  model_name: "XGBoost",
  model_version: "3.0.0",
  trained_at: "2026-09-23T05:36:07Z",
  dataset: { total: 218472 },
  metrics: { accuracy: 0.991, precision: 0.9958, recall: 0.989, f1_score: 0.9924, roc_auc: 0.9988 },
  comparison: [],
  thresholds: { phishing_threshold: 0.75, suspicious_threshold: 0.35 },
  feature_names: [],
  global_feature_importance: [],
  history: { enabled: true, total_scans: 2, phishing_detected: 1 },
};

const sampleHistory = {
  items: [
    {
      id: 41,
      url: "https://en.wikipedia.org/wiki/Machine_learning",
      normalized_url: "https://en.wikipedia.org/wiki/Machine_learning",
      url_hash: "a".repeat(64),
      prediction: "LEGITIMATE",
      confidence: 96.4,
      risk_score: 4,
      probability_phishing: 0.036,
      model_name: "XGBoost",
      model_version: "3.0.0",
      created_at: "2026-09-23T12:00:00+00:00",
    },
    {
      id: 40,
      url: "http://login.paypal.com.verify-billing-secure.xyz/signin.php",
      normalized_url: "http://login.paypal.com.verify-billing-secure.xyz/signin.php",
      url_hash: "b".repeat(64),
      prediction: "PHISHING",
      confidence: 99.1,
      risk_score: 99,
      probability_phishing: 0.991,
      model_name: "XGBoost",
      model_version: "3.0.0",
      created_at: "2026-09-23T11:55:00+00:00",
    },
  ],
  total: 2,
  page: 1,
  page_size: 10,
  pages: 1,
};

const emptyHistory = { items: [], total: 0, page: 1, page_size: 10, pages: 1 };

/** Stub fetch. predictImpl/historyImpl/modelImpl produce per-route responses. */
function mockBackend(predictImpl, historyImpl = () => jsonResponse(sampleHistory), modelImpl = () => jsonResponse(sampleModelInfo)) {
  const fetchMock = vi.fn((url) => {
    const u = String(url);
    if (u.startsWith("/api/v1/history")) return Promise.resolve(historyImpl());
    if (u === PREDICT_URL) return Promise.resolve(predictImpl());
    if (u === "/api/v1/model-info") return Promise.resolve(modelImpl());
    throw new Error(`unexpected fetch: ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

const input = () => screen.getByLabelText(/URL to analyze/i);

/** The primary Analyze button on the current page (skip sample chips). */
function analyzeButton() {
  const buttons = screen.getAllByRole("button", { name: /^analyze$/i });
  return buttons[0];
}

/** Wait for the result card (identified by its SHAP heading) and return it. */
async function findResultSection() {
  const heading = await screen.findByText(/why this verdict/i);
  return heading.closest("section");
}

beforeEach(() => {
  window.location.hash = "#/dashboard";
  mockBackend(() => jsonResponse(samplePrediction));
});

afterEach(() => {
  vi.unstubAllGlobals();
  window.location.hash = "";
});

describe("App integration", () => {
  it("renders the navbar, form, history section, and no error on load", async () => {
    render(<App />);
    expect(analyzeButton()).toBeInTheDocument();
    expect(input()).toBeInTheDocument();
    await screen.findByText(/wikipedia\.org\/wiki\/Machine_learning/); // history loaded
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: /primary/i })).toBeInTheDocument();
  });

  it("submits a URL and shows prediction, confidence, risk score, model, SHAP features", async () => {
    const fetchMock = mockBackend(() => jsonResponse(samplePrediction));
    render(<App />);
    await screen.findByText(/wikipedia\.org\/wiki\/Machine_learning/);

    await userEvent.type(input(), "https://en.wikipedia.org/wiki/Machine_learning");
    await userEvent.click(analyzeButton());

    const section = await findResultSection();
    expect(within(section).getByText("LEGITIMATE")).toBeInTheDocument();
    expect(within(section).getByText("96.4%")).toBeInTheDocument();
    expect(within(section).getByText("4")).toBeInTheDocument(); // risk dial
    expect(within(section).getByText(/XGBoost/)).toBeInTheDocument();
    expect(within(section).getByText("3.0.0")).toBeInTheDocument(); // model version
    expect(within(section).getByText(/has_https/)).toBeInTheDocument(); // SHAP feature

    const predictCall = fetchMock.mock.calls.find(([u]) => String(u) === PREDICT_URL);
    expect(predictCall).toBeTruthy();
    expect(JSON.parse(predictCall[1].body)).toEqual({ url: "https://en.wikipedia.org/wiki/Machine_learning" });
  });

  it("shows the loading state while analyzing", async () => {
    let resolvePredict;
    mockBackend(() => new Promise((resolve) => { resolvePredict = resolve; }));
    render(<App />);
    await screen.findByText(/wikipedia\.org\/wiki\/Machine_learning/);

    await userEvent.type(input(), "https://en.wikipedia.org/wiki/ML");
    await userEvent.click(analyzeButton());

    expect(await screen.findByText(/Analyzing URL/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /analyzing/i })).toBeDisabled();

    resolvePredict(jsonResponse(samplePrediction));
    await findResultSection();
    expect(screen.queryByText(/Analyzing URL/i)).not.toBeInTheDocument();
  });

  it("renders phishing and suspicious verdicts with their styles", async () => {
    mockBackend(() =>
      jsonResponse({
        ...samplePrediction,
        prediction: "PHISHING",
        confidence: 99.2,
        risk_score: 99,
        probability_phishing: 0.992,
      })
    );
    const { container } = render(<App />);
    await screen.findByText(/wikipedia\.org\/wiki\/Machine_learning/);

    await userEvent.type(input(), "http://login.paypal.com.verify-billing-secure.xyz/signin.php");
    await userEvent.click(analyzeButton());
    let section = await findResultSection();
    expect(within(section).getByText("PHISHING")).toBeInTheDocument();
    expect(container.querySelector(".result.phishing")).toBeTruthy();

    mockBackend(() =>
      jsonResponse({
        ...samplePrediction,
        prediction: "SUSPICIOUS",
        confidence: 61.0,
        risk_score: 39,
        probability_phishing: 0.61,
      })
    );
    // The "Official brand" sample chip auto-submits a fresh analysis.
    await userEvent.click(screen.getByRole("button", { name: /official brand/i }));
    section = await findResultSection();
    expect(within(section).getByText("SUSPICIOUS")).toBeInTheDocument();
    expect(container.querySelector(".result.suspicious")).toBeTruthy();
  });

  it("surfaces API error details in the alert banner (422 validation)", async () => {
    mockBackend(() =>
      jsonResponse(
        { detail: [{ msg: "String should have at least 4 characters", type: "string_too_short" }] },
        { status: 422 }
      )
    );
    render(<App />);
    await screen.findByText(/wikipedia\.org\/wiki\/Machine_learning/);

    await userEvent.type(input(), "https://example.com/x");
    await userEvent.click(analyzeButton());

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/at least 4 characters/i);
    expect(screen.queryByText(/why this verdict/i)).not.toBeInTheDocument();
  });

  it("surfaces backend 400 SSRF rejection messages", async () => {
    mockBackend(() =>
      jsonResponse({ detail: "Private, reserved, or internal network addresses cannot be analyzed." }, { status: 400 })
    );
    render(<App />);
    await screen.findByText(/wikipedia\.org\/wiki\/Machine_learning/);

    await userEvent.type(input(), "http://127.0.0.1/health");
    await userEvent.click(analyzeButton());

    expect(await screen.findByRole("alert")).toHaveTextContent(/cannot be analyzed/i);
  });

  it("shows a friendly banner when the API is unreachable", async () => {
    mockBackend(() => Promise.reject(new TypeError("Failed to fetch")));
    render(<App />);
    await screen.findByText(/wikipedia\.org\/wiki\/Machine_learning/);

    await userEvent.type(input(), "https://example.com/");
    await userEvent.click(analyzeButton());

    expect(await screen.findByRole("alert")).toHaveTextContent(/cannot reach the analysis service/i);
  });

  it("shows history rows with prediction badges and risk details", async () => {
    render(<App />);
    // Wait for a row unique to the history payload, then scope assertions.
    const historySection = (
      await screen.findByText(/verify-billing-secure\.xyz/)
    ).closest("section");

    expect(within(historySection).getByText(/2 scans/)).toBeInTheDocument();
    expect(within(historySection).getByText(/wikipedia\.org\/wiki\/Machine_learning/)).toBeInTheDocument();

    const badge = within(historySection).getByText("PHISHING");
    expect(badge).toHaveClass("history-badge");
    expect(badge).toHaveClass("bad");
    expect(within(historySection).getByText(/risk 4 · confidence 96\.4% · XGBoost v3\.0\.0/)).toBeInTheDocument();
    expect(within(historySection).getByText(/risk 99 · confidence 99\.1% · XGBoost v3\.0\.0/)).toBeInTheDocument();
  });

  it("refreshes history after a new scan", async () => {
    const fetchMock = mockBackend(() => jsonResponse(samplePrediction));
    render(<App />);
    await screen.findByText(/wikipedia\.org\/wiki\/Machine_learning/);
    const before = fetchMock.mock.calls.filter(([u]) => String(u).startsWith("/api/v1/history")).length;

    await userEvent.type(input(), "https://example.org/new");
    await userEvent.click(analyzeButton());
    await findResultSection();

    await waitFor(() => {
      const after = fetchMock.mock.calls.filter(([u]) => String(u).startsWith("/api/v1/history")).length;
      expect(after).toBeGreaterThan(before);
    });
  });

  it("shows an error state when history fails to load", async () => {
    mockBackend(
      () => jsonResponse(samplePrediction),
      () => jsonResponse({ detail: "Scan history is disabled." }, { status: 503 })
    );
    render(<App />);
    expect(await screen.findByText(/scan history is not available right now/i)).toBeInTheDocument();
  });

  it("shows the empty state when history has no rows", async () => {
    mockBackend(
      () => jsonResponse(samplePrediction),
      () => jsonResponse(emptyHistory)
    );
    render(<App />);
    expect(await screen.findByText(/no scans yet/i)).toBeInTheDocument();
  });

  it("navigates between routes via the navbar", async () => {
    render(<App />);
    await screen.findByText(/wikipedia\.org\/wiki\/Machine_learning/);

    await userEvent.click(screen.getByRole("link", { name: "Security Guide" }));
    expect(await screen.findByText(/spot a suspicious URL/i)).toBeInTheDocument();

    await userEvent.click(screen.getByRole("link", { name: "About" }));
    expect(await screen.findByText(/problem statement/i)).toBeInTheDocument();

    await userEvent.click(screen.getByRole("link", { name: "History" }));
    expect(await screen.findByText(/Scan History/i)).toBeInTheDocument();
  });

  it("history 'Analyze again' routes to the analyzer and auto-runs the scan", async () => {
    const fetchMock = mockBackend(() => jsonResponse(samplePrediction));
    render(<App />);
    const row = await screen.findByText(/verify-billing-secure\.xyz/);
    const section = row.closest("section");

    await userEvent.click(within(section).getByRole("button", { name: /analyze .* again/i }));

    // Routed to the analyzer, which auto-ran the stored URL through /predict.
    await waitFor(() => {
      const call = fetchMock.mock.calls.find(([u]) => String(u) === PREDICT_URL);
      expect(call).toBeTruthy();
    });
    expect(JSON.parse(fetchMock.mock.calls.find(([u]) => String(u) === PREDICT_URL)[1].body))
      .toEqual({ url: "http://login.paypal.com.verify-billing-secure.xyz/signin.php" });
  });
});
