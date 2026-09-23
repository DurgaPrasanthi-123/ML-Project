import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import AnalyticsPage from "../pages/AnalyticsPage.jsx";

const STATS_URL = "/api/v1/history/stats";

function jsonResponse(body, { status = 200 } = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  };
}

const sampleStats = {
  total: 982,
  counts: { LEGITIMATE: 600, SUSPICIOUS: 200, PHISHING: 182 },
  risk_bands: { low: 610, medium: 190, high: 182 },
};

const emptyHistory = { items: [], total: 0, page: 1, page_size: 10, pages: 1 };

/** Stub fetch; returns the mock so tests can inspect the requests made. */
function mockBackend({
  stats = () => jsonResponse(sampleStats),
  history = () => jsonResponse(emptyHistory),
} = {}) {
  const fetchMock = vi.fn((url) => {
    const u = String(url);
    if (u === STATS_URL) return Promise.resolve(stats());
    if (u.startsWith("/api/v1/history")) return Promise.resolve(history());
    throw new Error(`unexpected fetch: ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("AnalyticsPage", () => {
  it("renders totals, verdict counts and risk distribution from the API", async () => {
    mockBackend();
    render(<AnalyticsPage />);

    const totals = await screen.findByRole("region", { name: /scan totals/i });
    expect(within(totals).getByText("982")).toBeInTheDocument(); // total scans
    expect(within(totals).getByText("600")).toBeInTheDocument(); // legitimate
    expect(within(totals).getByText("200")).toBeInTheDocument(); // suspicious
    expect(within(totals).getByText("182")).toBeInTheDocument(); // phishing

    expect(within(totals).getByText("61% of scans")).toBeInTheDocument(); // 600/982

    const predictions = screen.getByRole("region", { name: /prediction distribution/i });
    expect(within(predictions).getByText(/all 982 recorded scans/i)).toBeInTheDocument();

    const risk = screen.getByRole("region", { name: /risk distribution/i });
    expect(within(risk).getByText(/low risk \(0–34\)/i)).toBeInTheDocument();
    expect(within(risk).getByText(/medium risk \(35–74\)/i)).toBeInTheDocument();
    expect(within(risk).getByText(/high risk \(75–100\)/i)).toBeInTheDocument();
  });

  it("loads its counters in ONE request instead of walking history pages", async () => {
    const fetchMock = mockBackend();
    render(<AnalyticsPage />);
    await screen.findByRole("region", { name: /scan totals/i });

    const urls = fetchMock.mock.calls.map(([u]) => String(u));
    expect(urls.filter((u) => u === STATS_URL)).toHaveLength(1);
    // The paged history endpoint must not be walked for analytics — that burst
    // of requests is exactly what used to trip the API and blank the page.
    expect(urls.filter((u) => u.startsWith("/api/v1/history?"))).toHaveLength(0);
  });

  it("surfaces the real API error rather than a generic message", async () => {
    mockBackend({
      stats: () => jsonResponse({ detail: "Scan history is disabled." }, { status: 503 }),
    });
    render(<AnalyticsPage />);

    expect(await screen.findByText(/scan history is disabled/i)).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: /scan totals/i })).not.toBeInTheDocument();
  });

  it("shows the empty state when the deployment has no scans", async () => {
    mockBackend({
      stats: () =>
        jsonResponse({
          total: 0,
          counts: { LEGITIMATE: 0, SUSPICIOUS: 0, PHISHING: 0 },
          risk_bands: { low: 0, medium: 0, high: 0 },
        }),
    });
    render(<AnalyticsPage />);

    expect(await screen.findByText(/no scans to analyze yet/i)).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: /scan totals/i })).not.toBeInTheDocument();
  });
});
