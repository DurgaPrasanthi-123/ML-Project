/**
 * Analytics derived from the backend's history aggregate.
 *
 * All figures come from /api/v1/history/stats, which groups every row in the
 * scan_history table in the database. Nothing is invented here, and nothing is
 * computed by walking history pages in the browser — one request covers the
 * whole table however large it grows.
 */

import { fetchHistoryStats } from "../api.js";

/**
 * Load the deployment's scan counters.
 * Returns { total, LEGITIMATE, SUSPICIOUS, PHISHING, riskBands }.
 */
export async function fetchPredictionCounts({ signal } = {}) {
  const data = await fetchHistoryStats({ signal });
  const counts = data?.counts || {};
  return {
    total: data?.total || 0,
    LEGITIMATE: counts.LEGITIMATE || 0,
    SUSPICIOUS: counts.SUSPICIOUS || 0,
    PHISHING: counts.PHISHING || 0,
    riskBands: data?.risk_bands || { low: 0, medium: 0, high: 0 },
  };
}

/** Percentages from raw counts; returns [] when total is 0. */
export function distribution(counts) {
  const total = counts.LEGITIMATE + counts.SUSPICIOUS + counts.PHISHING;
  if (!total) return [];
  return [
    { key: "PHISHING", label: "Phishing", value: counts.PHISHING, pct: (counts.PHISHING / total) * 100 },
    { key: "SUSPICIOUS", label: "Suspicious", value: counts.SUSPICIOUS, pct: (counts.SUSPICIOUS / total) * 100 },
    { key: "LEGITIMATE", label: "Legitimate", value: counts.LEGITIMATE, pct: (counts.LEGITIMATE / total) * 100 },
  ];
}

/** Percentages from risk-band counts; returns [] when no rows carry a band. */
export function riskDistribution(bands) {
  const total = bands.low + bands.medium + bands.high;
  if (!total) return [];
  return [
    { key: "LEGITIMATE", label: "Low risk (0–34)", value: bands.low, pct: (bands.low / total) * 100 },
    { key: "SUSPICIOUS", label: "Medium risk (35–74)", value: bands.medium, pct: (bands.medium / total) * 100 },
    { key: "PHISHING", label: "High risk (75–100)", value: bands.high, pct: (bands.high / total) * 100 },
  ];
}
