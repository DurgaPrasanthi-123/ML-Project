import { useEffect, useRef, useState } from "react";
import StatCard from "../components/StatCard.jsx";
import DistributionBar from "../components/DistributionBar.jsx";
import { EmptyState, ErrorState, LoadingState } from "../components/States.jsx";
import { fetchPredictionCounts, distribution, riskDistribution } from "../lib/analytics.js";
import { fmtInt } from "../lib/format.js";
import ScanHistory from "../components/ScanHistory.jsx";

/**
 * Analytics: a visual security overview over the deployment's whole scan
 * history. The counters come from the backend's database aggregate
 * (/history/stats) — one request, full table, nothing invented client-side.
 */
export default function AnalyticsPage() {
  const [state, setState] = useState({ status: "loading", counts: null });
  const cancelled = useRef(false);

  useEffect(() => {
    cancelled.current = false;
    setState({ status: "loading", counts: null });
    fetchPredictionCounts()
      .then((counts) => {
        if (!cancelled.current) setState({ status: "ready", counts });
      })
      .catch((err) => {
        if (!cancelled.current) {
          setState({
            status: "error",
            counts: null,
            error: err?.message || "Could not load analytics.",
          });
        }
      });
    return () => {
      cancelled.current = true;
    };
  }, []);

  const counts = state.counts;
  const segments = counts ? distribution(counts) : [];
  const bands = counts?.riskBands;
  const riskSegments = bands ? riskDistribution(bands) : [];
  const total = counts?.total || 0;

  return (
    <div className="page">
      <header className="page-head">
        <h1>Analytics</h1>
        <p>A security overview built entirely from this deployment&apos;s scan history.</p>
      </header>

      {state.status === "loading" && <LoadingState label="Crunching scan history…" />}
      {state.status === "error" && (
        <ErrorState
          title={state.error || "Could not load analytics."}
          hint="The scan-history API may be unavailable. Retry in a moment."
        />
      )}

      {state.status === "ready" && (
        <>
          {total === 0 ? (
            <EmptyState
              title="No scans to analyze yet"
              hint="Run a few URL analyses and this dashboard will fill up with distributions and activity."
            />
          ) : (
            <>
              <section className="stat-grid" aria-label="Scan totals">
                <StatCard label="Total scans" value={fmtInt(total)} icon="⌕" />
                <StatCard label="Phishing" value={fmtInt(counts.PHISHING)} sub={pct(counts.PHISHING, total)} variant="bad" icon="⚑" />
                <StatCard label="Suspicious" value={fmtInt(counts.SUSPICIOUS)} sub={pct(counts.SUSPICIOUS, total)} variant="warn" icon="⚠" />
                <StatCard label="Legitimate" value={fmtInt(counts.LEGITIMATE)} sub={pct(counts.LEGITIMATE, total)} variant="ok" icon="✓" />
              </section>

              <section className="card-glass" aria-label="Prediction distribution">
                <h2>Prediction distribution</h2>
                <DistributionBar segments={segments} />
                <p className="char-note">
                  All {fmtInt(total)} recorded scans in this deployment.
                </p>
              </section>

              <section className="card-glass" aria-label="Risk distribution">
                <h2>Risk distribution</h2>
                {riskSegments.length > 0 ? (
                  <DistributionBar segments={riskSegments} />
                ) : (
                  <EmptyState title="Risk distribution needs history rows" />
                )}
              </section>
            </>
          )}
        </>
      )}

      <ScanHistory compact />
    </div>
  );
}

function pct(part, total) {
  return total > 0 ? `${Math.round((part / total) * 100)}% of scans` : "of scans";
}
