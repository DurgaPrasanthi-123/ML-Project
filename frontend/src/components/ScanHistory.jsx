import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { fetchHistory, ApiError } from "../api.js";
import { fmtDate, fmtPct, verdictClass } from "../lib/format.js";
import { EmptyState, ErrorState, NoResultsState, LoadingState } from "./States.jsx";

const PAGE_SIZE = 10;

/**
 * Scan history browser. Two layouts:
 *  - compact: recent-activity strip used on the dashboard
 *  - full: paginated table with search + prediction filter (History page)
 *
 * History URLs are plain text — never links to external sites.
 */
export default function ScanHistory({
  refreshKey = 0,
  compact = false,
  onAnalyzeAgain,
}) {
  const [state, setState] = useState({ status: "loading", items: [], total: 0, page: 1, pages: 1 });
  const [page, setPage] = useState(1);
  const [prediction, setPrediction] = useState("");
  const [search, setSearch] = useState("");
  const cancelled = useRef(false);

  const load = useCallback(
    async (p, pred) => {
      setState((s) => ({ ...s, status: s.items.length ? "refreshing" : "loading" }));
      try {
        const data = await fetchHistory({ page: p, pageSize: PAGE_SIZE, prediction: pred || undefined });
        if (cancelled.current) return;
        setState({
          status: "ready",
          items: data.items || [],
          total: data.total ?? 0,
          page: data.page ?? p,
          pages: data.pages ?? 1,
        });
      } catch (err) {
        if (cancelled.current) return;
        const message =
          err instanceof ApiError && err.status === 503
            ? "Scan history is not available right now."
            : "Could not load scan history.";
        setState({ status: "error", items: [], total: 0, page: 1, pages: 1, error: message });
      }
    },
    []
  );

  useEffect(() => {
    cancelled.current = false;
    load(page, prediction);
    return () => {
      cancelled.current = true;
    };
  }, [load, page, prediction, refreshKey]);

  // Reset to the first page when the filter changes.
  function changePrediction(value) {
    setPrediction(value);
    setPage(1);
  }

  const visible = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return state.items;
    return state.items.filter((it) => (it.url || "").toLowerCase().includes(q));
  }, [state.items, search]);

  function goNext() { setPage((p) => Math.min(p + 1, state.pages)); }
  function goPrev() { setPage((p) => Math.max(p - 1, 1)); }

  const head = (
    <div className="history-head">
      <div>
        <h2>{compact ? "Recent scan activity" : "Scan history"}</h2>
        <span className="history-total">
          {state.total} scan{state.total === 1 ? "" : "s"}
          {prediction ? ` · filtered` : ""}
        </span>
      </div>
      {!compact && (
        <div className="history-controls">
          <input
            type="search"
            className="history-search"
            placeholder="Search scanned URLs…"
            aria-label="Search scanned URLs"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <div className="history-filters" role="group" aria-label="Filter by prediction">
            {["", "PHISHING", "SUSPICIOUS", "LEGITIMATE"].map((p) => (
              <button
                key={p || "all"}
                type="button"
                className={`chip filter ${prediction === p ? "active" : ""}`}
                aria-pressed={prediction === p}
                onClick={() => changePrediction(p)}
              >
                {p || "All"}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );

  if (state.status === "loading") {
    return (
      <section className="card-glass" aria-live="polite">
        {head}
        <LoadingState label="Loading scan history…" />
      </section>
    );
  }

  if (state.status === "error") {
    return (
      <section className="card-glass">
        {head}
        <ErrorState title={state.error} hint="Check that the API is running, then retry." onRetry={() => load(page, prediction)} />
      </section>
    );
  }

  if (state.items.length === 0) {
    return (
      <section className="card-glass">
        {head}
        <EmptyState
          title="No scans yet"
          hint="Analyze a URL and it will appear here."
        />
      </section>
    );
  }

  return (
    <section className="card-glass history">
      {head}
      {visible.length === 0 ? (
        <NoResultsState hint="No scanned URLs match your search on this page." />
      ) : (
        <ul className="history-list">
          {visible.map((item) => (
            <li key={item.id} className={`history-item ${verdictClass(item.prediction)}`}>
              <div className="history-row">
                <span className="history-url" title={item.url}>{item.url}</span>
                <span className={`history-badge ${verdictClass(item.prediction)}`}>
                  {item.prediction}
                </span>
              </div>
              <div className="history-sub">
                risk {item.risk_score} · confidence {fmtPct(item.confidence)} ·{" "}
                {item.model_name} v{item.model_version} · {fmtDate(item.created_at)}
              </div>
              {onAnalyzeAgain && (
                <div className="history-actions">
                  <button
                    type="button"
                    className="chip"
                    onClick={() => onAnalyzeAgain(item)}
                    aria-label={`Analyze ${item.url} again`}
                  >
                    ↻ Analyze again
                  </button>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}

      {!compact && state.pages > 1 && (
        <div className="history-pager">
          <button type="button" className="btn ghost" onClick={goPrev} disabled={state.page <= 1}>
            &larr; Previous
          </button>
          <span>
            Page {state.page} of {state.pages}
          </span>
          <button type="button" className="btn ghost" onClick={goNext} disabled={state.page >= state.pages}>
            Next &rarr;
          </button>
        </div>
      )}
    </section>
  );
}
