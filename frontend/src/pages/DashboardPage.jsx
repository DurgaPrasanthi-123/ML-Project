import { useState } from "react";
import { Link, navigate } from "../lib/router.jsx";
import { useModelInfo } from "../lib/hooks.js";
import UrlForm from "../components/UrlForm.jsx";
import ResultCard from "../components/ResultCard.jsx";
import ScanHistory from "../components/ScanHistory.jsx";
import StatCard from "../components/StatCard.jsx";
import Badge from "../components/Badge.jsx";
import { ErrorState, LoadingState } from "../components/States.jsx";
import { predictUrl, ApiError } from "../api.js";
import { fmtInt } from "../lib/format.js";

/** Landing + overview: hero, stats, quick analyzer, recent activity. */
export default function DashboardPage() {
  const model = useModelInfo();
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [historyKey, setHistoryKey] = useState(0);

  const stats = model.data?.history;
  const phish = stats?.phishing_detected;
  const total = stats?.total_scans;
  const phishPct = Number.isFinite(phish) && total > 0 ? Math.round((phish / total) * 100) : null;

  async function analyze(url) {
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const data = await predictUrl(url);
      setResult(data);
      setHistoryKey((k) => k + 1);
    } catch (err) {
      if (err instanceof ApiError) setError(err.message);
      else setError("Something went wrong while analyzing the URL.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="page">
      <section className="hero card-glass">
        <div className="hero-copy">
          <Badge variant="ok" className="hero-chip">● LIVE MODEL — {model.data?.model_name || "ML"} {model.data?.model_version ? `v${model.data.model_version}` : ""}</Badge>
          <h1>Detect suspicious URLs before you trust them.</h1>
          <p>
            Machine-learning powered URL analysis with transparent risk scoring and
            explainable predictions.
          </p>
          <div className="hero-cta">
            <button type="button" className="btn primary" onClick={() => navigate("analyze")}>
              Analyze a URL
            </button>
            <Link to="about" className="btn ghost">
              Explore how it works
            </Link>
          </div>
        </div>
        <div className="hero-panel" aria-hidden="true">
          <div className="hero-row"><span>URL Input</span><i /></div>
          <div className="hero-row"><span>Normalization</span><i /></div>
          <div className="hero-row"><span>Feature Extraction</span><i /></div>
          <div className="hero-row"><span>ML Classification</span><i className="on" /></div>
          <div className="hero-row"><span>Risk + Explanation</span><i className="on" /></div>
        </div>
      </section>

      <section className="stat-grid" aria-label="Security overview">
        <StatCard label="Total scans" value={Number.isFinite(total) ? fmtInt(total) : "—"} icon="⌕" />
        <StatCard label="Phishing detected" value={Number.isFinite(phish) ? fmtInt(phish) : "—"} sub={phishPct !== null ? `${phishPct}% of all scans` : "of all scans"} variant="bad" icon="⚑" />
        <StatCard label="Legitimate + suspicious" value={Number.isFinite(total) && Number.isFinite(phish) ? fmtInt(total - phish) : "—"} sub="benign or unclear" variant="ok" icon="✓" />
        <StatCard
          label="Model"
          value={model.data?.model_name || "—"}
          sub={model.data?.model_version ? `v${model.data.model_version} · ${model.data?.feature_names?.length ?? "—"} features` : "features"}
          variant="accent"
          icon="◈"
        />
      </section>

      <section className="card-glass" aria-label="Quick analyzer">
        <h2>Quick analyze</h2>
        <UrlForm onSubmit={analyze} loading={loading} submitLabel="Analyze" />
        {error && <ErrorState title={error} onRetry={() => setError("")} />}
        {loading && <LoadingState label="Analyzing URL…" />}
        {result && <ResultCard result={result} />}
      </section>

      <ScanHistory
        refreshKey={historyKey}
        compact
        onAnalyzeAgain={(item) => analyze(item.url)}
      />

      <section className="card-glass pipeline" aria-label="How it works">
        <h2>How it works</h2>
        <ol className="pipeline-steps">
          {["URL input", "Normalization", "Feature extraction", "ML classification", "Risk + explanation"].map((step, i) => (
            <li key={step}>
              <span className="step-num">{i + 1}</span>
              <span>{step}</span>
            </li>
          ))}
        </ol>
        <Link to="about" className="btn ghost">Explore how it works</Link>
      </section>
    </div>
  );
}
