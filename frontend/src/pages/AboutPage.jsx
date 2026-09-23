import { useModelInfo } from "../lib/hooks.js";
import { ErrorState, LoadingState } from "../components/States.jsx";
import { fmtPct } from "../lib/format.js";

const PIPELINE = [
  { title: "URL Input", body: "The user submits a URL. No crawling — the URL is never visited or fetched." },
  { title: "URL Normalization", body: "Bare domains (example.com) gain an https:// scheme; malformed separators are repaired so parsing is consistent." },
  { title: "Feature Extraction", body: "42 lexical, structural, entropy and content features are computed by the same module used in training — training/serving parity is test-enforced." },
  { title: "ML Classification", body: "A trained XGBoost classifier estimates P(phishing); deterministic guardrails (brand-impersonation, DNS existence) fuse in as safety nets." },
  { title: "Risk + Explanation", body: "The probability becomes a 0-100 risk score and a verdict; SHAP contributions explain which features drove the decision." },
];

const MODELS = [
  {
    name: "Logistic Regression",
    role: "Interpretable linear baseline — sets the floor and sanity-checks the features.",
  },
  {
    name: "Random Forest",
    role: "Bagged tree ensemble — robust to noisy features and overfitting.",
  },
  {
    name: "XGBoost",
    role: "Gradient-boosted trees — typically the strongest performer; the served model.",
  },
];

/** Project story + live model information (real metrics only, from /model-info). */
export default function AboutPage() {
  const { status, data, error, reload } = useModelInfo();

  return (
    <div className="page">
      <header className="page-head center">
        <h1>About this project</h1>
        <p>An end-to-end ML product for URL threat assessment — built to be explained.</p>
      </header>

      <div className="about-grid">
        <section className="card-glass">
          <h2>Problem statement</h2>
          <p>
            Phishing remains one of the most effective cyberattacks: a single convincing
            link is enough to harvest credentials. Human inspection of URLs is unreliable,
            and blocklists always lag behind newly registered malicious domains.
          </p>
          <h2>Objective</h2>
          <p>
            Classify URLs as LEGITIMATE, SUSPICIOUS or PHISHING using only lexical and
            structural features — with a transparent risk score and per-feature
            explanations, and without ever visiting the URL.
          </p>
        </section>

        <section className="card-glass">
          <h2>Technology stack</h2>
          <ul className="tech-list">
            <li><strong>Frontend</strong> React 18 + Vite, custom CSS design system</li>
            <li><strong>Backend</strong> FastAPI (Python)</li>
            <li><strong>ML</strong> scikit-learn + XGBoost, SHAP explainability</li>
            <li><strong>Database</strong> SQLAlchemy — PostgreSQL in production, SQLite fallback</li>
            <li><strong>Deployment</strong> Docker Compose; Render blueprint included</li>
          </ul>
          <h2>Security design</h2>
          <ul className="tips">
            <li>✓ Never visits or fetches submitted URLs — pure string analysis.</li>
            <li>✓ SSRF hardening: private/reserved targets rejected, including obfuscated literals.</li>
            <li>✓ No hardcoded per-URL verdicts; guardrails are pattern classes only.</li>
            <li>✓ DNS existence via DNS-over-HTTPS, fail-open on resolver errors.</li>
            <li>✓ Rate limiting, input validation and bounded history pagination.</li>
          </ul>
        </section>
      </div>

      <section className="card-glass">
        <h2>The ML pipeline</h2>
        <ol className="pipeline-steps vertical">
          {PIPELINE.map((s, i) => (
            <li key={s.title}>
              <span className="step-num">{i + 1}</span>
              <div>
                <strong>{s.title}</strong>
                <p>{s.body}</p>
              </div>
            </li>
          ))}
        </ol>
      </section>

      <section className="card-glass">
        <h2>The models</h2>
        <div className="model-cards">
          {MODELS.map((m) => (
            <article key={m.name} className={`model-card ${data?.model_name === m.name ? "served" : ""}`}>
              <h3>{m.name}</h3>
              {data?.model_name === m.name && <span className="served-tag">serving</span>}
              <p>{m.role}</p>
              {data && <ModelMiniStats comparison={data.comparison} name={m.name} />}
            </article>
          ))}
        </div>
        <p className="char-note">
          SHAP explainability: tree models use TreeExplainer; the linear baseline uses the
          equivalent additive decomposition. The top contributions for every scan are shown
          in the threat-analysis card.
        </p>
      </section>

      <section className="card-glass" aria-label="Model information">
        <h2>Model information</h2>
        {status === "loading" && <LoadingState label="Loading model information…" />}
        {status === "error" && <ErrorState title={error || "Model information unavailable."} hint="The API may be offline. Metrics are only shown when the backend provides them." onRetry={reload} />}
        {status === "ready" && data && (
          <dl className="model-info-grid">
            <div><dt>Model name</dt><dd>{data.model_name}</dd></div>
            <div><dt>Model version</dt><dd>{data.model_version}</dd></div>
            <div><dt>Feature count</dt><dd>{data.feature_names?.length ?? "—"}</dd></div>
            <div><dt>Classifications</dt><dd>LEGITIMATE · SUSPICIOUS · PHISHING</dd></div>
            <div><dt>Verdict thresholds</dt><dd>phishing ≥ {data.thresholds?.phishing_threshold} · suspicious ≥ {data.thresholds?.suspicious_threshold}</dd></div>
            <div><dt>Last trained</dt><dd>{data.trained_at ? new Date(data.trained_at).toLocaleString() : "—"}</dd></div>
            <div><dt>Dataset size</dt><dd>{data.dataset?.total ? `${data.dataset.total.toLocaleString()} URLs` : "—"}</dd></div>
            <div><dt>Scans recorded</dt><dd>{data.history?.total_scans?.toLocaleString?.() ?? "—"}</dd></div>
          </dl>
        )}
        {status === "ready" && data?.metrics && (
          <>
            <h3 className="metrics-sub">Test-set evaluation metrics (reported by the backend)</h3>
            <div className="metrics-grid">
              <Metric label="Accuracy" value={data.metrics.accuracy} />
              <Metric label="Precision" value={data.metrics.precision} />
              <Metric label="Recall" value={data.metrics.recall} />
              <Metric label="F1 score" value={data.metrics.f1_score} />
              <Metric label="ROC-AUC" value={data.metrics.roc_auc} />
              <Metric label="PR-AUC" value={data.metrics.pr_auc} />
            </div>
          </>
        )}
        {status === "ready" && !data?.metrics && (
          <p className="char-note">Evaluation metrics were not found in the model bundle; none are shown.</p>
        )}
      </section>
    </div>
  );
}

function Metric({ label, value }) {
  return (
    <div className="metric">
      <span className="metric-value">{value != null ? fmtPct(value * 100, 2) : "—"}</span>
      <span className="metric-label">{label}</span>
    </div>
  );
}

function ModelMiniStats({ comparison, name }) {
  const entry = (comparison || []).find((c) => c.model === name);
  if (!entry) return null;
  return (
    <p className="model-mini">
      accuracy {(entry.accuracy * 100).toFixed(1)}% · F1 {(entry.f1_score * 100).toFixed(1)}%
    </p>
  );
}
