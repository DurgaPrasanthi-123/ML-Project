import { urlShape } from "../lib/urlShape.js";
import { featureLabel, fmtPct, verdictClass } from "../lib/format.js";
import RiskDial from "./RiskDial.jsx";
import FeatureBar from "./FeatureBar.jsx";
import Badge from "./Badge.jsx";

const VERDICT_COPY = {
  LEGITIMATE: {
    title: "No strong phishing signals found",
    detail: "The model considers this URL consistent with legitimate patterns.",
  },
  SUSPICIOUS: {
    title: "Mixed signals — treat with caution",
    detail: "Some structural traits resemble phishing patterns. Verify before interacting.",
  },
  PHISHING: {
    title: "Strong phishing indicators",
    detail: "The model considers this URL consistent with known phishing structures.",
  },
};

/**
 * The threat-analysis centerpiece. Everything shown comes from the backend's
 * /predict response — nothing is fabricated client-side. URL characteristics
 * are a factual decomposition of the submitted string, not model features.
 */
export default function ResultCard({ result }) {
  const cls = result.prediction.toLowerCase(); // legitimate | suspicious | phishing
  const tone = verdictClass(result.prediction);
  const copy = VERDICT_COPY[result.prediction] || VERDICT_COPY.SUSPICIOUS;
  const shape = urlShape(result.normalized_url || result.url);
  const contribs = result.contributing_features || [];
  const scale = Math.max(...contribs.map((c) => Math.abs(c.impact)), 0.001);

  return (
    <section className={`card-glass result ${cls}`} aria-label="Threat analysis result">
      <div className="result-head">
        <RiskDial score={result.risk_score} level={cls} />
        <div className="result-verdict">
          <span className="result-kicker">THREAT ANALYSIS</span>
          <h2 className={`verdict ${tone}`}>{result.prediction}</h2>
          <p className="result-copy">{copy.title}. {copy.detail}</p>
          <dl className="result-metrics">
            <div>
              <dt>Confidence</dt>
              <dd>{fmtPct(result.confidence)}</dd>
            </div>
            <div>
              <dt>P(phishing)</dt>
              <dd>{fmtPct(result.probability_phishing * 100)}</dd>
            </div>
            <div>
              <dt>Model</dt>
              <dd>
                {result.model_name} <span className="model-ver">{result.model_version}</span>
              </dd>
            </div>
          </dl>
        </div>
      </div>

      <div className="result-url">
        <Badge variant={tone}>{result.risk_level || result.prediction}</Badge>
        <code title={result.normalized_url}>{result.normalized_url || result.url}</code>
      </div>

      {result.guardrail_flags?.length > 0 && (
        <div className="flags">
          <h3>Guardrail indicators</h3>
          {result.guardrail_flags.map((f, i) => (
            <div key={i} className="flag">
              <span aria-hidden="true">⚑</span> {f}
            </div>
          ))}
        </div>
      )}

      {shape && (
        <div className="char-grid" aria-label="URL characteristics">
          <h3>URL characteristics</h3>
          <ul>
            <Characteristic label="HTTPS" value={shape.https} good={shape.https} />
            <Characteristic
              label="IP-address host"
              value={shape.isIp}
              good={!shape.isIp}
            />
            <Characteristic label="Hostname length" value={shape.hostname.length} warn={shape.hostname.length > 40} />
            <Characteristic label="Path length" value={shape.pathLength} warn={shape.pathLength > 60} />
            <Characteristic label="Subdomain depth" value={shape.subdomainDepth} warn={shape.subdomainDepth >= 2} />
            <Characteristic label="Special characters" value={shape.specialChars} warn={shape.specialChars > 12} />
            <Characteristic label="Query parameters" value={shape.query ? shape.query.replace(/^\?/, "").split("&").length : 0} />
            <Characteristic label="Port" value={shape.port ? `${shape.port} (explicit)` : "default"} warn={!!shape.port && ![80, 443].includes(shape.port)} />
          </ul>
          <p className="char-note">
            Facts computed from the submitted string in-browser; they inform the model&apos;s
            feature vector but are not verdicts on their own.
          </p>
        </div>
      )}

      <div className="contrib" data-testid="why-this-verdict">
        <h3>Why this verdict — SHAP contributions</h3>
        {contribs.length === 0 ? (
          <p className="muted-note">No feature contributions were returned for this scan.</p>
        ) : (
          <ul>
            {contribs.map((c) => (
              <FeatureBar
                key={c.feature}
                feature={c.feature}
                impact={c.impact}
                direction={c.direction}
                scale={scale}
              />
            ))}
          </ul>
        )}
        <p className="char-note">
          Bars show how strongly each feature pushed the verdict toward phishing (↑ risk) or
          legitimate (↓ safe), computed with SHAP explainability.
        </p>
      </div>

      {result.dns_check?.checked && (
        <div className="dns-note">
          DNS check: domain{" "}
          {result.dns_check.exists
            ? "resolves in global DNS ✓"
            : "has no DNS records ✗ (common for fabricated phishing domains)"}
        </div>
      )}

      <p className="result-disclaimer">
        This is a machine-learning assessment of URL structure — a strong signal, not a
        guarantee. When in doubt, reach the site through a trusted bookmark.
      </p>
    </section>
  );
}

function Characteristic({ label, value, good, warn }) {
  const tone = good === true ? "ok" : warn ? "warn" : "";
  return (
    <li className={`char-item ${tone}`}>
      <span className="char-label">{label}</span>
      <span className="char-value">
        {typeof value === "boolean" ? (value ? "✓" : "✗") : String(value)}
      </span>
    </li>
  );
}
