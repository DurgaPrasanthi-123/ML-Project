import { Link } from "../lib/router.jsx";
import { useModelInfo } from "../lib/hooks.js";
import { Brand } from "./Navbar.jsx";

/** Global footer: brand, live model version, stack, disclaimer, nav links. */
export default function Footer() {
  const { data } = useModelInfo();
  const modelName = data?.model_name || "ML ensemble";
  const modelVersion = data?.model_version ? `v${data.model_version}` : "";

  return (
    <footer className="footer">
      <div className="footer-grid">
        <div className="footer-brand">
          <Brand />
          <p className="footer-note">
            Machine-learning powered URL analysis with transparent risk scoring
            and explainable predictions.
          </p>
          <p className="footer-meta">
            {modelName} {modelVersion && <strong>{modelVersion}</strong>} · React + FastAPI +
            XGBoost · SHAP explainability
          </p>
        </div>
        <nav className="footer-nav" aria-label="Footer">
          <h3>Product</h3>
          <Link to="dashboard">Dashboard</Link>
          <Link to="analyze">Analyze</Link>
          <Link to="history">Scan history</Link>
          <Link to="analytics">Analytics</Link>
        </nav>
        <nav className="footer-nav" aria-label="Footer resources">
          <h3>Resources</h3>
          <Link to="guide">Security guide</Link>
          <Link to="about">How it works</Link>
          <Link to="about">Model information</Link>
        </nav>
      </div>
      <p className="footer-disclaimer">
        Educational capstone project. Predictions are probabilistic ML assessments of URL
        structure — never a guarantee that a site is safe or malicious. Always apply your
        own judgement.
      </p>
    </footer>
  );
}
