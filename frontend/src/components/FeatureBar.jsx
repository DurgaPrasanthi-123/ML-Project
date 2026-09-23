import { featureLabel } from "../lib/format.js";

/**
 * One signed SHAP contribution as a horizontal bar.
 * `scale` normalizes bar widths across the set (max |impact|).
 * Shows the human label plus the raw feature key used by the model.
 */
export default function FeatureBar({ feature, impact, direction, scale = 1 }) {
  const magnitude = Math.min(Math.abs(impact) / (scale || 1), 1) * 100;
  return (
    <li className="feature-bar">
      <span className="feature-name" title={`${feature} = raw model feature`}>
        {featureLabel(feature)}
        <small>{feature}</small>
      </span>
      <span className="bar-track">
        <span
          className={`bar ${direction}`}
          style={{ width: `${Math.max(magnitude, 2)}%` }}
        />
      </span>
      <span className={`direction ${direction}`}>
        {direction === "phishing" ? "↑ risk" : "↓ safe"}
      </span>
    </li>
  );
}
