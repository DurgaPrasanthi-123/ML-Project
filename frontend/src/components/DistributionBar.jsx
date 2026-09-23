/**
 * Stacked single-row distribution bar. `segments` = [{key,label,value,pct}].
 * Renders nothing when there is no data (never fabricates a distribution).
 */
export default function DistributionBar({ segments = [] }) {
  const visible = segments.filter((s) => s.value > 0);
  if (!visible.length) {
    return <div className="dist-empty">No data yet — analyze URLs to populate this chart.</div>;
  }
  return (
    <div className="dist" role="img" aria-label={segments.map((s) => `${s.label} ${s.pct.toFixed(0)}%`).join(", ")}>
      <div className="dist-bar">
        {visible.map((s) => (
          <span
            key={s.key}
            className={`dist-seg ${s.key.toLowerCase()}`}
            style={{ width: `${s.pct}%` }}
            title={`${s.label}: ${s.value} (${s.pct.toFixed(1)}%)`}
          />
        ))}
      </div>
      <div className="dist-legend">
        {segments.map((s) => (
          <span key={s.key} className="dist-item">
            <span className={`dist-dot ${s.key.toLowerCase()}`} />
            {s.label}
            <strong>{s.value.toLocaleString()}</strong>
            <em>{s.pct.toFixed(1)}%</em>
          </span>
        ))}
      </div>
    </div>
  );
}
