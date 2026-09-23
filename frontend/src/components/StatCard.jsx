/** Compact metric card: big number + label + optional accent variant. */
export default function StatCard({ label, value, sub, variant = "", icon }) {
  return (
    <div className={`stat-card ${variant}`.trim()}>
      {icon && <span className="stat-icon" aria-hidden="true">{icon}</span>}
      <div>
        <div className="stat-value">{value}</div>
        <div className="stat-label">{label}</div>
        {sub && <div className="stat-sub">{sub}</div>}
      </div>
    </div>
  );
}
