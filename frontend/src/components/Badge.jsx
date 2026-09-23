/** Small pill badge; class variants come from styles.css (.badge.ok/.warn/.bad/.muted). */
export default function Badge({ variant = "muted", children, className = "" }) {
  return <span className={`badge ${variant} ${className}`.trim()}>{children}</span>;
}
