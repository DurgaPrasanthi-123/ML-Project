/** Shared empty / error / no-results states. */
export function EmptyState({ icon = "◎", title, hint }) {
  return (
    <div className="state">
      <span className="state-icon" aria-hidden="true">{icon}</span>
      <p className="state-title">{title}</p>
      {hint && <p className="state-hint">{hint}</p>}
    </div>
  );
}

export function ErrorState({ title = "Something went wrong.", hint, onRetry }) {
  return (
    <div className="state error" role="alert">
      <span className="state-icon" aria-hidden="true">⚠</span>
      <p className="state-title">{title}</p>
      {hint && <p className="state-hint">{hint}</p>}
      {onRetry && (
        <button type="button" className="btn ghost" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  );
}

export function NoResultsState({ hint }) {
  return (
    <div className="state">
      <span className="state-icon" aria-hidden="true">⌕</span>
      <p className="state-title">No matching scans</p>
      {hint && <p className="state-hint">{hint}</p>}
    </div>
  );
}

export function LoadingState({ label = "Loading…" }) {
  return (
    <div className="state loading" aria-live="polite" aria-busy="true">
      <span className="spinner" aria-hidden="true" />
      <p className="state-title">{label}</p>
    </div>
  );
}
