import { useState } from "react";
import { normalizePreview } from "../lib/urlShape.js";

const SAMPLES = [
  { label: "Legitimate", url: "https://en.wikipedia.org/wiki/Machine_learning" },
  { label: "Official brand", url: "https://www.paypal.com/signin" },
  { label: "Subdomain spoof", url: "https://login.paypal.com.session-928431.xyz/login" },
  { label: "IP host", url: "http://23.22.14.105:8080/paypal-security/login.php" },
];

/** Client-side validation only — the backend re-validates authoritatively. */
export function validateUrl(raw) {
  const url = raw.trim();
  if (!url) return "Enter a URL to analyze.";
  if (url.length < 4) return "URL is too short.";
  if (/\s/.test(url)) return "URL must not contain whitespace.";
  if (/^(javascript|data|vbscript|file):/i.test(url)) return "This URL scheme is not allowed.";
  return "";
}

/**
 * The analyzer input. Shows a live preview of the normalized URL so bare
 * domains (example.com) transparently become https://example.com.
 */
export default function UrlForm({ onSubmit, loading, submitLabel = "Analyze" }) {
  const [url, setUrl] = useState("");
  const [validationError, setValidationError] = useState("");

  const trimmed = url.trim();
  const preview = trimmed && !validationError ? normalizePreview(trimmed) : "";
  const showsPreview =
    preview && preview !== trimmed && !/^[a-z]+:\/\//i.test(trimmed);

  function submit(e) {
    e.preventDefault();
    if (loading) return;
    const problem = validateUrl(url);
    setValidationError(problem);
    if (problem) return;
    onSubmit(trimmed);
  }

  function useSample(s) {
    setUrl(s.url);
    setValidationError("");
    if (!loading) onSubmit(s.url);
  }

  return (
    <section className="analyzer card-glass" aria-label="URL analyzer">
      <form onSubmit={submit} className="form" noValidate>
        <div className="input-wrap">
          <span className="input-glyph" aria-hidden="true">⌕</span>
          <input
            type="text"
            value={url}
            onChange={(e) => {
              setUrl(e.target.value);
              if (validationError) setValidationError("");
            }}
            placeholder="https://example.com/login — or just example.com"
            aria-label="URL to analyze"
            aria-invalid={validationError ? "true" : "false"}
            disabled={loading}
            spellCheck="false"
            autoComplete="off"
            inputMode="url"
          />
        </div>
        <button type="submit" className="btn primary" disabled={loading || trimmed.length < 4}>
          {loading ? "Analyzing…" : submitLabel}
        </button>
      </form>

      {showsPreview && (
        <p className="normalize-preview">
          <span aria-hidden="true">⇢</span> will be analyzed as{" "}
          <code>{preview}</code>
        </p>
      )}

      {validationError && (
        <div className="field-error" role="alert">
          <span>{validationError}</span>
          <button
            type="button"
            className="chip field-error-dismiss"
            onClick={() => {
              setValidationError("");
              setUrl("");
            }}
          >
            Clear
          </button>
        </div>
      )}

      <div className="samples" aria-label="Example URLs">
        <span className="samples-label">Try:</span>
        {SAMPLES.map((s) => (
          <button
            key={s.label}
            type="button"
            className="chip"
            disabled={loading}
            onClick={() => useSample(s)}
          >
            {s.label}
          </button>
        ))}
      </div>

      <p className="analyzer-note">
        The service never opens the submitted URL — analysis is lexical and structural only.
      </p>
    </section>
  );
}
