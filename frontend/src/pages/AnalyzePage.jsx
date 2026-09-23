import { useEffect, useRef, useState } from "react";
import UrlForm from "../components/UrlForm.jsx";
import ResultCard from "../components/ResultCard.jsx";
import { ErrorState, LoadingState } from "../components/States.jsx";
import { predictUrl, ApiError } from "../api.js";

/**
 * The analyzer: large input, loading animation, threat-analysis result card.
 * Also listens for "sentinel:analyze" events (from history's "Analyze again")
 * and runs the analysis for the given URL.
 */
export default function AnalyzePage({ onAnalyzed }) {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const running = useRef(false);

  async function analyze(url) {
    if (running.current) return;
    running.current = true;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const data = await predictUrl(url);
      setResult(data);
      onAnalyzed?.(data);
    } catch (err) {
      if (err instanceof ApiError) setError(err.message);
      else setError("Something went wrong while analyzing the URL.");
    } finally {
      running.current = false;
      setLoading(false);
    }
  }

  useEffect(() => {
    const onAnalyzeEvent = (e) => {
      const url = e.detail?.url;
      if (typeof url === "string" && url) analyze(url);
    };
    window.addEventListener("sentinel:analyze", onAnalyzeEvent);
    return () => window.removeEventListener("sentinel:analyze", onAnalyzeEvent);
  }, []);

  return (
    <div className="page">
      <header className="page-head center">
        <h1>URL Threat Analyzer</h1>
        <p>Analyze a URL before interacting with it — the service never visits it.</p>
      </header>

      <UrlForm onSubmit={analyze} loading={loading} submitLabel="Analyze" />

      {error && (
        <ErrorState
          title={error}
          hint="If this keeps happening, the API may be down or the URL may be rejected by validation."
          onRetry={() => setError("")}
        />
      )}

      {loading && <LoadingState label="Analyzing URL — extracting features and running the model…" />}

      {result && <ResultCard result={result} />}
    </div>
  );
}
