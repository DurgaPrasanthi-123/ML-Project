import { useEffect, useState } from "react";
import ScanHistory from "../components/ScanHistory.jsx";
import { navigate } from "../lib/router.jsx";

/** Full scan history: search, prediction filter, pagination, analyze-again. */
export default function HistoryPage() {
  // "Analyze again" sends the stored URL to the analyzer page via a custom
  // event — no external navigation, no auto-analysis.
  function analyzeAgain(item) {
    navigate("analyze");
    window.dispatchEvent(
      new CustomEvent("sentinel:analyze", { detail: { url: item.url } })
    );
  }

  return (
    <div className="page">
      <header className="page-head">
        <h1>Scan History</h1>
        <p>Every analysis recorded by this deployment, newest first.</p>
      </header>
      <ScanHistory onAnalyzeAgain={analyzeAgain} />
    </div>
  );
}
