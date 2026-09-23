import { useEffect, useState } from "react";

const CLASS_BY_LEVEL = {
  legitimate: "ok",
  suspicious: "warn",
  phishing: "bad",
};

/**
 * Circular risk gauge (0-100). The numeric value is always the true final
 * score (accessibility + deterministic rendering); only the arc animates.
 */
export default function RiskDial({ score = 0, level = "legitimate" }) {
  const target = Math.max(0, Math.min(100, Number(score) || 0));
  const [arc, setArc] = useState(target);
  const tone = CLASS_BY_LEVEL[level] || "ok";

  useEffect(() => {
    if (prefersReducedMotion()) {
      setArc(target);
      return undefined;
    }
    setArc(0);
    let raf;
    const start = performance.now();
    const tick = (now) => {
      const t = Math.min((now - start) / 900, 1);
      setArc(target * (1 - Math.pow(1 - t, 3)));
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target]);

  const R = 52;
  const C = 2 * Math.PI * R;
  const filled = (arc / 100) * C;

  return (
    <div className={`risk-dial ${tone}`} role="img" aria-label={`Risk score ${target} of 100`}>
      <svg viewBox="0 0 128 128" width="128" height="128" aria-hidden="true">
        <circle className="dial-track" cx="64" cy="64" r={R} />
        <circle
          className="dial-fill"
          cx="64"
          cy="64"
          r={R}
          strokeDasharray={`${filled} ${C - filled}`}
          transform="rotate(-90 64 64)"
        />
      </svg>
      <div className="dial-center">
        <span className="dial-value">{target}</span>
        <span className="dial-label">RISK</span>
      </div>
    </div>
  );
}

function prefersReducedMotion() {
  return typeof window !== "undefined" &&
    window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
}
