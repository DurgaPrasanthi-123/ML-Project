import { useEffect, useState } from "react";
import { Link, useRoute } from "../lib/router.jsx";

const NAV_ITEMS = [
  { route: "dashboard", label: "Dashboard" },
  { route: "analyze", label: "Analyze" },
  { route: "history", label: "History" },
  { route: "analytics", label: "Analytics" },
  { route: "guide", label: "Security Guide" },
  { route: "about", label: "About" },
];

/**
 * Brand: a purely typographic wordmark — "Phish" at full weight, ".ML" lighter.
 * No glyph or icon; the wordmark itself is the mark.
 */
export function Brand() {
  return (
    <Link to="dashboard" className="brand" aria-label="Phish.ML — dashboard">
      <span className="brand-name">
        Phish<em>.ML</em>
      </span>
    </Link>
  );
}

export default function Navbar() {
  const route = useRoute();
  const [open, setOpen] = useState(false);

  // Close the mobile menu whenever the route changes.
  useEffect(() => {
    setOpen(false);
  }, [route]);

  // Escape closes the mobile menu; focus stays on the page.
  useEffect(() => {
    if (!open) return undefined;
    const onKey = (e) => {
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  return (
    <header className="nav-shell">
      <nav className="nav" aria-label="Primary">
        <Brand />
        <button
          type="button"
          className="nav-toggle"
          aria-expanded={open}
          aria-controls="nav-links"
          aria-label={open ? "Close menu" : "Open menu"}
          onClick={() => setOpen((o) => !o)}
        >
          <span aria-hidden="true">{open ? "✕" : "☰"}</span>
        </button>
        <ul id="nav-links" className={`nav-links ${open ? "open" : ""}`}>
          {NAV_ITEMS.map((item) => (
            <li key={item.route}>
              <Link
                to={item.route}
                className={`nav-link ${route === item.route ? "active" : ""}`}
                aria-current={route === item.route ? "page" : undefined}
              >
                {item.label}
              </Link>
            </li>
          ))}
        </ul>
      </nav>
    </header>
  );
}
