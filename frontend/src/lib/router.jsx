import { useEffect, useState } from "react";

/**
 * Minimal hash router: '#/analyze' -> 'analyze'. Keeps the product feeling
 * multi-page without adding a dependency. Unknown routes fall back to
 * 'dashboard'.
 */
export const ROUTES = ["dashboard", "analyze", "history", "analytics", "guide", "about"];

export function parseHash(hash) {
  const name = (hash || "").replace(/^#\/?/, "").split("?")[0].toLowerCase();
  return ROUTES.includes(name) ? name : "dashboard";
}

export function useRoute() {
  const [route, setRoute] = useState(() => parseHash(window.location.hash));
  useEffect(() => {
    const onChange = () => setRoute(parseHash(window.location.hash));
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}

/** Navigate to a route (also used by "Analyze again" / CTA buttons). */
export function navigate(route) {
  window.location.hash = `#/${route}`;
}

export function Link({ to, className, children, ...rest }) {
  return (
    <a href={`#/${to}`} className={className} {...rest}>
      {children}
    </a>
  );
}
