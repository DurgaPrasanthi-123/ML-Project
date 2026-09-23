import { useCallback, useEffect, useRef, useState } from "react";
import { fetchModelInfo, ApiError } from "../api.js";

/**
 * Session-wide cache for /model-info: Navbar, Footer, Dashboard and About all
 * consume the same fetch instead of refetching per component.
 */
let cache = null;
let inflight = null;

function loadModelInfo() {
  if (cache) return Promise.resolve(cache);
  if (!inflight) {
    inflight = fetchModelInfo()
      .then((data) => {
        cache = data;
        inflight = null;
        return data;
      })
      .catch((err) => {
        inflight = null;
        throw err;
      });
  }
  return inflight;
}

/**
 * Loads /model-info once for the whole app. Failure degrades to
 * { status: "error" } so pages can show their own fallbacks — model metadata
 * is never fabricated client-side.
 */
export function useModelInfo() {
  const [state, setState] = useState(() =>
    cache ? { status: "ready", data: cache } : { status: "loading", data: null }
  );
  const cancelled = useRef(false);

  const load = useCallback(async () => {
    setState((s) => ({ ...s, status: s.data ? "refreshing" : "loading" }));
    try {
      const data = await loadModelInfo();
      if (cancelled.current) return;
      setState({ status: "ready", data });
    } catch (err) {
      if (cancelled.current) return;
      const message =
        err instanceof ApiError && err.status === 503
          ? "Model information is not available right now."
          : "Could not load model information.";
      setState({ status: "error", data: null, error: message });
    }
  }, []);

  useEffect(() => {
    cancelled.current = false;
    if (!cache) load();
    return () => {
      cancelled.current = true;
    };
  }, [load]);

  return { ...state, reload: load };
}
