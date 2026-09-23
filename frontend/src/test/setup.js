import "@testing-library/jest-dom/vitest";

// jsdom lacks AbortSignal.addEventListener plumbing used by the api client in
// some paths; keep fetch mockable per-test. Tests mock global.fetch directly.
import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";

afterEach(() => {
  cleanup();
});
