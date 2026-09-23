import { describe, expect, it } from "vitest";
import { validateUrl } from "../components/UrlForm.jsx";

describe("validateUrl (client-side mirror of backend rules)", () => {
  it("accepts ordinary http(s) URLs", () => {
    expect(validateUrl("https://example.com/login")).toBe("");
    expect(validateUrl("http://23.22.14.105:8080/x")).toBe("");
  });

  it("trims surrounding whitespace before validating", () => {
    expect(validateUrl("  https://example.com  ")).toBe("");
  });

  it("rejects empty and too-short input", () => {
    expect(validateUrl("")).toBe("Enter a URL to analyze.");
    expect(validateUrl("   ")).toBe("Enter a URL to analyze.");
    expect(validateUrl("ab")).toBe("URL is too short.");
  });

  it("rejects internal whitespace", () => {
    expect(validateUrl("https://ex ample.com")).toBe("URL must not contain whitespace.");
  });

  it("rejects dangerous schemes", () => {
    for (const bad of ["javascript:alert(1)", "data:text/html,hi", "vbscript:x", "file:///etc/passwd"]) {
      expect(validateUrl(bad)).toBe("This URL scheme is not allowed.");
    }
  });

  it("accepts scheme-less input (backend normalizes to https)", () => {
    expect(validateUrl("example.com/login")).toBe("");
  });
});
