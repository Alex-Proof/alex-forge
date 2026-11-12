import { describe, expect, it } from "vitest";
import { validateHtmlArtifact } from "./html.js";
import { getRegisteredAction } from "../modes/repair/actions.js";

const action = getRegisteredAction("free-tcp-port");

describe("validateHtmlArtifact", () => {
  it("accepts the real generated free-tcp-port report", () => {
    expect(action?.generateHtml).toBeDefined();
    const html = action!.generateHtml!({ port: 3000 });
    const result = validateHtmlArtifact(html);
    expect(result.valid).toBe(true);
    expect(result.findings).toEqual([]);
  });

  it("rejects an artifact with an external script reference", () => {
    const html = `<!doctype html><html><head><script src="https://evil.example/x.js"></script></head><body></body></html>`;
    expect(validateHtmlArtifact(html).valid).toBe(false);
  });

  it("rejects an artifact using fetch()", () => {
    const html = `<!doctype html><html><body><script>fetch("https://evil.example");</script></body></html>`;
    const result = validateHtmlArtifact(html);
    expect(result.valid).toBe(false);
    expect(result.findings.some((f) => f.ruleId === "html-network-api")).toBe(true);
  });

  it("rejects an artifact with an inline event handler attribute", () => {
    const html = `<!doctype html><html><body><button onclick="doStuff()">go</button></body></html>`;
    const result = validateHtmlArtifact(html);
    expect(result.findings.some((f) => f.ruleId === "html-inline-event-handler")).toBe(true);
  });

  it("rejects an artifact that assigns innerHTML", () => {
    const html = `<!doctype html><html><body><script>el.innerHTML = userInput;</script></body></html>`;
    const result = validateHtmlArtifact(html);
    expect(result.findings.some((f) => f.ruleId === "html-inner-html-assignment")).toBe(true);
  });

  it("rejects an artifact with no CSP meta tag", () => {
    const html = `<!doctype html><html><head></head><body>hi</body></html>`;
    const result = validateHtmlArtifact(html);
    expect(result.findings.some((f) => f.ruleId === "html-missing-csp")).toBe(true);
  });

  it("rejects a CSP that still allows 'unsafe-inline'", () => {
    const html = `<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'"></head><body></body></html>`;
    const result = validateHtmlArtifact(html);
    expect(result.findings.some((f) => f.ruleId === "html-unsafe-csp-token")).toBe(true);
  });

  it("rejects eval()", () => {
    const html = `<!doctype html><html><body><script>eval("2+2");</script></body></html>`;
    const result = validateHtmlArtifact(html);
    expect(result.findings.some((f) => f.ruleId === "html-eval")).toBe(true);
  });
});
