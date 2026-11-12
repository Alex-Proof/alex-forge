/// <reference lib="dom" />
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { chromium, type Browser, type Page } from "playwright";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { diagnoseFallback, generateHtmlArtifact } from "./diagnose.js";
import { validateHtmlArtifact } from "../../formats/html.js";

/**
 * Real browser tests for the standalone HTML repair artifact (blueprint Phase 7: "DOM-XSS-
 * Prüfungen", "Funktionstests"). A static string check cannot prove a browser will actually
 * refuse to run something -- these tests load the generated page in real headless Chromium and
 * observe real DOM/CSP behavior, the same discipline Phase 2-6 applied to the CLI artifact in a
 * real Docker sandbox.
 */

let browser: Browser;
let page: Page;
const tempDirs: string[] = [];

beforeAll(async () => {
  browser = await chromium.launch();
});
afterAll(async () => {
  await browser.close();
});
afterEach(async () => {
  await page?.close();
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function loadGeneratedHtml(html: string): Promise<Page> {
  const dir = await mkdtemp(path.join(tmpdir(), "forge-html-fixture-"));
  tempDirs.push(dir);
  const filePath = path.join(dir, "repair.html");
  await writeFile(filePath, html);
  page = await browser.newPage();
  await page.goto(`file://${filePath}`);
  return page;
}

function buildArtifact(port: number) {
  const diagnosis = diagnoseFallback(
    `Error: listen EADDRINUSE: address already in use :::${port}`,
    "linux",
  );
  const artifact = generateHtmlArtifact(diagnosis);
  if (!artifact.ok) {
    throw new Error(`expected a generated artifact, got: ${artifact.reason}`);
  }
  return artifact;
}

describe("standalone HTML repair artifact (real browser)", () => {
  it("passes static validation", () => {
    const artifact = buildArtifact(3000);
    const result = validateHtmlArtifact(artifact.content);
    expect(result.valid).toBe(true);
  });

  it("renders the embedded script and a correct default validation result", async () => {
    const artifact = buildArtifact(3000);
    const loaded = await loadGeneratedHtml(artifact.content);

    const scriptText = await loaded.textContent("#script-content");
    expect(scriptText).toContain("PORT=3000");

    const validationText = await loaded.textContent("#validation-result");
    expect(validationText).toBe("Valid port number: 3000");

    const downloadHref = await loaded.getAttribute("#download-link", "href");
    expect(downloadHref).toMatch(/^blob:/);
  });

  it("re-validates correctly as the user edits the port input (real client-side logic, fixed inputs)", async () => {
    const artifact = buildArtifact(3000);
    const loaded = await loadGeneratedHtml(artifact.content);

    await loaded.fill("#port-input", "8080");
    expect(await loaded.textContent("#validation-result")).toBe("Valid port number: 8080");

    await loaded.fill("#port-input", "99999");
    expect(await loaded.textContent("#validation-result")).toMatch(/not a valid port number/i);

    await loaded.fill("#port-input", "0");
    expect(await loaded.textContent("#validation-result")).toMatch(/not a valid port number/i);
  });

  it("does not execute markup injected into the port input (DOM-XSS)", async () => {
    const artifact = buildArtifact(3000);
    const loaded = await loadGeneratedHtml(artifact.content);

    let dialogAppeared = false;
    loaded.on("dialog", async (dialog) => {
      dialogAppeared = true;
      await dialog.dismiss();
    });

    await loaded.fill("#port-input", "<img src=x onerror=window.__xss=1>");
    await loaded.waitForTimeout(100);

    const xssFired = await loaded.evaluate(() => (window as unknown as { __xss?: number }).__xss);
    expect(xssFired).toBeUndefined();
    expect(dialogAppeared).toBe(false);

    const resultHtml = await loaded.$eval("#validation-result", (el) => el.innerHTML);
    expect(resultHtml).not.toContain("<img");
    expect(await loaded.textContent("#validation-result")).toMatch(/not a valid port number/i);
  });

  it("refuses to execute a freshly injected inline script that is not in the CSP hash allowlist", async () => {
    const artifact = buildArtifact(3000);
    const loaded = await loadGeneratedHtml(artifact.content);

    const cspViolations: string[] = [];
    loaded.on("console", (msg) => {
      if (/content security policy/i.test(msg.text())) {
        cspViolations.push(msg.text());
      }
    });

    await loaded.evaluate(() => {
      (window as unknown as { __injected: boolean }).__injected = false;
      const injected = document.createElement("script");
      injected.textContent = "window.__injected = true;";
      document.body.appendChild(injected);
    });
    await loaded.waitForTimeout(100);

    const injectedRan = await loaded.evaluate(() => (window as unknown as { __injected: boolean }).__injected);
    expect(injectedRan).toBe(false);
    expect(cspViolations.length).toBeGreaterThan(0);
  });

  it("blocks an attempted outbound network request (connect-src 'none')", async () => {
    const artifact = buildArtifact(3000);
    const loaded = await loadGeneratedHtml(artifact.content);

    const outcome = await loaded.evaluate(async () => {
      try {
        await fetch("https://example.com/");
        return "fetch-succeeded";
      } catch (error) {
        return `fetch-failed: ${error instanceof Error ? error.message : String(error)}`;
      }
    });
    expect(outcome).toMatch(/^fetch-failed/);
  });
});
