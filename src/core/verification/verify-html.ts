/// <reference lib="dom" />
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { chromium, type Browser } from "playwright";
import type { VerificationCheck, VerificationSummary } from "../../types/verification.js";
import { validateHtmlArtifact } from "../../formats/html.js";

export interface HtmlVerificationFixture {
  html: string;
  /** The port value Forge embedded at generation time; used to check the default render. */
  expectedDefaultPort: number;
}

function check(name: string, passed: boolean, details?: Record<string, unknown>): VerificationCheck {
  return { name, status: passed ? "passed" : "failed", exitCode: null, details };
}

/**
 * Real browser verification for a standalone HTML repair artifact. There is no OS-level fault to
 * reproduce here (a browser cannot free a TCP port), so this never claims L3 state-transition
 * verification -- it proves the artifact's own client-side logic behaves correctly and that its
 * CSP genuinely blocks what it claims to block, using a real headless Chromium instance as the
 * sandboxed execution environment (hence L2_sandbox_executed on success, matching the blueprint's
 * "Logik mit festen Inputs geprüft" language for this format).
 */
export async function verifyHtmlArtifact(fixture: HtmlVerificationFixture): Promise<VerificationSummary> {
  const checks: VerificationCheck[] = [];

  const staticResult = validateHtmlArtifact(fixture.html);
  checks.push(check("static_html_policy", staticResult.valid, { findings: staticResult.findings }));
  if (!staticResult.valid) {
    return { status: "failed", level: "L1_static_validated", checks };
  }

  const dir = await mkdtemp(path.join(tmpdir(), "forge-html-verify-"));
  const filePath = path.join(dir, "repair.html");
  let browser: Browser | undefined;
  try {
    await writeFile(filePath, fixture.html);
    browser = await chromium.launch();
    const page = await browser.newPage();

    let dialogAppeared = false;
    page.on("dialog", async (dialog) => {
      dialogAppeared = true;
      await dialog.dismiss();
    });
    const cspViolations: string[] = [];
    page.on("console", (msg) => {
      if (/content security policy/i.test(msg.text())) {
        cspViolations.push(msg.text());
      }
    });

    await page.goto(`file://${filePath}`);

    const defaultValidation = await page.textContent("#validation-result");
    checks.push(
      check("renders_default_state", defaultValidation === `Valid port number: ${fixture.expectedDefaultPort}`, {
        actual: defaultValidation,
      }),
    );

    const downloadHref = await page.getAttribute("#download-link", "href");
    checks.push(check("download_link_is_offline_blob", Boolean(downloadHref?.startsWith("blob:"))));

    await page.fill("#port-input", "8080");
    const reValidation = await page.textContent("#validation-result");
    checks.push(check("client_logic_responds_to_fixed_input", reValidation === "Valid port number: 8080"));

    await page.fill("#port-input", "<img src=x onerror=window.__xss=1>");
    await page.waitForTimeout(100);
    const xssFired = await page.evaluate(() => (window as unknown as { __xss?: number }).__xss);
    const resultHtmlAfterXss = await page.$eval("#validation-result", (el) => el.innerHTML);
    checks.push(
      check(
        "dom_xss_injection_does_not_execute",
        xssFired === undefined && !dialogAppeared && !resultHtmlAfterXss.includes("<img"),
        { xssFired, dialogAppeared, resultHtmlAfterXss },
      ),
    );

    const injectedRan = await page.evaluate(() => {
      (window as unknown as { __injected: boolean }).__injected = false;
      const injected = document.createElement("script");
      injected.textContent = "window.__injected = true;";
      document.body.appendChild(injected);
      return new Promise((resolve) => setTimeout(() => resolve((window as unknown as { __injected: boolean }).__injected), 100));
    });
    checks.push(
      check("csp_blocks_non_allowlisted_inline_script", injectedRan === false && cspViolations.length > 0),
    );

    const fetchOutcome = await page.evaluate(async () => {
      try {
        await fetch("https://example.com/");
        return "succeeded";
      } catch {
        return "failed";
      }
    });
    checks.push(check("csp_blocks_outbound_network_request", fetchOutcome === "failed"));
  } finally {
    await browser?.close();
    await rm(dir, { recursive: true, force: true });
  }

  const allPassed = checks.every((c) => c.status === "passed");
  return {
    status: allPassed ? "passed" : "failed",
    level: allPassed ? "L2_sandbox_executed" : "L1_static_validated",
    checks,
  };
}
