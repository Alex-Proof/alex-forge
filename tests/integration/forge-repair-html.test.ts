import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import AdmZip from "adm-zip";
import { afterEach, describe, expect, it } from "vitest";
import { main } from "../../src/cli.js";

const tempDirs: string[] = [];
async function freshDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

// The HTML counterpart to tests/integration/forge-repair.test.ts: drives the real `forge` CLI
// entry point with `--format html`, which must take the no-Docker, real-headless-Chromium path
// (generateHtmlArtifact + verifyHtmlArtifact) instead of the sandboxed CLI red/green path, but
// land in the exact same evidence/export/independent-re-verify/catalog chain. Nothing here is
// mocked: the browser actually runs, the ZIP is a real file on disk, and the catalog record comes
// from a real `forge catalog list` call.
describe("forge repair --format html (end to end, log to ZIP)", () => {
  it(
    "diagnoses, verifies in a real browser, exports repair.html, and admits it to the catalog",
    async () => {
      const workDir = await freshDir("forge-cli-html-e2e-");
      const logPath = path.join(workDir, "error.log");
      await writeFile(logPath, "Error: listen EADDRINUSE: address already in use :::3000\n");
      const outputDir = path.join(workDir, "out");
      const catalogDir = path.join(workDir, "catalog");

      const result = await main([
        "repair",
        "--log",
        logPath,
        "--os",
        "linux",
        "--output",
        outputDir,
        "--format",
        "html",
        "--catalog-dir",
        catalogDir,
        "--json",
      ]);

      expect(result.exitCode).toBe(0);
      const report = JSON.parse(result.stdout);
      expect(report.status).toBe("approved");
      expect(existsSync(report.zipPath)).toBe(true);
      expect(report.catalogArtifact.status).toBe("approved");
      expect(report.catalogArtifact.format).toBe("html");

      const zip = new AdmZip(report.zipPath);
      const artifactEntry = zip.getEntry("artifact/repair.html");
      expect(artifactEntry).not.toBeNull();
      const html = artifactEntry?.getData().toString("utf-8") ?? "";
      expect(html).toContain("<!doctype html>");
      expect(html).toContain("Content-Security-Policy");

      const evidenceEntry = zip.getEntry("evidence.json");
      const evidence = JSON.parse(evidenceEntry?.getData().toString("utf-8") ?? "{}");
      expect(evidence.artifact.format).toBe("html");
      expect(evidence.verification.level).toBe("L2_sandbox_executed");
      expect(evidence.verification.status).toBe("passed");

      const catalogList = await main(["catalog", "list", "--catalog-dir", catalogDir, "--json"]);
      expect(catalogList.exitCode).toBe(0);
      const records = JSON.parse(catalogList.stdout);
      expect(records).toHaveLength(1);
      expect(records[0].artifactHash).toBe(report.catalogArtifact.artifactHash);
      expect(records[0].format).toBe("html");
    },
    30_000,
  );

  it("rejects an unrecognized --format value with exit code 2", async () => {
    const result = await main(["repair", "--log", "./x", "--os", "linux", "--output", "./out", "--format", "exe"]);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toMatch(/invalid --format value/);
  });
});
