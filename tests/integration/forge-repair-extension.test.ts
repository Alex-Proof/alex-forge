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

// The extension counterpart to tests/integration/forge-repair.test.ts and
// forge-repair-html.test.ts: drives the real `forge` CLI entry point with `--format extension`,
// which packages a real .vsix via @vscode/vsce and, wherever this environment allows it, runs a
// real VS Code Extension Host launch (no Docker sandbox for this path either). Nothing here is
// mocked. Catalog admission itself is conditional on a real runtime launch actually succeeding in
// this environment -- consistent with src/modes/repair/fixture-extension-catalog.test.ts.
describe("forge repair --format extension (end to end, log to ZIP or honest rejection)", () => {
  it(
    "diagnoses, packages a real .vsix, and gets exactly as far as this environment's runtime allows",
    async () => {
      const workDir = await freshDir("forge-cli-extension-e2e-");
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
        "extension",
        "--catalog-dir",
        catalogDir,
        "--json",
      ]);

      if (result.exitCode === 0) {
        // A real VS Code Extension Host launch succeeded in this environment: full approval,
        // same shape as the sh/html end-to-end tests.
        const report = JSON.parse(result.stdout);
        expect(report.status).toBe("approved");
        expect(existsSync(report.zipPath)).toBe(true);
        expect(report.catalogArtifact.status).toBe("approved");
        expect(report.catalogArtifact.format).toBe("extension");

        const zip = new AdmZip(report.zipPath);
        const artifactEntry = zip.getEntry("artifact/repair.vsix");
        expect(artifactEntry).not.toBeNull();
        const vsixBytes = artifactEntry?.getData();
        expect(vsixBytes?.length).toBeGreaterThan(0);
        // A .vsix is itself a zip; confirm it is a real, openable one, not an opaque blob.
        const innerZip = new AdmZip(vsixBytes);
        expect(innerZip.getEntry("extension/package.json")).not.toBeNull();

        const evidenceEntry = zip.getEntry("evidence.json");
        const evidence = JSON.parse(evidenceEntry?.getData().toString("utf-8") ?? "{}");
        expect(evidence.artifact.format).toBe("extension");
        expect(evidence.verification.level).toBe("L2_sandbox_executed");
        expect(evidence.verification.status).toBe("passed");

        const catalogList = await main(["catalog", "list", "--catalog-dir", catalogDir, "--json"]);
        expect(catalogList.exitCode).toBe(0);
        const records = JSON.parse(catalogList.stdout);
        expect(records).toHaveLength(1);
        expect(records[0].format).toBe("extension");
      } else {
        // No real runtime launch was possible here: Forge must refuse rather than fake it. Exit 2
        // is "independent re-verification of the exported package failed" (an insufficient
        // verification level, per independentlyVerify), matching the honest-skip path proven at
        // the library level in fixture-extension-catalog.test.ts.
        expect(result.exitCode).toBe(2);
        expect(result.stderr).toMatch(/independent re-verification/);
        expect(existsSync(catalogDir)).toBe(false);
      }
    },
    240_000,
  );
});
