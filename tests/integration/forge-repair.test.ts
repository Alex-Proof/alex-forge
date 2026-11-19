import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
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

// This is the literal "end-to-end test from log to ZIP" the roadmap's Phase 6 requires: it drives
// the real `forge` CLI entry point (src/cli.ts), which runs a real Docker sandbox, a real
// independent oracle, real evidence, a real ZIP on disk, and a real catalog gate -- nothing here
// is mocked.
describe("forge repair (end to end, log to ZIP)", () => {
  it(
    "diagnoses, verifies, exports, and admits a real repair case to the catalog",
    async () => {
      const workDir = await freshDir("forge-cli-e2e-");
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
        "--catalog-dir",
        catalogDir,
        "--json",
      ]);

      expect(result.exitCode).toBe(0);
      const report = JSON.parse(result.stdout);
      expect(report.status).toBe("approved");
      expect(existsSync(report.zipPath)).toBe(true);
      expect(report.catalogArtifact.status).toBe("approved");

      const catalogList = await main(["catalog", "list", "--catalog-dir", catalogDir, "--json"]);
      expect(catalogList.exitCode).toBe(0);
      const records = JSON.parse(catalogList.stdout);
      expect(records).toHaveLength(1);
      expect(records[0].artifactHash).toBe(report.catalogArtifact.artifactHash);
    },
    30_000,
  );

  it(
    "reports needs_review (exit 1) for an unrecognized log instead of guessing a fix",
    async () => {
      const workDir = await freshDir("forge-cli-e2e-");
      const logPath = path.join(workDir, "error.log");
      await writeFile(logPath, "segmentation fault in module xyz at offset 0x1234\n");

      const result = await main([
        "repair",
        "--log",
        logPath,
        "--os",
        "linux",
        "--output",
        path.join(workDir, "out"),
        "--catalog-dir",
        path.join(workDir, "catalog"),
        "--json",
      ]);

      expect(result.exitCode).toBe(1);
      const report = JSON.parse(result.stdout);
      expect(report.status).toBe("needs_review");
    },
    15_000,
  );

  it("rejects a log containing a private key before any diagnosis or sandbox work runs", async () => {
    const workDir = await freshDir("forge-cli-e2e-");
    const logPath = path.join(workDir, "error.log");
    await writeFile(
      logPath,
      "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAKCAQ==\n-----END RSA PRIVATE KEY-----\n",
    );
    const outputDir = path.join(workDir, "out");

    const result = await main([
      "repair",
      "--log",
      logPath,
      "--os",
      "linux",
      "--output",
      outputDir,
      "--catalog-dir",
      path.join(workDir, "catalog"),
    ]);

    expect(result.exitCode).toBe(2);
    expect(result.stderr).toMatch(/blocked by policy/);
    expect(existsSync(outputDir)).toBe(false);
  });

  it("rejects an unknown flag with exit code 2", async () => {
    const result = await main(["repair", "--bogus"]);
    expect(result.exitCode).toBe(2);
  });

  it("rejects a missing required flag with exit code 2", async () => {
    const result = await main(["repair", "--os", "linux"]);
    expect(result.exitCode).toBe(2);
  });

  it("rejects an unknown command with exit code 2", async () => {
    const result = await main(["not-a-real-command"]);
    expect(result.exitCode).toBe(2);
  });

  it("reports an empty catalog honestly rather than erroring", async () => {
    const workDir = await freshDir("forge-cli-e2e-");
    const result = await main(["catalog", "list", "--catalog-dir", path.join(workDir, "nonexistent")]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("catalog is empty");
  });
});
