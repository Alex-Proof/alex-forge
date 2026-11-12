import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { exportRepairPackage, readArtifactAndEvidenceFromZip } from "./zip-exporter.js";
import { buildEvidence } from "../evidence/evidence.js";

const artifactContent = new TextEncoder().encode("#!/bin/sh\necho hello\n");

function sampleEvidence() {
  return buildEvidence({
    artifactId: "forge-repair-test-003",
    artifactFileName: "repair.sh",
    artifactFormat: "cli",
    artifactContent,
    sourceLogRedactedText: "service exited with code 1",
    targetOS: "linux",
    sandboxImage: "alpine:3.20",
    verification: { status: "passed", level: "L3_state_transition_verified", checks: [] },
    forgeVersion: "0.0.1",
    templateVersion: "1.0.0",
  });
}

const tempDirs: string[] = [];
async function freshOutDir(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "forge-export-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("exportRepairPackage", () => {
  it("writes a ZIP containing artifact/, evidence.json, manifest.json, README.md, checksums.txt", async () => {
    const outDir = await freshOutDir();
    const evidence = sampleEvidence();
    const { zipPath, manifest } = await exportRepairPackage(outDir, "forge-repair-example", {
      artifactFileName: "repair.sh",
      artifactBytes: artifactContent,
      evidence,
      readmeContent: "# Repair artifact\n",
    });

    expect(existsSync(zipPath)).toBe(true);
    expect(manifest.files.map((f) => f.path)).toContain("artifact/repair.sh");

    const { artifactBytes, evidence: readBackEvidence } = readArtifactAndEvidenceFromZip(zipPath, "repair.sh");
    expect(Buffer.from(artifactBytes).equals(Buffer.from(artifactContent))).toBe(true);
    expect((readBackEvidence as { artifactId: string }).artifactId).toBe(evidence.artifactId);
  });

  it("never leaves a partially named package behind on success (no stray .tmp- files)", async () => {
    const outDir = await freshOutDir();
    await exportRepairPackage(outDir, "forge-repair-example", {
      artifactFileName: "repair.sh",
      artifactBytes: artifactContent,
      evidence: sampleEvidence(),
      readmeContent: "# Repair artifact\n",
    });
    const fs = await import("node:fs/promises");
    const entries = await fs.readdir(outDir);
    expect(entries.every((name) => !name.startsWith(".tmp-"))).toBe(true);
    expect(entries).toContain("forge-repair-example.zip");
  });

  it("rejects an artifact file name that attempts path traversal", async () => {
    const outDir = await freshOutDir();
    await expect(
      exportRepairPackage(outDir, "forge-repair-example", {
        artifactFileName: "../../evil.sh",
        artifactBytes: artifactContent,
        evidence: sampleEvidence(),
        readmeContent: "# Repair artifact\n",
      }),
    ).rejects.toThrow();
  });

  it("rejects an artifact file name with an absolute path", async () => {
    const outDir = await freshOutDir();
    await expect(
      exportRepairPackage(outDir, "forge-repair-example", {
        artifactFileName: "/etc/passwd",
        artifactBytes: artifactContent,
        evidence: sampleEvidence(),
        readmeContent: "# Repair artifact\n",
      }),
    ).rejects.toThrow();
  });

  it("produces byte-identical checksums.txt entries for re-hashed content", async () => {
    const outDir = await freshOutDir();
    const { zipPath } = await exportRepairPackage(outDir, "forge-repair-example", {
      artifactFileName: "repair.sh",
      artifactBytes: artifactContent,
      evidence: sampleEvidence(),
      readmeContent: "# Repair artifact\n",
    });
    const AdmZip = (await import("adm-zip")).default;
    const zip = new AdmZip(zipPath);
    const checksumsText = zip.getEntry("checksums.txt")?.getData().toString("utf-8") ?? "";
    expect(checksumsText).toMatch(/^[0-9a-f]{64}  artifact\/repair\.sh$/m);
  });
});
