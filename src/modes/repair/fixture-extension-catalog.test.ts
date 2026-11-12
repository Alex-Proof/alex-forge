import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { diagnoseFallback, generateExtensionArtifact } from "./diagnose.js";
import { verifyExtensionArtifact } from "../../core/verification/verify-extension.js";
import { buildEvidence } from "../../core/evidence/evidence.js";
import { independentlyVerify } from "../../core/evidence/independent-verifier.js";
import { admitToCatalog } from "../../core/catalog/catalog.js";
import { exportRepairPackage, readArtifactAndEvidenceFromZip } from "../../core/export/zip-exporter.js";

const SOURCE_LOG = "Error: listen EADDRINUSE: address already in use :::3000";

const tempDirs: string[] = [];
async function freshOutDir(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "forge-extension-catalog-test-"));
  tempDirs.push(dir);
  return dir;
}
afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

// Same chain as fixture-html-catalog.test.ts, for the VS Code extension format: diagnose ->
// generate the extension project -> real @vscode/vsce packaging + (where this environment allows
// it) a real VS Code Extension Host runtime check -> evidence -> export -> read back ->
// independent re-verify -> catalog admission. Proves that the extension format reaches the same
// catalog gate through the same format-agnostic independent verifier as CLI/HTML, not through a
// shortcut.
describe("Extension artifact: evidence + export + independent second verifier + catalog gate", () => {
  it(
    "packages a genuinely passing extension companion and gets as far as this environment allows",
    async () => {
      const diagnosis = diagnoseFallback(SOURCE_LOG, "linux");
      const artifact = generateExtensionArtifact(diagnosis);
      expect(artifact.ok).toBe(true);
      if (!artifact.ok) {
        return;
      }

      const { verification, vsixBytes } = await verifyExtensionArtifact(artifact.files);

      // Packaging must always succeed for this real, policy-passing project -- regardless of
      // whether a full runtime launch is possible in this environment.
      const packageCheck = verification.checks.find((c) => c.name === "build_and_package");
      expect(packageCheck?.status).toBe("passed");
      expect(vsixBytes).not.toBeNull();
      expect(vsixBytes!.byteLength).toBeGreaterThan(0);

      const runtimeCheck = verification.checks.find((c) => c.name === "runtime_started_in_test_instance");
      expect(runtimeCheck).toBeDefined();
      expect(["passed", "skipped"]).toContain(runtimeCheck!.status);
      // Whatever this environment allowed, the overall status is "passed" (every check that
      // ran, passed) and the level honestly reflects whether a real runtime launch happened.
      expect(verification.status).toBe("passed");
      expect(["L1_static_validated", "L2_sandbox_executed"]).toContain(verification.level);

      const evidence = buildEvidence({
        artifactId: "forge-repair-extension-free-tcp-port-001",
        artifactFileName: "forge-repair.vsix",
        artifactFormat: "extension",
        artifactContent: vsixBytes!,
        sourceLogRedactedText: SOURCE_LOG,
        targetOS: "linux",
        sandboxImage: "vscode-extension-host",
        verification,
        forgeVersion: "0.0.1",
        templateVersion: "1.0.0",
      });

      const outDir = await freshOutDir();
      const { zipPath } = await exportRepairPackage(outDir, evidence.artifactId, {
        artifactFileName: "forge-repair.vsix",
        artifactBytes: vsixBytes!,
        evidence,
        readmeContent: `# ${evidence.artifactId}\n\nInstall forge-repair.vsix yourself (Forge never installs it for you) to view the already-verified repair script and prepare terminal commands under your own explicit confirmation.\n`,
      });

      const readBack = readArtifactAndEvidenceFromZip(zipPath, "forge-repair.vsix");
      const reVerification = independentlyVerify(readBack.evidence, readBack.artifactBytes);

      const admission = admitToCatalog(
        readBack.evidence,
        readBack.artifactBytes,
        new TextEncoder().encode(`${JSON.stringify(readBack.evidence, null, 2)}\n`),
        "0.0.1",
      );

      if (verification.level === "L2_sandbox_executed") {
        // A real runtime launch happened and passed in this environment: full catalog admission,
        // exactly like the HTML format's end-to-end test.
        expect(reVerification.verified).toBe(true);
        expect(admission.admitted).toBe(true);
        if (admission.admitted) {
          expect(admission.artifact.format).toBe("extension");
          expect(admission.artifact.status).toBe("approved");
        }
      } else {
        // No real runtime launch was possible here (no Xvfb / no network path to VS Code's
        // download host): the independent verifier must still honestly refuse catalog admission
        // rather than accept a static-only L1 result as if it were a runtime-verified one.
        expect(reVerification.verified).toBe(false);
        expect(admission.admitted).toBe(false);
      }
    },
    240_000,
  );

  it(
    "refuses catalog admission when the extension's manifest violates the dependency policy",
    async () => {
      const brokenFiles = {
        "package.json": JSON.stringify({
          name: "broken",
          publisher: "forge-local",
          version: "0.0.1",
          main: "./extension.js",
          engines: { vscode: "^1.90.0" },
          activationEvents: ["onCommand:x.run"],
          contributes: { commands: [{ command: "x.run", title: "Run" }] },
          dependencies: { "left-pad": "^1.0.0" },
        }),
        "extension.js": "module.exports = { activate() {} };",
      };

      const { verification, vsixBytes } = await verifyExtensionArtifact(brokenFiles);
      expect(verification.status).toBe("failed");
      expect(verification.level).toBe("L1_static_validated");
      expect(vsixBytes).toBeNull();

      const evidence = buildEvidence({
        artifactId: "forge-repair-extension-broken-001",
        artifactFileName: "forge-repair.vsix",
        artifactFormat: "extension",
        artifactContent: new TextEncoder().encode("not-a-real-vsix"),
        sourceLogRedactedText: SOURCE_LOG,
        targetOS: "linux",
        sandboxImage: "vscode-extension-host",
        verification,
        forgeVersion: "0.0.1",
        templateVersion: "1.0.0",
      });

      const admission = admitToCatalog(
        evidence,
        new TextEncoder().encode("not-a-real-vsix"),
        new TextEncoder().encode(JSON.stringify(evidence)),
        "0.0.1",
      );
      expect(admission.admitted).toBe(false);
    },
    30_000,
  );
});
