import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { diagnoseFallback, generateHtmlArtifact } from "./diagnose.js";
import { verifyHtmlArtifact } from "../../core/verification/verify-html.js";
import { buildEvidence } from "../../core/evidence/evidence.js";
import { independentlyVerify } from "../../core/evidence/independent-verifier.js";
import { admitToCatalog } from "../../core/catalog/catalog.js";
import { exportRepairPackage, readArtifactAndEvidenceFromZip } from "../../core/export/zip-exporter.js";

const SOURCE_LOG = "Error: listen EADDRINUSE: address already in use :::3000";

const tempDirs: string[] = [];
async function freshOutDir(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "forge-html-catalog-test-"));
  tempDirs.push(dir);
  return dir;
}
afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

// Same chain as fixture-free-tcp-port-catalog.test.ts, for the HTML format: diagnose -> generate
// -> real browser verification -> evidence -> export -> read back -> independent re-verify ->
// catalog admission. Proves the generalized independent verifier (L2_sandbox_executed path)
// actually works end to end, not just against hand-crafted evidence objects in a unit test.
describe("HTML artifact: evidence + export + independent second verifier + catalog gate", () => {
  it(
    "admits a genuinely passing HTML repair report to the catalog",
    async () => {
      const diagnosis = diagnoseFallback(SOURCE_LOG, "linux");
      const artifact = generateHtmlArtifact(diagnosis);
      expect(artifact.ok).toBe(true);
      if (!artifact.ok) {
        return;
      }

      const verification = await verifyHtmlArtifact({ html: artifact.content, expectedDefaultPort: 3000 });
      expect(verification.status).toBe("passed");
      expect(verification.level).toBe("L2_sandbox_executed");

      const artifactBytes = new TextEncoder().encode(artifact.content);
      const evidence = buildEvidence({
        artifactId: "forge-repair-html-free-tcp-port-001",
        artifactFileName: artifact.fileName,
        artifactFormat: "html",
        artifactContent: artifactBytes,
        sourceLogRedactedText: SOURCE_LOG,
        targetOS: "linux",
        sandboxImage: "headless-chromium",
        verification,
        forgeVersion: "0.0.1",
        templateVersion: "1.0.0",
      });

      const outDir = await freshOutDir();
      const { zipPath } = await exportRepairPackage(outDir, evidence.artifactId, {
        artifactFileName: artifact.fileName,
        artifactBytes,
        evidence,
        readmeContent: `# ${evidence.artifactId}\n\nOpen repair.html in a browser. It does not run anything on your system by itself.\n`,
      });

      const readBack = readArtifactAndEvidenceFromZip(zipPath, artifact.fileName);
      const reVerification = independentlyVerify(readBack.evidence, readBack.artifactBytes);
      expect(reVerification.verified).toBe(true);

      const evidenceBytes = new TextEncoder().encode(`${JSON.stringify(readBack.evidence, null, 2)}\n`);
      const admission = admitToCatalog(readBack.evidence, readBack.artifactBytes, evidenceBytes, "0.0.1");
      expect(admission.admitted).toBe(true);
      if (admission.admitted) {
        expect(admission.artifact.format).toBe("html");
        expect(admission.artifact.status).toBe("approved");
      }
    },
    30_000,
  );

  it(
    "refuses catalog admission when the HTML artifact fails its own static policy check",
    async () => {
      // A hand-broken "artifact" that violates the no-external-resources rule -- verifyHtmlArtifact
      // must catch this at the static-validation step and never reach the browser at all.
      const brokenHtml = `<!doctype html><html><head><script src="https://evil.example/x.js"></script></head><body></body></html>`;
      const verification = await verifyHtmlArtifact({ html: brokenHtml, expectedDefaultPort: 3000 });
      expect(verification.status).toBe("failed");
      expect(verification.level).toBe("L1_static_validated");

      const artifactBytes = new TextEncoder().encode(brokenHtml);
      const evidence = buildEvidence({
        artifactId: "forge-repair-html-broken-001",
        artifactFileName: "repair.html",
        artifactFormat: "html",
        artifactContent: artifactBytes,
        sourceLogRedactedText: SOURCE_LOG,
        targetOS: "linux",
        sandboxImage: "headless-chromium",
        verification,
        forgeVersion: "0.0.1",
        templateVersion: "1.0.0",
      });

      const admission = admitToCatalog(
        evidence,
        artifactBytes,
        new TextEncoder().encode(JSON.stringify(evidence)),
        "0.0.1",
      );
      expect(admission.admitted).toBe(false);
    },
    15_000,
  );
});
