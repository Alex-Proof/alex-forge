import { copyFile, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { createSandbox, type SandboxOptions } from "../../core/verification/sandbox.js";
import { verifyRedGreen, type RedGreenFixture } from "../../core/verification/verify-cli.js";
import { buildEvidence } from "../../core/evidence/evidence.js";
import { independentlyVerify } from "../../core/evidence/independent-verifier.js";
import { admitToCatalog } from "../../core/catalog/catalog.js";
import { exportRepairPackage, readArtifactAndEvidenceFromZip } from "../../core/export/zip-exporter.js";
import { diagnoseFallback, generateCliArtifact } from "./diagnose.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ORACLE_SOURCE = path.resolve(__dirname, "../../../tests/fixtures/tcp-port-oracle.mjs");

const sandboxOptions: SandboxOptions = {
  network: "disabled",
  readOnlyRoot: true,
  cpuLimit: "0.5",
  memoryLimitMb: 128,
  processLimit: 32,
  image: "node:22-alpine",
};

const PORT = 3000;
const SOURCE_LOG = "Error: listen EADDRINUSE: address already in use :::3000";

const tempDirs: string[] = [];
async function freshOutDir(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "forge-catalog-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

// Full pipeline, end to end on real infrastructure: diagnose -> generate -> run the real red/green
// protocol with the independent oracle -> build evidence from the real observed results ->
// export a ZIP -> read that ZIP back from disk -> have the independently implemented second
// verifier re-check it -> only then may admitToCatalog mark it "approved".
describe("evidence + export + independent second verifier + catalog gate", () => {
  it(
    "admits a genuinely passing repair artifact to the catalog",
    async () => {
      const diagnosis = diagnoseFallback(SOURCE_LOG, "linux");
      const artifact = generateCliArtifact(diagnosis);
      expect(artifact.ok).toBe(true);
      if (!artifact.ok) {
        return;
      }

      const sandbox = await createSandbox(sandboxOptions);
      try {
        await copyFile(ORACLE_SOURCE, path.join(sandbox.hostWorkDir, "oracle.mjs"));
        await writeFile(path.join(sandbox.hostWorkDir, artifact.fileName), artifact.content, { mode: 0o755 });

        const fixture: RedGreenFixture = {
          setupCommand: `nc -l -p ${PORT} &`,
          oracleCommand: `node oracle.mjs ${PORT}`,
          cliCommand: (flag) => `sh ${artifact.fileName} ${flag}`,
        };
        const verification = await verifyRedGreen(sandbox, fixture);
        expect(verification.status).toBe("passed");

        const evidence = buildEvidence({
          artifactId: "forge-repair-free-tcp-port-001",
          artifactFileName: artifact.fileName,
          artifactFormat: "cli",
          artifactContent: new TextEncoder().encode(artifact.content),
          sourceLogRedactedText: SOURCE_LOG,
          targetOS: "linux",
          sandboxImage: sandboxOptions.image,
          verification,
          forgeVersion: "0.0.1",
          templateVersion: "1.0.0",
        });

        const outDir = await freshOutDir();
        const { zipPath } = await exportRepairPackage(outDir, evidence.artifactId, {
          artifactFileName: artifact.fileName,
          artifactBytes: new TextEncoder().encode(artifact.content),
          evidence,
          readmeContent: `# ${evidence.artifactId}\n\nSee evidence.json for the full verification record.\n`,
        });

        const readBack = readArtifactAndEvidenceFromZip(zipPath, artifact.fileName);
        const reVerification = independentlyVerify(readBack.evidence, readBack.artifactBytes);
        expect(reVerification.verified).toBe(true);

        const evidenceBytes = new TextEncoder().encode(`${JSON.stringify(readBack.evidence, null, 2)}\n`);
        const admission = admitToCatalog(readBack.evidence, readBack.artifactBytes, evidenceBytes, "0.0.1");
        expect(admission.admitted).toBe(true);
        if (admission.admitted) {
          expect(admission.artifact.status).toBe("approved");
          expect(admission.artifact.artifactHash).toBe(evidence.artifact.sha256);
        }
      } finally {
        await sandbox.destroy();
      }
    },
    30_000,
  );

  it(
    "refuses to admit a repair artifact whose red/green verification actually failed",
    async () => {
      // Same lying script as the Phase 4 negative control: fakes success via a self-trusted
      // marker file. verifyRedGreen already catches this via the independent oracle; this test
      // proves the catalog gate refuses it too, end to end through evidence and export.
      const lyingScript = `#!/bin/sh
set -eu
MARKER=/workspace/.lying-fixed-marker
case "\${1:-}" in
  --check)
    if [ -f "$MARKER" ]; then exit 0; else exit 1; fi
    ;;
  --dry-run)
    exit 0
    ;;
  --fix)
    touch "$MARKER"
    exit 0
    ;;
  --verify)
    if [ -f "$MARKER" ]; then exit 0; else exit 1; fi
    ;;
  *)
    exit 2
    ;;
esac
`;

      const sandbox = await createSandbox(sandboxOptions);
      try {
        await copyFile(ORACLE_SOURCE, path.join(sandbox.hostWorkDir, "oracle.mjs"));
        await writeFile(path.join(sandbox.hostWorkDir, "lying.sh"), lyingScript, { mode: 0o755 });

        const fixture: RedGreenFixture = {
          setupCommand: `nc -l -p ${PORT} &`,
          oracleCommand: `node oracle.mjs ${PORT}`,
          cliCommand: (flag) => `sh lying.sh ${flag}`,
        };
        const verification = await verifyRedGreen(sandbox, fixture);
        expect(verification.status).toBe("failed");

        const evidence = buildEvidence({
          artifactId: "forge-repair-lying-script-001",
          artifactFileName: "lying.sh",
          artifactFormat: "cli",
          artifactContent: new TextEncoder().encode(lyingScript),
          sourceLogRedactedText: SOURCE_LOG,
          targetOS: "linux",
          sandboxImage: sandboxOptions.image,
          verification,
          forgeVersion: "0.0.1",
          templateVersion: "1.0.0",
        });

        const outDir = await freshOutDir();
        const { zipPath } = await exportRepairPackage(outDir, evidence.artifactId, {
          artifactFileName: "lying.sh",
          artifactBytes: new TextEncoder().encode(lyingScript),
          evidence,
          readmeContent: `# ${evidence.artifactId}\n`,
        });

        const readBack = readArtifactAndEvidenceFromZip(zipPath, "lying.sh");
        const evidenceBytes = new TextEncoder().encode(`${JSON.stringify(readBack.evidence, null, 2)}\n`);
        const admission = admitToCatalog(readBack.evidence, readBack.artifactBytes, evidenceBytes, "0.0.1");

        expect(admission.admitted).toBe(false);
        if (!admission.admitted) {
          expect(admission.reasons.length).toBeGreaterThan(0);
        }
      } finally {
        await sandbox.destroy();
      }
    },
    30_000,
  );
});
