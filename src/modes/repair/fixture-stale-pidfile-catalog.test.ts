import { copyFile, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createSandbox, type SandboxOptions } from "../../core/verification/sandbox.js";
import { verifyRedGreen, type RedGreenFixture } from "../../core/verification/verify-cli.js";
import { buildEvidence } from "../../core/evidence/evidence.js";
import { independentlyVerify } from "../../core/evidence/independent-verifier.js";
import { admitToCatalog } from "../../core/catalog/catalog.js";
import { exportRepairPackage, readArtifactAndEvidenceFromZip } from "../../core/export/zip-exporter.js";
import { diagnoseFallback, generateCliArtifact } from "./diagnose.js";
import { getRegisteredAction } from "./actions.js";

const sandboxOptions: SandboxOptions = {
  network: "disabled",
  readOnlyRoot: true,
  cpuLimit: "0.5",
  memoryLimitMb: 128,
  processLimit: 32,
  image: "python:3-alpine",
};

const PID_FILE = "/tmp/postmaster.pid";
const SOURCE_LOG = `FATAL:  lock file "${PID_FILE}" already exists`;

const tempDirs: string[] = [];
async function freshOutDir(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "forge-pidfile-catalog-test-"));
  tempDirs.push(dir);
  return dir;
}
afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

// The same "diagnose -> generate -> real sandboxed red/green with an independent oracle ->
// evidence -> export -> independently re-verify -> catalog admit" chain already proven for
// free-tcp-port, now for the second registered action. Nothing here is mocked: a real subshell
// is spawned and reaped in a real Docker container to produce a genuinely stale PID, and a real
// Python process (the independent oracle, sharing no code with either the generated sh script or
// this test) checks its liveness via the real os.kill(pid, 0) syscall idiom.
describe("clear-stale-pidfile: evidence + export + independent second verifier + catalog gate", () => {
  it(
    "admits a genuinely passing stale-pidfile repair to the catalog",
    async () => {
      const diagnosis = diagnoseFallback(SOURCE_LOG, "linux");
      const artifact = generateCliArtifact(diagnosis);
      expect(artifact.ok).toBe(true);
      if (!artifact.ok) {
        return;
      }
      expect(diagnosis.fixPlan).toEqual([{ actionId: "clear-stale-pidfile", parameters: { pidFilePath: PID_FILE } }]);

      const action = getRegisteredAction("clear-stale-pidfile");
      expect(action).toBeDefined();
      const fixture = action!.buildFixture(diagnosis.fixPlan[0]!.parameters);

      const sandbox = await createSandbox({ ...sandboxOptions, image: fixture.sandboxImage });
      try {
        await copyFile(fixture.oracleAssetSourcePath, path.join(sandbox.hostWorkDir, fixture.oracleAssetStagedName));
        await writeFile(path.join(sandbox.hostWorkDir, artifact.fileName), artifact.content, { mode: 0o755 });

        const redGreenFixture: RedGreenFixture = {
          setupCommand: fixture.setupCommand,
          oracleCommand: fixture.oracleCommand,
          cliCommand: (flag) => `sh ${artifact.fileName} ${flag}`,
        };
        const verification = await verifyRedGreen(sandbox, redGreenFixture);
        expect(verification.status).toBe("passed");
        expect(verification.level).toBe("L3_state_transition_verified");

        const evidence = buildEvidence({
          artifactId: "forge-repair-clear-stale-pidfile-001",
          artifactFileName: artifact.fileName,
          artifactFormat: "cli",
          artifactContent: new TextEncoder().encode(artifact.content),
          sourceLogRedactedText: SOURCE_LOG,
          targetOS: "linux",
          sandboxImage: fixture.sandboxImage,
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
        }
      } finally {
        await sandbox.destroy();
      }
    },
    30_000,
  );

  it(
    "never removes a pidfile whose PID is genuinely alive (a possible real second instance), and this resolves to not_verified rather than a guessed pass",
    async () => {
      // No setup command holding/creating a stale file: the fault (a *stale* pidfile) never
      // actually exists, so the independent oracle's precondition check must correctly refuse to
      // confirm it -- proving this action can never be tricked into treating "a live PID exists"
      // as the fault it's allowed to clean up.
      const diagnosis = diagnoseFallback(SOURCE_LOG, "linux");
      const artifact = generateCliArtifact(diagnosis);
      expect(artifact.ok).toBe(true);
      if (!artifact.ok) {
        return;
      }
      const action = getRegisteredAction("clear-stale-pidfile")!;
      const fixture = action.buildFixture(diagnosis.fixPlan[0]!.parameters);

      const sandbox = await createSandbox({ ...sandboxOptions, image: fixture.sandboxImage });
      try {
        await copyFile(fixture.oracleAssetSourcePath, path.join(sandbox.hostWorkDir, fixture.oracleAssetStagedName));
        await writeFile(path.join(sandbox.hostWorkDir, artifact.fileName), artifact.content, { mode: 0o755 });

        const redGreenFixture: RedGreenFixture = {
          // Write OUR OWN (live) shell PID into the file instead of a dead one.
          setupCommand: `echo $$ > ${PID_FILE}`,
          oracleCommand: fixture.oracleCommand,
          cliCommand: (flag) => `sh ${artifact.fileName} ${flag}`,
        };
        const verification = await verifyRedGreen(sandbox, redGreenFixture);
        expect(verification.status).toBe("not_verified");
      } finally {
        await sandbox.destroy();
      }
    },
    30_000,
  );
});
