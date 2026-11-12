import { copyFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { createSandbox, type SandboxOptions } from "../../core/verification/sandbox.js";
import { verifyRedGreen, type RedGreenFixture } from "../../core/verification/verify-cli.js";
import { diagnoseFallback, generateCliArtifact } from "./diagnose.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ORACLE_SOURCE = path.resolve(__dirname, "../../../tests/fixtures/tcp-port-oracle.mjs");

// node:22-alpine, not plain alpine: the independent oracle is written in Node on purpose (a
// different language from the generated sh script), so the sandbox image needs both a Node
// runtime and the busybox net tools the repair script relies on.
const sandboxOptions: SandboxOptions = {
  network: "disabled",
  readOnlyRoot: true,
  cpuLimit: "0.5",
  memoryLimitMb: 128,
  processLimit: 32,
  image: "node:22-alpine",
};

const PORT = 3000;

async function stageOracle(hostWorkDir: string): Promise<void> {
  await copyFile(ORACLE_SOURCE, path.join(hostWorkDir, "oracle.mjs"));
}

function fixtureFor(cliScriptFileName: string): RedGreenFixture {
  return {
    setupCommand: `nc -l -p ${PORT} &`,
    oracleCommand: `node oracle.mjs ${PORT}`,
    cliCommand: (flag) => `sh ${cliScriptFileName} ${flag}`,
  };
}

describe("free-tcp-port red/green verification with an independent oracle", () => {
  it(
    "passes L3_state_transition_verified for the real, honest repair script",
    async () => {
      const diagnosis = diagnoseFallback("Error: listen EADDRINUSE: address already in use :::3000", "linux");
      const artifact = generateCliArtifact(diagnosis);
      expect(artifact.ok).toBe(true);
      if (!artifact.ok) {
        return;
      }

      const sandbox = await createSandbox(sandboxOptions);
      try {
        await stageOracle(sandbox.hostWorkDir);
        await writeFile(path.join(sandbox.hostWorkDir, artifact.fileName), artifact.content, { mode: 0o755 });

        const summary = await verifyRedGreen(sandbox, fixtureFor(artifact.fileName));

        expect(summary.status).toBe("passed");
        expect(summary.level).toBe("L3_state_transition_verified");
        expect(summary.checks.every((c) => c.status === "passed")).toBe(true);
      } finally {
        await sandbox.destroy();
      }
    },
    30_000,
  );

  it(
    "reports not_verified instead of guessing when the fault state cannot be reproduced",
    async () => {
      const diagnosis = diagnoseFallback("Error: listen EADDRINUSE: address already in use :::3000", "linux");
      const artifact = generateCliArtifact(diagnosis);
      expect(artifact.ok).toBe(true);
      if (!artifact.ok) {
        return;
      }

      const sandbox = await createSandbox(sandboxOptions);
      try {
        await stageOracle(sandbox.hostWorkDir);
        await writeFile(path.join(sandbox.hostWorkDir, artifact.fileName), artifact.content, { mode: 0o755 });

        // No setup command: the port is never actually held, so the fault never exists.
        const fixture: RedGreenFixture = {
          setupCommand: "true",
          oracleCommand: `node oracle.mjs ${PORT}`,
          cliCommand: (flag) => `sh ${artifact.fileName} ${flag}`,
        };

        const summary = await verifyRedGreen(sandbox, fixture);

        expect(summary.status).toBe("not_verified");
      } finally {
        await sandbox.destroy();
      }
    },
    30_000,
  );

  it(
    "negative control: catches a script that lies about having fixed the fault",
    async () => {
      // This script never kills the real holder process. It fakes success by writing a marker
      // file and trusting that same marker for its own --check/--verify -- exactly the
      // "claim-without-verify" pattern this project exists to rule out. Only the independent
      // oracle, which never looks at the marker, can catch it.
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
        await stageOracle(sandbox.hostWorkDir);
        await writeFile(path.join(sandbox.hostWorkDir, "lying.sh"), lyingScript, { mode: 0o755 });

        const summary = await verifyRedGreen(sandbox, fixtureFor("lying.sh"));

        expect(summary.status).not.toBe("passed");
        const postconditionOracle = summary.checks.find((c) => c.name === "postcondition_oracle");
        expect(postconditionOracle?.status).toBe("failed");

        // The lying script's own self-check (reading its own marker) would have said "passed"
        // here -- demonstrating exactly why that alone is not acceptable as proof.
        const checkAfterFix = summary.checks.find((c) => c.name === "check_after_fix");
        expect(checkAfterFix?.status).toBe("passed");
      } finally {
        await sandbox.destroy();
      }
    },
    30_000,
  );
});
