import { writeFile } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { createSandbox, type SandboxOptions } from "../../core/verification/sandbox.js";
import type { ProcessRequest } from "../../core/verification/process-runner.js";
import { diagnoseFallback, generateCliArtifact } from "./diagnose.js";

const sandboxOptions: SandboxOptions = {
  network: "disabled",
  readOnlyRoot: true,
  cpuLimit: "0.5",
  memoryLimitMb: 128,
  processLimit: 32,
  image: "alpine:3.20",
};

async function stageGeneratedScript(hostWorkDir: string, fileName: string, content: string): Promise<void> {
  await writeFile(path.join(hostWorkDir, fileName), content, { mode: 0o755 });
}

// This is the "one fixture, end to end" that the roadmap's Phase 3 requires: a real log line is
// fed through the deterministic fallback, turned into a generated script, and that script is run
// for real against a real held TCP port inside the Docker sandbox from Phase 2. Nothing here is
// mocked or simulated. A dedicated independent oracle (separate code path confirming the state
// transition) is still Phase 4's job -- this fixture only proves the CLI flag contract itself.
describe("free-tcp-port fixture (real sandbox, real TCP port)", () => {
  it(
    "detects, dry-runs without mutating, fixes, and verifies a real held port",
    async () => {
      const diagnosis = diagnoseFallback("Error: listen EADDRINUSE: address already in use :::3000", "linux");
      const artifact = generateCliArtifact(diagnosis);
      expect(artifact.ok).toBe(true);
      if (!artifact.ok) {
        return;
      }

      const sandbox = await createSandbox(sandboxOptions);
      try {
        await stageGeneratedScript(sandbox.hostWorkDir, artifact.fileName, artifact.content);

        const harness = [
          "nc -l -p 3000 &",
          "sleep 0.3",
          `sh ${artifact.fileName} --check; echo "CHECK1=$?"`,
          `sh ${artifact.fileName} --dry-run; echo "DRYRUN=$?"`,
          `sh ${artifact.fileName} --check; echo "CHECK2=$?"`,
          `sh ${artifact.fileName} --fix; echo "FIX=$?"`,
          `sh ${artifact.fileName} --verify; echo "VERIFY=$?"`,
        ].join("\n");

        const request: ProcessRequest = {
          executable: "sh",
          args: ["-c", harness],
          cwd: "/workspace",
          env: {},
          timeoutMs: 15_000,
          maxOutputBytes: 100_000,
        };

        const outcome = await sandbox.run(request);
        expect(outcome.kind).toBe("completed");
        if (outcome.kind !== "completed") {
          return;
        }

        const output = outcome.result.stdout;
        expect(output).toMatch(/CHECK1=1/);
        expect(output).toMatch(/DRYRUN=0/);
        // Re-checking right after --dry-run and before --fix proves dry-run did not mutate state.
        expect(output).toMatch(/CHECK2=1/);
        expect(output).toMatch(/FIX=0/);
        expect(output).toMatch(/VERIFY=0/);
      } finally {
        await sandbox.destroy();
      }
    },
    20_000,
  );

  it(
    "rejects --check combined with --fix as an invalid flag combination (exit 2)",
    async () => {
      const diagnosis = diagnoseFallback("port 3000 already in use", "linux");
      const artifact = generateCliArtifact(diagnosis);
      expect(artifact.ok).toBe(true);
      if (!artifact.ok) {
        return;
      }

      const sandbox = await createSandbox(sandboxOptions);
      try {
        await stageGeneratedScript(sandbox.hostWorkDir, artifact.fileName, artifact.content);
        const request: ProcessRequest = {
          executable: "sh",
          args: [artifact.fileName, "--check", "--fix"],
          cwd: "/workspace",
          env: {},
          timeoutMs: 10_000,
          maxOutputBytes: 10_000,
        };
        const outcome = await sandbox.run(request);
        expect(outcome.kind).toBe("completed");
        if (outcome.kind === "completed") {
          expect(outcome.result.exitCode).toBe(2);
        }
      } finally {
        await sandbox.destroy();
      }
    },
    20_000,
  );

  it(
    "rejects an unknown flag (exit 2)",
    async () => {
      const diagnosis = diagnoseFallback("port 3000 already in use", "linux");
      const artifact = generateCliArtifact(diagnosis);
      expect(artifact.ok).toBe(true);
      if (!artifact.ok) {
        return;
      }

      const sandbox = await createSandbox(sandboxOptions);
      try {
        await stageGeneratedScript(sandbox.hostWorkDir, artifact.fileName, artifact.content);
        const request: ProcessRequest = {
          executable: "sh",
          args: [artifact.fileName, "--bogus"],
          cwd: "/workspace",
          env: {},
          timeoutMs: 10_000,
          maxOutputBytes: 10_000,
        };
        const outcome = await sandbox.run(request);
        expect(outcome.kind).toBe("completed");
        if (outcome.kind === "completed") {
          expect(outcome.result.exitCode).toBe(2);
        }
      } finally {
        await sandbox.destroy();
      }
    },
    20_000,
  );

  it(
    "reports ok/free via valid --json output when the port is already free",
    async () => {
      const diagnosis = diagnoseFallback("port 4555 already in use", "linux");
      const artifact = generateCliArtifact(diagnosis);
      expect(artifact.ok).toBe(true);
      if (!artifact.ok) {
        return;
      }

      const sandbox = await createSandbox(sandboxOptions);
      try {
        await stageGeneratedScript(sandbox.hostWorkDir, artifact.fileName, artifact.content);
        const request: ProcessRequest = {
          executable: "sh",
          args: [artifact.fileName, "--check", "--json"],
          cwd: "/workspace",
          env: {},
          timeoutMs: 10_000,
          maxOutputBytes: 10_000,
        };
        const outcome = await sandbox.run(request);
        expect(outcome.kind).toBe("completed");
        if (outcome.kind === "completed") {
          expect(outcome.result.exitCode).toBe(0);
          const parsed = JSON.parse(outcome.result.stdout.trim());
          expect(parsed.status).toBe("ok");
        }
      } finally {
        await sandbox.destroy();
      }
    },
    20_000,
  );
});
