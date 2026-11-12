import { existsSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { createSandbox, runIsolated, type SandboxOptions } from "./sandbox.js";
import type { ProcessRequest } from "./process-runner.js";

const sandboxOptions: SandboxOptions = {
  network: "disabled",
  readOnlyRoot: true,
  cpuLimit: "0.5",
  memoryLimitMb: 128,
  processLimit: 32,
  image: "alpine:3.20",
};

function request(overrides: Partial<ProcessRequest>): ProcessRequest {
  return {
    executable: "true",
    args: [],
    cwd: "/workspace",
    env: {},
    timeoutMs: 10_000,
    maxOutputBytes: 1_000_000,
    ...overrides,
  };
}

// These are real integration tests against a real Docker daemon -- per the blueprint, a mock
// sandbox is not a sandbox. They are slower than unit tests and need Docker's image pull/startup
// overhead accounted for in their timeouts.

describe("DockerSandbox", () => {
  it(
    "runs a harmless command in isolation and captures its stdout",
    async () => {
      const outcome = await runIsolated(sandboxOptions, request({ executable: "echo", args: ["hello"] }));
      expect(outcome.kind).toBe("completed");
      if (outcome.kind === "completed") {
        expect(outcome.result.exitCode).toBe(0);
        expect(outcome.result.stdout.trim()).toBe("hello");
        expect(outcome.result.timedOut).toBe(false);
      }
    },
    20_000,
  );

  it(
    "disables network access by default",
    async () => {
      const outcome = await runIsolated(
        sandboxOptions,
        request({ executable: "ping", args: ["-c", "1", "-W", "1", "8.8.8.8"] }),
      );
      expect(outcome.kind).toBe("completed");
      if (outcome.kind === "completed") {
        expect(outcome.result.exitCode).not.toBe(0);
      }
    },
    20_000,
  );

  it(
    "enforces the timeout and reports timedOut instead of a misleading exit code",
    async () => {
      const outcome = await runIsolated(
        sandboxOptions,
        request({ executable: "sleep", args: ["30"], timeoutMs: 1_000 }),
      );
      expect(outcome.kind).toBe("completed");
      if (outcome.kind === "completed") {
        expect(outcome.result.timedOut).toBe(true);
        expect(outcome.result.exitCode).toBeNull();
      }
    },
    20_000,
  );

  it(
    "truncates output once it exceeds the configured byte limit",
    async () => {
      const outcome = await runIsolated(
        sandboxOptions,
        request({
          executable: "sh",
          args: ["-c", "yes A | head -c 200000"],
          maxOutputBytes: 100,
        }),
      );
      expect(outcome.kind).toBe("completed");
      if (outcome.kind === "completed") {
        expect(outcome.result.truncated).toBe(true);
        expect(outcome.result.stdout.length).toBeLessThanOrEqual(100);
      }
    },
    20_000,
  );

  it(
    "surfaces a missing interpreter as a real exit code, not a crash",
    async () => {
      const outcome = await runIsolated(
        sandboxOptions,
        request({ executable: "this-binary-does-not-exist", args: [] }),
      );
      expect(outcome.kind).toBe("completed");
      if (outcome.kind === "completed") {
        expect(outcome.result.exitCode).not.toBe(0);
      }
    },
    20_000,
  );

  it(
    "blocks a destructive command via policy before ever spawning Docker",
    async () => {
      const outcome = await runIsolated(sandboxOptions, request({ executable: "rm", args: ["-rf", "/"] }));
      expect(outcome.kind).toBe("policy_blocked");
    },
    20_000,
  );

  it(
    "blocks a cwd outside the sandbox workspace",
    async () => {
      const outcome = await runIsolated(sandboxOptions, request({ cwd: "/etc" }));
      expect(outcome.kind).toBe("policy_blocked");
    },
    20_000,
  );

  it(
    "removes the host-side workspace directory on destroy",
    async () => {
      const sandbox = await createSandbox(sandboxOptions);
      expect(existsSync(sandbox.hostWorkDir)).toBe(true);
      await sandbox.destroy();
      expect(existsSync(sandbox.hostWorkDir)).toBe(false);
    },
    20_000,
  );

  it(
    "never resolves to a passing-looking result when the sandbox itself cannot start",
    async () => {
      const originalDockerHost = process.env.DOCKER_HOST;
      process.env.DOCKER_HOST = "unix:///tmp/forge-test-nonexistent-daemon.sock";
      try {
        const outcome = await runIsolated(sandboxOptions, request({}));
        expect(outcome.kind).toBe("runner_error");
      } finally {
        if (originalDockerHost === undefined) {
          delete process.env.DOCKER_HOST;
        } else {
          process.env.DOCKER_HOST = originalDockerHost;
        }
      }
    },
    20_000,
  );
});
