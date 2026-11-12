import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { policyEngine } from "../policy/policy.js";
import { errorMessage, type ProcessRequest, type ProcessResult, type RunOutcome } from "./process-runner.js";

const execFileAsync = promisify(execFile);

/** Fixed workspace path inside every sandbox container. `ProcessRequest.cwd` must stay inside it. */
export const CONTAINER_WORKDIR = "/workspace";

export interface SandboxOptions {
  /**
   * MVP supports exactly one value by construction: there is no `--allow-network` escape hatch.
   * Network access stays disabled for every sandboxed run.
   */
  network: "disabled";
  readOnlyRoot: boolean;
  /** Docker `--cpus` value, e.g. "0.5". */
  cpuLimit: string;
  memoryLimitMb: number;
  processLimit: number;
  /** Container image providing the interpreter(s) the request needs. */
  image: string;
  /** Hard ceiling on how long any single sandbox lifetime (create -> destroy) may run. */
  dockerCommandTimeoutMs?: number;
}

export interface Sandbox {
  /** Host-side directory bind-mounted at {@link CONTAINER_WORKDIR}; callers stage input files here. */
  readonly hostWorkDir: string;
  run(request: ProcessRequest): Promise<RunOutcome>;
  destroy(): Promise<void>;
}

async function assertDockerAvailable(timeoutMs: number): Promise<void> {
  try {
    await execFileAsync("docker", ["version", "--format", "{{.Server.Version}}"], { timeout: timeoutMs });
  } catch (error) {
    throw new Error(`Docker is not available or its daemon is unreachable: ${errorMessage(error)}`);
  }
}

function assertCwdWithinSandbox(cwd: string): { ok: true } | { ok: false; reason: string } {
  if (cwd.includes("\0")) {
    return { ok: false, reason: "cwd contains a null byte" };
  }
  if (cwd.split("/").some((segment) => segment === "..")) {
    return { ok: false, reason: "cwd contains a '..' traversal segment" };
  }
  if (cwd !== CONTAINER_WORKDIR && !cwd.startsWith(`${CONTAINER_WORKDIR}/`)) {
    return { ok: false, reason: `cwd must be ${CONTAINER_WORKDIR} or a path inside it, got: ${cwd}` };
  }
  return { ok: true };
}

async function killContainer(name: string): Promise<void> {
  try {
    await execFileAsync("docker", ["kill", name], { timeout: 10_000 });
  } catch {
    // Best-effort: the container may already have exited.
  }
}

async function removeContainer(name: string): Promise<void> {
  try {
    await execFileAsync("docker", ["rm", "-f", name], { timeout: 10_000 });
  } catch {
    // Best-effort: --rm already removed it in the normal path.
  }
}

class DockerSandbox implements Sandbox {
  private readonly trackedContainers = new Set<string>();

  constructor(
    private readonly options: SandboxOptions,
    public readonly hostWorkDir: string,
  ) {}

  async run(request: ProcessRequest): Promise<RunOutcome> {
    const cwdCheck = assertCwdWithinSandbox(request.cwd);
    if (!cwdCheck.ok) {
      return { kind: "policy_blocked", reason: cwdCheck.reason };
    }

    const commandDecision = policyEngine.inspectCommand(request.executable, request.args);
    if (!commandDecision.allowed) {
      return { kind: "policy_blocked", reason: commandDecision.reason };
    }

    const containerName = `forge-sandbox-${randomUUID()}`;
    this.trackedContainers.add(containerName);

    const dockerArgs = [
      "run",
      "--rm",
      "--name",
      containerName,
      "--network",
      "none",
      ...(this.options.readOnlyRoot ? ["--read-only"] : []),
      "--tmpfs",
      "/tmp:rw,size=16m",
      "--memory",
      `${this.options.memoryLimitMb}m`,
      "--cpus",
      this.options.cpuLimit,
      "--pids-limit",
      String(this.options.processLimit),
      "--security-opt",
      "no-new-privileges",
      "-v",
      `${this.hostWorkDir}:${CONTAINER_WORKDIR}`,
      "-w",
      request.cwd,
      ...Object.entries(request.env).flatMap(([key, value]) => ["-e", `${key}=${value}`]),
      this.options.image,
      request.executable,
      ...request.args,
    ];

    const result = await this.spawnAndCollect(containerName, dockerArgs, request);
    this.trackedContainers.delete(containerName);
    return result;
  }

  private spawnAndCollect(
    containerName: string,
    dockerArgs: string[],
    request: ProcessRequest,
  ): Promise<RunOutcome> {
    return new Promise((resolve) => {
      const startedAt = Date.now();
      // No shell: argv stays a plain array all the way down to execve.
      const child = spawn("docker", dockerArgs, { stdio: ["ignore", "pipe", "pipe"] });

      let stdout = Buffer.alloc(0);
      let stderr = Buffer.alloc(0);
      let truncated = false;
      let timedOut = false;
      let stoppedEarly = false;
      let settled = false;

      const stopEarly = (reason: "timeout" | "output_limit") => {
        if (stoppedEarly) {
          return;
        }
        stoppedEarly = true;
        if (reason === "timeout") {
          timedOut = true;
        }
        void killContainer(containerName);
        child.kill("SIGKILL");
      };

      const timer = setTimeout(() => stopEarly("timeout"), request.timeoutMs);

      const appendLimited = (current: Buffer, chunk: Buffer): Buffer => {
        if (current.length >= request.maxOutputBytes) {
          truncated = true;
          stopEarly("output_limit");
          return current;
        }
        const remaining = request.maxOutputBytes - current.length;
        if (chunk.length > remaining) {
          truncated = true;
          const next = Buffer.concat([current, chunk.subarray(0, remaining)]);
          stopEarly("output_limit");
          return next;
        }
        return Buffer.concat([current, chunk]);
      };

      child.stdout?.on("data", (chunk: Buffer) => {
        stdout = appendLimited(stdout, chunk);
      });
      child.stderr?.on("data", (chunk: Buffer) => {
        stderr = appendLimited(stderr, chunk);
      });

      child.on("error", (error) => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);
        resolve({ kind: "runner_error", message: `failed to spawn docker: ${errorMessage(error)}` });
      });

      child.on("close", (code, signal) => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);
        const processResult: ProcessResult = {
          exitCode: timedOut ? null : code,
          signal: signal ?? null,
          timedOut,
          stdout: stdout.toString("utf-8"),
          stderr: stderr.toString("utf-8"),
          durationMs: Date.now() - startedAt,
          truncated,
        };
        resolve({ kind: "completed", result: processResult });
      });
    });
  }

  async destroy(): Promise<void> {
    await Promise.allSettled([...this.trackedContainers].map((name) => removeContainer(name)));
    this.trackedContainers.clear();
    await rm(this.hostWorkDir, { recursive: true, force: true });
  }
}

export async function createSandbox(options: SandboxOptions): Promise<Sandbox> {
  await assertDockerAvailable(options.dockerCommandTimeoutMs ?? 10_000);
  const hostWorkDir = await mkdtemp(path.join(tmpdir(), "forge-sandbox-"));
  return new DockerSandbox(options, hostWorkDir);
}

/**
 * Convenience wrapper matching the blueprint's `runIsolated` pseudocode: create a fresh sandbox,
 * run exactly one request, always destroy the sandbox afterward. Any failure anywhere in this
 * path -- including a sandbox that never starts -- resolves to `runner_error`, never to a result
 * that could be mistaken for a passing check.
 */
export async function runIsolated(sandboxOptions: SandboxOptions, request: ProcessRequest): Promise<RunOutcome> {
  let sandbox: Sandbox;
  try {
    sandbox = await createSandbox(sandboxOptions);
  } catch (error) {
    return { kind: "runner_error", message: errorMessage(error) };
  }

  try {
    return await sandbox.run(request);
  } catch (error) {
    return { kind: "runner_error", message: errorMessage(error) };
  } finally {
    await sandbox.destroy().catch(() => {
      // Cleanup failures must not mask the run's own outcome.
    });
  }
}
