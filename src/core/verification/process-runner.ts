/**
 * Process execution contracts shared by every sandbox backend. A runner-level failure (sandbox
 * could not start, Docker unreachable, container crashed before producing a result) is a
 * different thing from the *script's own* exit code, and the two must never be conflated: a
 * sandbox outage must never be reported as a passing (or even a definitively failing) check.
 */

export interface ProcessRequest {
  executable: string;
  args: string[];
  /** Working directory *inside the sandbox*. Must stay within the sandbox's workspace root. */
  cwd: string;
  /** Explicit allowlist of environment variables to set. The host environment is never inherited. */
  env: Record<string, string>;
  timeoutMs: number;
  maxOutputBytes: number;
}

export interface ProcessResult {
  exitCode: number | null;
  signal: string | null;
  timedOut: boolean;
  stdout: string;
  stderr: string;
  durationMs: number;
  /** True if stdout and/or stderr were cut off at maxOutputBytes before the process finished. */
  truncated: boolean;
}

export type RunOutcome =
  | { kind: "completed"; result: ProcessResult }
  /** The request itself was rejected before anything ran (policy violation, invalid cwd). */
  | { kind: "policy_blocked"; reason: string }
  /** Sandbox infrastructure failed (Docker unreachable, container could not start, etc). */
  | { kind: "runner_error"; message: string };

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
