import type { VerificationCheck, VerificationLevel, VerificationStatus, VerificationSummary } from "../../types/verification.js";
import type { Sandbox } from "./sandbox.js";
import type { ProcessRequest } from "./process-runner.js";

/**
 * A red/green fixture: the shell commands needed to run the blueprint's state-transition
 * protocol (setup, independent oracle, --check, --dry-run, --fix, --verify) for one repair case.
 * `oracleCommand` MUST be implemented independently of the generated CLI artifact being tested --
 * see tests/fixtures/tcp-port-oracle.mjs for why and how.
 */
export interface RedGreenFixture {
  /** Establishes the fault state. May background a long-lived holder process. */
  setupCommand: string;
  /** Runs the independent oracle. Exit 0 = target state holds, exit 1 = fault present, exit 2 = oracle error. */
  oracleCommand: string;
  /** Builds the shell invocation for one CLI flag against the generated artifact. */
  cliCommand: (flag: "--check" | "--dry-run" | "--fix" | "--verify") => string;
}

interface StepResult {
  name: string;
  exitCode: number;
  output: string;
}

const STEP_START = (name: string): string => `###STEP:${name}:START###`;
const STEP_EXIT = (name: string, code: string): string => `###STEP:${name}:EXIT:${code}###`;

function buildProtocolScript(fixture: RedGreenFixture): { script: string; stepNames: string[] } {
  const steps: Array<{ name: string; command: string }> = [
    { name: "precondition_oracle", command: fixture.oracleCommand },
    { name: "check_before_fix", command: fixture.cliCommand("--check") },
    { name: "dry_run", command: fixture.cliCommand("--dry-run") },
    { name: "dry_run_oracle", command: fixture.oracleCommand },
    { name: "fix", command: fixture.cliCommand("--fix") },
    { name: "postcondition_oracle", command: fixture.oracleCommand },
    { name: "check_after_fix", command: fixture.cliCommand("--check") },
    { name: "verify", command: fixture.cliCommand("--verify") },
  ];

  const lines = [fixture.setupCommand, "sleep 0.3"];
  for (const step of steps) {
    lines.push(`echo "${STEP_START(step.name)}"`);
    lines.push(`${step.command} 2>&1`);
    lines.push(`echo "${STEP_EXIT(step.name, "$?")}"`);
  }

  return { script: lines.join("\n"), stepNames: steps.map((s) => s.name) };
}

function parseSteps(stdout: string, expectedNames: string[]): StepResult[] {
  const results: StepResult[] = [];
  for (const name of expectedNames) {
    const pattern = new RegExp(
      `###STEP:${name}:START###\\n([\\s\\S]*?)###STEP:${name}:EXIT:(\\d+)###`,
    );
    const match = pattern.exec(stdout);
    if (!match) {
      // Script was killed (timeout/output limit) before this step's marker was written.
      break;
    }
    results.push({ name, output: match[1] ?? "", exitCode: Number.parseInt(match[2] ?? "-1", 10) });
  }
  return results;
}

function toCheck(name: string, expectedExitCode: number, step: StepResult | undefined): VerificationCheck {
  if (!step) {
    return {
      name,
      status: "not_verified",
      exitCode: null,
      expectedExitCode,
      details: { reason: "step did not complete (sandbox run ended early)" },
    };
  }
  const status: VerificationStatus = step.exitCode === expectedExitCode ? "passed" : "failed";
  return {
    name,
    status,
    exitCode: step.exitCode,
    expectedExitCode,
    stdoutExcerpt: step.output.slice(0, 2000),
  };
}

function finalize(checks: VerificationCheck[]): VerificationSummary {
  const allPassed = checks.every((c) => c.status === "passed");
  if (allPassed) {
    return { status: "passed", level: "L3_state_transition_verified", checks };
  }

  const precondition = checks.find((c) => c.name === "precondition_oracle");
  if (precondition && precondition.status !== "passed") {
    // The fault state could not be confirmed reproducible before anything else ran: this is an
    // honest "we could not test this", never a failure of the fix itself.
    return { status: "not_verified", level: "none", checks };
  }

  const level: VerificationLevel = checks.some((c) => c.status === "passed") ? "L2_sandbox_executed" : "none";
  return { status: "failed", level, checks };
}

/**
 * Runs the full blueprint red/green protocol for one fixture inside a single sandboxed container
 * run, and cross-checks every state transition against an oracle that is implemented separately
 * from the artifact under test. A sandbox infrastructure failure or a policy block resolves to
 * `not_verified`/`blocked` -- never to anything that could be mistaken for a passing run.
 */
export async function verifyRedGreen(
  sandbox: Sandbox,
  fixture: RedGreenFixture,
  options?: { timeoutMs?: number; maxOutputBytes?: number },
): Promise<VerificationSummary> {
  const { script, stepNames } = buildProtocolScript(fixture);

  const request: ProcessRequest = {
    executable: "sh",
    args: ["-c", script],
    cwd: "/workspace",
    env: {},
    timeoutMs: options?.timeoutMs ?? 20_000,
    maxOutputBytes: options?.maxOutputBytes ?? 200_000,
  };

  const outcome = await sandbox.run(request);

  if (outcome.kind === "policy_blocked") {
    return {
      status: "blocked",
      level: "none",
      checks: [{ name: "sandbox_run", status: "blocked", exitCode: null, details: { reason: outcome.reason } }],
    };
  }
  if (outcome.kind === "runner_error") {
    return {
      status: "not_verified",
      level: "none",
      checks: [{ name: "sandbox_run", status: "not_verified", exitCode: null, details: { message: outcome.message } }],
    };
  }

  const steps = parseSteps(outcome.result.stdout, stepNames);
  const byName = new Map(steps.map((s) => [s.name, s]));

  const checks: VerificationCheck[] = [
    toCheck("precondition_oracle", 1, byName.get("precondition_oracle")),
    toCheck("check_before_fix", 1, byName.get("check_before_fix")),
    toCheck("dry_run", 0, byName.get("dry_run")),
    toCheck("dry_run_oracle", 1, byName.get("dry_run_oracle")),
    toCheck("fix", 0, byName.get("fix")),
    toCheck("postcondition_oracle", 0, byName.get("postcondition_oracle")),
    toCheck("check_after_fix", 0, byName.get("check_after_fix")),
    toCheck("verify", 0, byName.get("verify")),
  ];

  if (outcome.result.timedOut || outcome.result.truncated) {
    checks.push({
      name: "sandbox_run",
      status: "not_verified",
      exitCode: null,
      details: { timedOut: outcome.result.timedOut, truncated: outcome.result.truncated },
    });
  }

  return finalize(checks);
}
