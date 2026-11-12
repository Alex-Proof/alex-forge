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

// Oracle steps document their own exit-code contract (see RedGreenFixture.oracleCommand above):
// 0 = target state holds, 1 = fault present, 2 = the oracle itself errored. Exit 2 is NOT a
// pass/fail verdict about the system under test at all -- it means the oracle couldn't answer.
// A naive exit-code-equality check has no way to tell "oracle confirmed the fault" (exit 1, by
// its own contract) apart from "oracle crashed" (also commonly exit 1, e.g. Node's default
// uncaught-exception code for a missing module) -- so a broken/missing oracle could silently
// read as a confirmed precondition. toOracleCheck treats exit 2 as its own status, never folded
// into "passed" or "failed" against whatever expectedExitCode happened to be.
const ORACLE_STEP_NAMES = new Set(["precondition_oracle", "dry_run_oracle", "postcondition_oracle"]);
// 2 = the oracle's own documented "I errored" signal. 126/127 are POSIX sh's own "found but not
// executable" / "command not found" -- the oracle command never even started, which is an infra
// problem, not a state verdict either. (A crash *inside* an interpreter that did start, e.g.
// Node's generic exit 1 for an uncaught "module not found", cannot be distinguished this way --
// see the red-team report for why that residual case is accepted rather than claimed fixed.)
const ORACLE_ERROR_EXIT_CODES = new Set([2, 126, 127]);

/**
 * Both real oracles (tcp-port-oracle.mjs, stale-pidfile-oracle.py) print exactly one JSON object
 * with an "oracle" field as their last line of output on every path, success or their own
 * handled error. This closes the residual gap the exit-code checks above cannot: an interpreter
 * that crashes for a reason *outside* the oracle's own error handling (e.g. a third-party import
 * failing before any of the oracle's own code runs) often exits with a generic code like 1,
 * which can coincidentally equal the oracle contract's own "1 = fault present" -- but it will
 * never have printed this marker, since it never reached the oracle's own logic at all. Required
 * on every oracle step regardless of exit code: a "correct-looking" exit code with no real
 * verdict behind it is still refused.
 */
function hasOracleVerdictMarker(output: string): boolean {
  const lines = output.split("\n").map((line) => line.trim()).filter((line) => line.length > 0);
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const parsed = JSON.parse(lines[i]!);
      if (typeof parsed === "object" && parsed !== null && typeof parsed.oracle === "string") {
        return true;
      }
    } catch {
      // Not a JSON line (e.g. a stray log line or a crash's own stack trace) -- keep scanning
      // backwards; the marker only has to appear somewhere in this step's output.
    }
  }
  return false;
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
  if (ORACLE_STEP_NAMES.has(name)) {
    if (ORACLE_ERROR_EXIT_CODES.has(step.exitCode)) {
      return {
        name,
        status: "not_verified",
        exitCode: step.exitCode,
        expectedExitCode,
        details: {
          reason: `the independent oracle did not produce a real state verdict (exit ${step.exitCode}: ${
            step.exitCode === 2 ? "oracle-reported internal error" : "command not found/not executable"
          }) -- this is never treated as pass or fail`,
        },
        stdoutExcerpt: step.output.slice(0, 2000),
      };
    }
    if (!hasOracleVerdictMarker(step.output)) {
      return {
        name,
        status: "not_verified",
        exitCode: step.exitCode,
        expectedExitCode,
        details: {
          reason:
            "the oracle's exit code looked valid but it never printed its own verdict marker -- " +
            "its interpreter likely crashed before reaching the oracle's own logic at all, so this " +
            "exit code is not trusted as a real state verdict",
        },
        stdoutExcerpt: step.output.slice(0, 2000),
      };
    }
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

  // Any oracle step reporting its own error (not_verified, see toCheck above) makes the entire
  // run untrustworthy from that point on -- not just the specific step -- since every later
  // check's expected exit code assumes the oracle can actually answer.
  const brokenOracle = checks.find((c) => ORACLE_STEP_NAMES.has(c.name) && c.status === "not_verified");
  if (brokenOracle) {
    return { status: "not_verified", level: "none", checks };
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
