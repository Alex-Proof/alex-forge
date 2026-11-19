import { writeFile } from "node:fs/promises";
import path from "node:path";
import type { VerificationCheck, VerificationLevel, VerificationStatus, VerificationSummary } from "../../types/verification.js";
import type { Sandbox } from "./sandbox.js";
import type { ProcessRequest } from "./process-runner.js";

/**
 * Red/green fixture for the "diff" format (see docs/ASSUMPTIONS.md A-026 in alex-core). Unlike
 * RedGreenFixture (verify-cli.ts), there is no registered action here -- `diffText` is an
 * arbitrary unified diff, so this protocol leans harder on independent confirmation than the
 * action-based formats do: `verificationCommand` and `oracleCommand` MUST be two different,
 * independently meaningful checks (e.g. "the project's own test/lint command" and "a direct
 * re-run of the exact static check that produced this finding"). A diff that only satisfies one
 * of them is not accepted as fixed.
 */
export interface DiffVerificationFixture {
  /**
   * Caller is responsible for staging the target source tree into the sandbox's `hostWorkDir`
   * BEFORE calling {@link verifyDiff} -- this must always be a disposable snapshot/worktree, never
   * the caller's real working directory. This command runs first, inside the container, and may
   * do additional setup. Deliberately NOT a git repository: Forge's sandbox always runs with
   * `network: "disabled"` (sandbox.ts), so `git` cannot be installed into a bare image and is not
   * assumed present. The diff is applied with BusyBox's `patch` applet instead (present in every
   * Alpine-based sandbox image by default), via `-p1` against plain unified-diff headers
   * (`a/<path>` / `b/<path>`), on files that already exist -- not new-file creation, which
   * BusyBox's reduced `patch` is not documented to support reliably.
   */
  setupCommand: string;
  /** Unified diff text (plain `-p1` unified format, modifying existing files only). Written to
   *  `repair.diff` in the sandbox workdir by this module itself -- never interpolated into a
   *  shell string -- and applied only after a dry run against a disposable copy succeeds. */
  diffText: string;
  /** Caller-supplied regression command (e.g. the project's real test/lint invocation). Forge
   *  never invents this command; an invented check would make the red/green proof meaningless. */
  verificationCommand: string;
  /** A SEPARATE, independently implemented re-check of the exact finding this diff claims to fix
   *  (e.g. re-running serviceAudit's own dangling-import detector against the patched tree).
   *  Contract matches verify-cli.ts's oracle: exit 0 = fault gone, exit 1 = fault present,
   *  exit 2 = oracle itself errored (never read as pass or fail). */
  oracleCommand: string;
}

interface StepResult {
  name: string;
  exitCode: number;
  output: string;
}

const STEP_START = (name: string): string => `###STEP:${name}:START###`;
const STEP_EXIT = (name: string, code: string): string => `###STEP:${name}:EXIT:${code}###`;

const ORACLE_STEP_NAMES = new Set(["precondition_oracle", "postcondition_oracle"]);
// Same contract as verify-cli.ts's ORACLE_ERROR_EXIT_CODES: 2 is the oracle's own "I errored"
// signal, 126/127 mean the command never even started. None of these are a state verdict.
const ORACLE_ERROR_EXIT_CODES = new Set([2, 126, 127]);

function buildScript(fixture: DiffVerificationFixture): { script: string; stepNames: string[] } {
  const steps: Array<{ name: string; command: string }> = [
    { name: "precondition_oracle", command: fixture.oracleCommand },
    { name: "check_before_diff", command: fixture.verificationCommand },
    {
      name: "apply_check",
      // Dry-run against a disposable copy under /tmp (the one writable path in the --read-only
      // sandbox root, see sandbox.ts's --tmpfs /tmp) rather than a --dry-run flag: BusyBox's
      // reduced `patch` is not documented to support one, so this tests the real command instead.
      command:
        "(rm -rf /tmp/forge-diff-check && cp -r /workspace /tmp/forge-diff-check && " +
        "cd /tmp/forge-diff-check && patch -p1 < /workspace/repair.diff); rc=$?; " +
        "rm -rf /tmp/forge-diff-check; exit $rc",
    },
    { name: "apply", command: "patch -p1 < repair.diff" },
    { name: "check_after_diff", command: fixture.verificationCommand },
    { name: "postcondition_oracle", command: fixture.oracleCommand },
  ];

  const lines = [fixture.setupCommand];
  for (const step of steps) {
    lines.push(`echo "${STEP_START(step.name)}"`);
    // Jeder Step laeuft in einer eigenen Subshell: mehrere Step-Befehle (precondition_oracle,
    // apply_check, postcondition_oracle) enden selbst mit `exit N`, um ihren Verdikt zu
    // signalisieren. Ohne diese Klammerung wuerde dieses `exit` das gesamte sh-c-Skript sofort
    // beenden (es ist sonst EIN zusammenhaengender Top-Level-Lauf) -- noch vor der eigenen
    // EXIT-Marker-Zeile und allen folgenden Steps. Gefunden 19.11.2026: genau dieser Fehler liess
    // in CI (echtes Docker, erster echter Lauf ueberhaupt -- siehe docs/ASSUMPTIONS.md A-026)
    // ausnahmslos jeden Check auf "not_verified" zurueckfallen, weil parseSteps() beim allerersten
    // Step (precondition_oracle) schon keinen vollstaendigen START/EXIT-Marker mehr fand.
    lines.push(`( ${step.command} ) 2>&1`);
    lines.push(`echo "${STEP_EXIT(step.name, "$?")}"`);
  }
  return { script: lines.join("\n"), stepNames: steps.map((s) => s.name) };
}

function parseSteps(stdout: string, expectedNames: string[]): StepResult[] {
  const results: StepResult[] = [];
  for (const name of expectedNames) {
    const pattern = new RegExp(`###STEP:${name}:START###\\n([\\s\\S]*?)###STEP:${name}:EXIT:(\\d+)###`);
    const match = pattern.exec(stdout);
    if (!match) {
      break; // script was killed (timeout/output limit) before this step's marker was written
    }
    results.push({ name, output: match[1] ?? "", exitCode: Number.parseInt(match[2] ?? "-1", 10) });
  }
  return results;
}

function hasOracleVerdictMarker(output: string): boolean {
  const lines = output.split("\n").map((line) => line.trim()).filter((line) => line.length > 0);
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const parsed = JSON.parse(lines[i]!);
      if (typeof parsed === "object" && parsed !== null && typeof parsed.oracle === "string") {
        return true;
      }
    } catch {
      // keep scanning backwards; not every line needs to be JSON
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
        details: { reason: `independent oracle did not produce a real verdict (exit ${step.exitCode})` },
        stdoutExcerpt: step.output.slice(0, 2000),
      };
    }
    if (!hasOracleVerdictMarker(step.output)) {
      return {
        name,
        status: "not_verified",
        exitCode: step.exitCode,
        expectedExitCode,
        details: { reason: "oracle exit code looked valid but it never printed its own verdict marker" },
        stdoutExcerpt: step.output.slice(0, 2000),
      };
    }
  }
  const status: VerificationStatus = step.exitCode === expectedExitCode ? "passed" : "failed";
  return { name, status, exitCode: step.exitCode, expectedExitCode, stdoutExcerpt: step.output.slice(0, 2000) };
}

/**
 * `verificationCommand` is caller-supplied (e.g. a project's own `npm run lint`) and has no fixed
 * exit-code contract beyond the universal "0 = passed" convention -- unlike the oracle, Forge
 * cannot assume a specific non-zero code means "fault confirmed". `check_before_diff` therefore
 * only requires "not 0", never a specific number.
 */
function toNonZeroCheck(name: string, step: StepResult | undefined): VerificationCheck {
  if (!step) {
    return { name, status: "not_verified", exitCode: null, details: { reason: "step did not complete" } };
  }
  const status: VerificationStatus = step.exitCode !== 0 ? "passed" : "failed";
  return { name, status, exitCode: step.exitCode, stdoutExcerpt: step.output.slice(0, 2000) };
}

function finalize(checks: VerificationCheck[]): VerificationSummary {
  const allPassed = checks.every((c) => c.status === "passed");
  if (allPassed) {
    return { status: "passed", level: "L3_state_transition_verified", checks };
  }

  const brokenOracle = checks.find((c) => ORACLE_STEP_NAMES.has(c.name) && c.status === "not_verified");
  if (brokenOracle) {
    return { status: "not_verified", level: "none", checks };
  }

  const precondition = checks.find((c) => c.name === "precondition_oracle");
  if (precondition && precondition.status !== "passed") {
    // The finding could not be confirmed reproducible before anything else ran -- honest
    // "could not test this", never a claim that the fix itself failed.
    return { status: "not_verified", level: "none", checks };
  }

  const applyCheck = checks.find((c) => c.name === "apply_check");
  if (applyCheck && applyCheck.status !== "passed") {
    // The diff no longer applies cleanly to the snapshot -- never force an apply.
    return { status: "not_verified", level: "none", checks };
  }

  const level: VerificationLevel = checks.some((c) => c.status === "passed") ? "L2_sandbox_executed" : "none";
  return { status: "failed", level, checks };
}

/**
 * Runs the diff red/green protocol inside a single sandboxed container run: confirm the finding
 * reproduces (red), apply the diff (check-only first, never forced), confirm the caller's own
 * verification command passes (green), and cross-check with a separately implemented oracle for
 * the exact original finding. A sandbox failure or policy block resolves to `not_verified`/
 * `blocked` -- never to anything that could be mistaken for a passing run. Per docs/ASSUMPTIONS.md
 * A-026, a `passed` result here is NOT itself a catalog-admission decision -- the diff format's
 * non-negotiable human-approval gate lives in core/catalog/catalog.ts, not here.
 */
export async function verifyDiff(
  sandbox: Sandbox,
  fixture: DiffVerificationFixture,
  options?: { timeoutMs?: number; maxOutputBytes?: number },
): Promise<VerificationSummary> {
  await writeFile(path.join(sandbox.hostWorkDir, "repair.diff"), fixture.diffText, "utf-8");

  const { script, stepNames } = buildScript(fixture);
  const request: ProcessRequest = {
    executable: "sh",
    args: ["-c", script],
    cwd: "/workspace",
    env: {},
    timeoutMs: options?.timeoutMs ?? 30_000,
    maxOutputBytes: options?.maxOutputBytes ?? 400_000,
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
    toNonZeroCheck("check_before_diff", byName.get("check_before_diff")),
    toCheck("apply_check", 0, byName.get("apply_check")),
    toCheck("apply", 0, byName.get("apply")),
    toCheck("check_after_diff", 0, byName.get("check_after_diff")),
    toCheck("postcondition_oracle", 0, byName.get("postcondition_oracle")),
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
