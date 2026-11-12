import type { RepairDiagnosis } from "../../types/diagnosis.js";
import { getRegisteredAction, type ExtensionProjectFiles } from "./actions.js";
import { RepairDiagnosisSchema } from "./schema.js";
import type { DiagnosisProvider } from "../../core/diagnosis-provider/provider.js";

export type DiagnosisValidationResult =
  | { ok: true; diagnosis: RepairDiagnosis }
  | { ok: false; reason: string };

/**
 * The single gate between *any* diagnosis object -- deterministic fallback or, later, a model
 * response -- and code generation. A model may propose a diagnosis; it never gets to assert that
 * an action is legitimate just by naming it. Every actionId must already be registered, and its
 * parameters must pass that specific action's own schema.
 */
export function validateDiagnosis(candidate: unknown): DiagnosisValidationResult {
  const structural = RepairDiagnosisSchema.safeParse(candidate);
  if (!structural.success) {
    return { ok: false, reason: `diagnosis failed schema validation: ${structural.error.message}` };
  }

  for (const step of structural.data.fixPlan) {
    const action = getRegisteredAction(step.actionId);
    if (!action) {
      return { ok: false, reason: `fixPlan references unregistered actionId: ${step.actionId}` };
    }
    const parameterCheck = action.parametersSchema.safeParse(step.parameters);
    if (!parameterCheck.success) {
      return {
        ok: false,
        reason: `parameters for action "${step.actionId}" failed validation: ${parameterCheck.error.message}`,
      };
    }
  }

  return { ok: true, diagnosis: structural.data };
}

const PORT_IN_USE_PATTERNS = [
  /EADDRINUSE/i,
  /address already in use/i,
  /port\s+(\d{1,5})\s+(?:is\s+)?(?:already\s+)?in\s+use/i,
  // Docker's own phrasing (`docker run -p`/compose port-mapping conflicts) never says "in use".
  /port\s+(?:is\s+)?already\s+allocated/i,
];

function isValidPort(port: number): boolean {
  return port >= 1 && port <= 65535;
}

/**
 * Extracts the port number from the specific line(s) that actually triggered the port-conflict
 * match, never from the whole log blob. A bare ":NN" is not enough evidence on its own -- a
 * timestamp like "2026-11-12T20:00:00Z" contains exactly that shape and would otherwise be
 * misread as a listen address (":00" from "20:00:00") before the regex ever reaches the real
 * "...in use :::3000" later in the same line. A real listen-address colon is only trusted when
 * it is anchored to one of the address forms Node/most runtimes actually log: `0.0.0.0`,
 * `127.0.0.1`, `localhost`, or an IPv6 form built on a literal "::" (confirmed against Node's own
 * real EADDRINUSE message text, not assumed) -- e.g. ":::3000" for the "any" address "::", or
 * "::1:3000" for the loopback address "::1". The "::[0-9a-fA-F]{0,4}" branch covers both: it
 * matches the literal "::" plus however many of the next (optional) hex characters belong to the
 * address itself, so it still requires the following ":" + digits to be the actual port -- a
 * plain decimal timestamp never contains two consecutive colons, so it can never trigger this
 * branch by coincidence.
 *
 * A bare ":PORT" with no address literal at all is *also* trusted, but only when it is anchored
 * right after a literal "tcp"/"tcp6"/"udp"/"udp6" -- Go's standard net package logs exactly this
 * shape ("listen tcp :8080: bind: address already in use"), with no 0.0.0.0/127.0.0.1/::
 * anywhere in the message. A timestamp never contains "tcp"/"udp", so this cannot collide with
 * the same ambiguity the address-literal requirement above exists to rule out.
 */
function extractPort(logText: string): number | null {
  const relevantLines = logText
    .split("\n")
    .filter((line) => PORT_IN_USE_PATTERNS.some((pattern) => pattern.test(line)));
  const scopedText = relevantLines.length > 0 ? relevantLines.join("\n") : logText;

  const addressPrefixedMatch = scopedText.match(
    /(?:0\.0\.0\.0|127\.0\.0\.1|localhost|::[0-9a-fA-F]{0,4})\s*:\s*(\d{2,5})\b|(?:tcp6?|udp6?)\s*:\s*(\d{2,5})\b/i,
  );
  if (addressPrefixedMatch) {
    const port = Number.parseInt(addressPrefixedMatch[1] ?? addressPrefixedMatch[2] ?? "", 10);
    if (isValidPort(port)) {
      return port;
    }
  }
  const wordedMatch = scopedText.match(/port\s+(\d{1,5})/i);
  if (wordedMatch?.[1]) {
    const port = Number.parseInt(wordedMatch[1], 10);
    if (isValidPort(port)) {
      return port;
    }
  }
  return null;
}

// Covers both the generic daemon phrasing ("PID file ... already exists") and PostgreSQL's own
// wording ("lock file ... already exists"). Deliberately requires an absolute-path-looking,
// ".pid"-suffixed capture -- a bare filename alone ("postmaster.pid" with no directory) doesn't
// tell Forge enough to safely act on, so that case honestly falls through to needs_review rather
// than guessing a location, the same "never guess" discipline extractPort already follows.
const STALE_PIDFILE_PATTERN = /\b(?:pid|lock)\s*file\s*["']?(\/[A-Za-z0-9_\-./]+\.pid)["']?\s*(?:already\s+)?exists/i;

/**
 * Only `/tmp/<name>.pid` is currently a registered, verifiable action (see
 * ClearStalePidfileParametersSchema in actions.ts for why). A real absolute path mentioned
 * anywhere else (e.g. the very common `/var/run/...`) is honestly reported as unmatched rather
 * than silently rewritten to a different location than what the log actually said.
 */
function extractTmpPidFilePath(logText: string): string | null {
  const match = STALE_PIDFILE_PATTERN.exec(logText);
  const candidate = match?.[1];
  if (candidate && /^\/tmp\/[A-Za-z0-9_-]+\.pid$/.test(candidate)) {
    return candidate;
  }
  return null;
}

/**
 * Deterministic, offline diagnosis. No model call, no network access. Recognizes two fault
 * patterns (a TCP port held by another process, and a stale PID/lock file under /tmp blocking
 * startup) and otherwise honestly reports that it could not match a registered action, rather
 * than guessing a fix.
 */
export function diagnoseFallback(logText: string, targetOS: RepairDiagnosis["targetOS"]): RepairDiagnosis {
  const looksLikePortConflict = PORT_IN_USE_PATTERNS.some((pattern) => pattern.test(logText));
  const port = looksLikePortConflict ? extractPort(logText) : null;

  if (looksLikePortConflict && port !== null) {
    return {
      issueTitle: `Port ${port} is already in use`,
      rootCause: "Another process is already listening on the target TCP port",
      targetOS,
      checkPlan: [`Check whether a process is listening on port ${port}`],
      fixPlan: [{ actionId: "free-tcp-port", parameters: { port } }],
      preconditions: ["A disposable test environment with a reproducible port conflict"],
      riskLevel: "low",
      needsHumanApproval: true,
    };
  }

  const pidFilePath = extractTmpPidFilePath(logText);
  if (pidFilePath !== null) {
    return {
      issueTitle: `Stale PID file at ${pidFilePath}`,
      rootCause: "A leftover PID/lock file from a previous, no-longer-running process is blocking startup",
      targetOS,
      checkPlan: [`Check whether the PID recorded in ${pidFilePath} belongs to a still-running process`],
      fixPlan: [{ actionId: "clear-stale-pidfile", parameters: { pidFilePath } }],
      preconditions: ["A disposable test environment with a reproducible stale pidfile"],
      riskLevel: "low",
      needsHumanApproval: true,
    };
  }

  return {
    issueTitle: "Unrecognized error pattern",
    rootCause: "The deterministic fallback has no registered action matching this input",
    targetOS,
    checkPlan: [],
    fixPlan: [],
    preconditions: [],
    riskLevel: "high",
    needsHumanApproval: true,
  };
}

export const FALLBACK_PROVENANCE = { modelProvider: "fallback-deterministic", modelVersion: null } as const;

export interface DiagnosisOutcome {
  diagnosis: RepairDiagnosis;
  modelProvider: string;
  modelVersion: string | null;
}

/**
 * The single place a model provider and the mandatory deterministic fallback meet (blueprint
 * section 20: "Modell ist optional; Fallback ist verpflichtend"). A provider's response is never
 * trusted more than the fallback's own output -- both are just an untrusted `candidate` object
 * until `validateDiagnosis` says otherwise. Any missing/unconfigured provider, disabled model
 * use, network failure, or a model response that fails validation all resolve the exact same
 * way: the deterministic fallback runs and its result is returned, never a thrown error and
 * never a partially-trusted guess.
 */
export async function proposeDiagnosis(input: {
  redactedLogText: string;
  targetOS: RepairDiagnosis["targetOS"];
  provider?: DiagnosisProvider | null;
}): Promise<DiagnosisOutcome> {
  if (input.provider) {
    const response = await input.provider.propose(input.redactedLogText, input.targetOS);
    if (response) {
      const validated = validateDiagnosis(response.candidate);
      if (validated.ok) {
        return { diagnosis: validated.diagnosis, modelProvider: input.provider.name, modelVersion: response.modelVersion };
      }
    }
  }
  return { diagnosis: diagnoseFallback(input.redactedLogText, input.targetOS), ...FALLBACK_PROVENANCE };
}

export type GenerateCliArtifactResult =
  | { ok: true; fileName: string; content: string }
  | { ok: false; reason: string };

/**
 * Turns a validated diagnosis into a CLI script. Re-validates the diagnosis itself (never trusts
 * an already-typed object blindly) and only supports a single registered action per artifact for
 * now; multi-action composition is future work, not an MVP requirement.
 */
export function generateCliArtifact(diagnosis: RepairDiagnosis): GenerateCliArtifactResult {
  const validated = validateDiagnosis(diagnosis);
  if (!validated.ok) {
    return { ok: false, reason: validated.reason };
  }

  if (validated.diagnosis.fixPlan.length === 0) {
    return { ok: false, reason: "diagnosis has no registered fix action; nothing to generate" };
  }
  if (validated.diagnosis.fixPlan.length > 1) {
    return { ok: false, reason: "multi-action diagnoses are not supported by the current template catalog" };
  }
  if (validated.diagnosis.targetOS !== "linux") {
    return {
      ok: false,
      reason: `no CLI template exists yet for targetOS "${validated.diagnosis.targetOS}"`,
    };
  }

  const step = validated.diagnosis.fixPlan[0];
  if (!step) {
    return { ok: false, reason: "diagnosis has no registered fix action; nothing to generate" };
  }
  const action = getRegisteredAction(step.actionId);
  if (!action) {
    return { ok: false, reason: `fixPlan references unregistered actionId: ${step.actionId}` };
  }

  return { ok: true, fileName: "repair.sh", content: action.generateScript(step.parameters) };
}

export type GenerateHtmlArtifactResult =
  | { ok: true; fileName: string; content: string }
  | { ok: false; reason: string };

/**
 * Turns a validated diagnosis into a standalone HTML report. Same validation discipline as
 * generateCliArtifact: re-validates the diagnosis, refuses an empty or multi-action fixPlan, and
 * refuses an action that has no HTML template rather than silently falling back to something
 * else.
 */
export function generateHtmlArtifact(diagnosis: RepairDiagnosis): GenerateHtmlArtifactResult {
  const validated = validateDiagnosis(diagnosis);
  if (!validated.ok) {
    return { ok: false, reason: validated.reason };
  }
  if (validated.diagnosis.fixPlan.length === 0) {
    return { ok: false, reason: "diagnosis has no registered fix action; nothing to generate" };
  }
  if (validated.diagnosis.fixPlan.length > 1) {
    return { ok: false, reason: "multi-action diagnoses are not supported by the current template catalog" };
  }
  if (validated.diagnosis.targetOS !== "linux") {
    return { ok: false, reason: `no HTML template exists yet for targetOS "${validated.diagnosis.targetOS}"` };
  }

  const step = validated.diagnosis.fixPlan[0];
  if (!step) {
    return { ok: false, reason: "diagnosis has no registered fix action; nothing to generate" };
  }
  const action = getRegisteredAction(step.actionId);
  if (!action) {
    return { ok: false, reason: `fixPlan references unregistered actionId: ${step.actionId}` };
  }
  if (!action.generateHtml) {
    return { ok: false, reason: `action "${step.actionId}" has no HTML template yet` };
  }

  return { ok: true, fileName: "repair.html", content: action.generateHtml(step.parameters) };
}

export type GenerateExtensionArtifactResult =
  | { ok: true; files: ExtensionProjectFiles }
  | { ok: false; reason: string };

/**
 * Turns a validated diagnosis into a VS Code extension companion project (source files only --
 * packaging and the real runtime check happen in src/core/verification/verify-extension.ts). Same
 * validation discipline as generateCliArtifact/generateHtmlArtifact.
 */
export function generateExtensionArtifact(diagnosis: RepairDiagnosis): GenerateExtensionArtifactResult {
  const validated = validateDiagnosis(diagnosis);
  if (!validated.ok) {
    return { ok: false, reason: validated.reason };
  }
  if (validated.diagnosis.fixPlan.length === 0) {
    return { ok: false, reason: "diagnosis has no registered fix action; nothing to generate" };
  }
  if (validated.diagnosis.fixPlan.length > 1) {
    return { ok: false, reason: "multi-action diagnoses are not supported by the current template catalog" };
  }
  if (validated.diagnosis.targetOS !== "linux") {
    return { ok: false, reason: `no extension template exists yet for targetOS "${validated.diagnosis.targetOS}"` };
  }

  const step = validated.diagnosis.fixPlan[0];
  if (!step) {
    return { ok: false, reason: "diagnosis has no registered fix action; nothing to generate" };
  }
  const action = getRegisteredAction(step.actionId);
  if (!action) {
    return { ok: false, reason: `fixPlan references unregistered actionId: ${step.actionId}` };
  }
  if (!action.generateExtensionProject) {
    return { ok: false, reason: `action "${step.actionId}" has no extension template yet` };
  }

  return { ok: true, files: action.generateExtensionProject(step.parameters) };
}
