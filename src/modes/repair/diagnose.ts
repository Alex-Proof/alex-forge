import type { RepairDiagnosis } from "../../types/diagnosis.js";
import { getRegisteredAction } from "./actions.js";
import { RepairDiagnosisSchema } from "./schema.js";

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
];

function extractPort(logText: string): number | null {
  const colonPortMatch = logText.match(/(?:0\.0\.0\.0|127\.0\.0\.1|::|:::|localhost)?:(\d{2,5})\b/);
  if (colonPortMatch?.[1]) {
    const port = Number.parseInt(colonPortMatch[1], 10);
    if (port >= 1 && port <= 65535) {
      return port;
    }
  }
  const wordedMatch = logText.match(/port\s+(\d{1,5})/i);
  if (wordedMatch?.[1]) {
    const port = Number.parseInt(wordedMatch[1], 10);
    if (port >= 1 && port <= 65535) {
      return port;
    }
  }
  return null;
}

/**
 * Deterministic, offline diagnosis. No model call, no network access. Recognizes exactly one
 * fault pattern for now (a TCP port held by another process) and otherwise honestly reports that
 * it could not match a registered action, rather than guessing a fix.
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
