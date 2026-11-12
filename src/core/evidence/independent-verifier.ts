import { createHash } from "node:crypto";
import { EvidenceSchema, type EvidencePackage } from "./schema.js";

/**
 * A second, independently implemented verifier. This file deliberately imports nothing from
 * evidence.ts: it must not share the logic that produced the evidence, or a bug or a forged
 * evidence.json could pass its own self-check. It re-derives every decision from raw data --
 * recomputes the artifact hash itself, and re-evaluates pass/fail from the raw checks array
 * rather than trusting `verification.status` as given.
 */

export interface IndependentVerificationResult {
  verified: boolean;
  reasons: string[];
  /** Present whenever the evidence at least parsed against the schema, verified or not. */
  evidence?: EvidencePackage;
}

const MANDATORY_CHECK_NAMES = [
  "precondition_oracle",
  "check_before_fix",
  "dry_run",
  "dry_run_oracle",
  "fix",
  "postcondition_oracle",
  "check_after_fix",
  "verify",
];

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function independentlyVerify(rawEvidence: unknown, artifactBytes: Uint8Array): IndependentVerificationResult {
  const schemaResult = EvidenceSchema.safeParse(rawEvidence);
  if (!schemaResult.success) {
    return { verified: false, reasons: [`evidence failed schema validation: ${schemaResult.error.message}`] };
  }
  const evidence = schemaResult.data;
  const reasons: string[] = [];

  const recomputedHash = sha256Hex(artifactBytes);
  if (recomputedHash !== evidence.artifact.sha256) {
    reasons.push(
      `artifact hash mismatch: evidence claims ${evidence.artifact.sha256}, recomputed ${recomputedHash}`,
    );
  }
  if (artifactBytes.byteLength !== evidence.artifact.sizeBytes) {
    reasons.push(
      `artifact size mismatch: evidence claims ${evidence.artifact.sizeBytes} bytes, actual ${artifactBytes.byteLength} bytes`,
    );
  }

  if (evidence.policy.input !== "passed") {
    reasons.push(`input policy did not pass (status=${evidence.policy.input})`);
  }
  if (evidence.policy.generatedOutput !== "passed") {
    reasons.push(`generated-output policy did not pass (status=${evidence.policy.generatedOutput})`);
  }
  if (evidence.policy.package !== "passed") {
    reasons.push(`package policy did not pass (status=${evidence.policy.package})`);
  }
  if (evidence.policy.findings.some((finding) => finding.severity === "block")) {
    reasons.push("policy findings include an unresolved block-severity finding");
  }

  for (const name of MANDATORY_CHECK_NAMES) {
    const check = evidence.verification.checks.find((c) => c.name === name);
    if (!check) {
      reasons.push(`missing mandatory verification check: ${name}`);
      continue;
    }
    if (check.status !== "passed") {
      reasons.push(`mandatory check "${name}" is not passed (status=${check.status})`);
    }
  }

  if (evidence.verification.level !== "L3_state_transition_verified") {
    reasons.push(
      `verification level is "${evidence.verification.level}", expected "L3_state_transition_verified"`,
    );
  }
  if (evidence.verification.status !== "passed") {
    reasons.push(`verification status is "${evidence.verification.status}", expected "passed"`);
  }

  return { verified: reasons.length === 0, reasons, evidence };
}
