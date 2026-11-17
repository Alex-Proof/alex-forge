import { createHash } from "node:crypto";
import { EvidenceSchema, type EvidencePackage } from "./schema.js";
import { canonicalJson } from "./canonical-json.js";
import { forgeVerify } from "./keystore.js";
import { verifyRfc3161Binding, verifyRfc3161TsaChain } from "./rfc3161-timestamp.js";

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

// The CLI red/green protocol's fixed step names (verify-cli.ts). Only evidence claiming
// L3_state_transition_verified is held to this exact, named sequence.
const CLI_RED_GREEN_CHECK_NAMES = [
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

/**
 * `trustedPublicKeyPem`, when given, must come from somewhere other than the evidence file
 * itself (a published trust anchor, a prior catalog entry) -- an embedded public key would let a
 * forger regenerate both a fresh keypair and a matching signature. Omitting it keeps the old,
 * signature-blind behavior (structural + hash checks only), which is what every pre-existing
 * caller and test still relies on.
 */
export function independentlyVerify(
  rawEvidence: unknown,
  artifactBytes: Uint8Array,
  trustedPublicKeyPem?: string,
): IndependentVerificationResult {
  const schemaResult = EvidenceSchema.safeParse(rawEvidence);
  if (!schemaResult.success) {
    return { verified: false, reasons: [`evidence failed schema validation: ${schemaResult.error.message}`] };
  }
  const evidence = schemaResult.data;
  const reasons: string[] = [];

  if (trustedPublicKeyPem !== undefined) {
    if (!evidence.proof) {
      reasons.push("evidence carries no proof (signature) but a trusted public key was supplied");
    } else {
      const { proof, ...unsigned } = evidence;
      const digest = createHash("sha256").update(canonicalJson(unsigned)).digest();
      if (!forgeVerify(trustedPublicKeyPem, digest, proof.signature)) {
        reasons.push("signature does not verify against the supplied trusted public key");
      }
    }
  }

  // RFC3161 is best-effort and optional (rfc3161-timestamp.ts): absence is never a reason to
  // fail, exactly like every pre-existing evidence package that predates this field. Only when a
  // timestamp IS present does it have to actually hold up -- both the hash binding (including
  // the token's own cryptographically signed hash, not just the self-declared field) and the TSA
  // signature/certificate chain against the pinned FreeTSA root.
  if (evidence.rfc3161_timestamp) {
    const binding = verifyRfc3161Binding(evidence);
    if (!binding.ok) {
      reasons.push(`rfc3161 timestamp binding check failed: ${binding.reason ?? "unknown"}`);
    }
    const chain = verifyRfc3161TsaChain(evidence.rfc3161_timestamp);
    if (!chain.ok) {
      reasons.push(`rfc3161 timestamp TSA chain check failed: ${chain.reason ?? "unknown"}`);
    }
  }

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

  // What counts as "actually verified" depends on the format: a CLI artifact must have gone
  // through the full named red/green protocol; a format with no OS-level state to verify (e.g.
  // HTML, checked by a real headless-browser functional/CSP run) instead must show that
  // everything that WAS checked actually passed, and that something was checked at all -- an
  // empty checks array can never count as verified just because nothing in it failed.
  if (evidence.verification.level === "L3_state_transition_verified") {
    for (const name of CLI_RED_GREEN_CHECK_NAMES) {
      const matchingCheck = evidence.verification.checks.find((c) => c.name === name);
      if (!matchingCheck) {
        reasons.push(`missing mandatory verification check: ${name}`);
        continue;
      }
      if (matchingCheck.status !== "passed") {
        reasons.push(`mandatory check "${name}" is not passed (status=${matchingCheck.status})`);
      }
    }
  } else if (evidence.verification.level === "L2_sandbox_executed") {
    if (evidence.verification.checks.length === 0) {
      reasons.push("verification level claims L2_sandbox_executed but no checks were recorded");
    }
    for (const recordedCheck of evidence.verification.checks) {
      if (recordedCheck.status !== "passed") {
        reasons.push(`check "${recordedCheck.name}" is not passed (status=${recordedCheck.status})`);
      }
    }
  } else {
    reasons.push(
      `verification level "${evidence.verification.level}" is not sufficient for catalog admission ` +
        `(expected L2_sandbox_executed or L3_state_transition_verified)`,
    );
  }

  if (evidence.verification.status !== "passed") {
    reasons.push(`verification status is "${evidence.verification.status}", expected "passed"`);
  }

  return { verified: reasons.length === 0, reasons, evidence };
}
