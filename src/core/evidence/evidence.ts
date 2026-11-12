import { createHash } from "node:crypto";
import type { VerificationSummary } from "../../types/verification.js";
import { policyEngine } from "../policy/policy.js";
import { EVIDENCE_SCHEMA_VERSION, EvidenceSchema, type EvidencePackage } from "./schema.js";

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export interface BuildEvidenceInput {
  artifactId: string;
  artifactFileName: string;
  artifactFormat: "cli" | "html" | "extension";
  artifactContent: Uint8Array;
  /** The already-redacted log text the diagnosis was produced from. */
  sourceLogRedactedText: string;
  targetOS: "linux" | "windows" | "macos";
  sandboxImage: string;
  /** The real VerificationSummary produced by verifyRedGreen; this is transcribed, not re-decided. */
  verification: VerificationSummary;
  forgeVersion: string;
  templateVersion: string;
  /** Honest provenance: who actually proposed this diagnosis. Defaults to the mandatory
   * deterministic fallback's own provenance -- never silently claim a model was involved. */
  modelProvider?: string;
  modelVersion?: string | null;
}

/**
 * Builds evidence.json strictly from observed results: the artifact hash is computed over the
 * artifact's own bytes (and only those bytes -- never over anything that itself references this
 * evidence, which would be circular), and the policy fields come from running the real policy
 * engine on the real input/output/package content right here, not from a caller-supplied claim.
 */
export function buildEvidence(input: BuildEvidenceInput): EvidencePackage {
  const artifactHash = sha256Hex(input.artifactContent);
  const sourceHash = sha256Hex(new TextEncoder().encode(input.sourceLogRedactedText));

  const inputPolicy = policyEngine.inspectText(input.sourceLogRedactedText, "input");
  const generatedCodeText = new TextDecoder("utf-8", { fatal: false }).decode(input.artifactContent);
  const outputPolicy = policyEngine.inspectText(generatedCodeText, "generated-code");
  const packagePolicy = policyEngine.inspectFiles(
    [{ path: input.artifactFileName, content: input.artifactContent }],
    "package",
  );

  const findings = [...inputPolicy.findings, ...outputPolicy.findings, ...packagePolicy.findings];

  const evidence: EvidencePackage = {
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    artifactId: input.artifactId,
    createdAt: new Date().toISOString(),
    artifact: {
      fileName: input.artifactFileName,
      format: input.artifactFormat,
      sha256: artifactHash,
      sizeBytes: input.artifactContent.byteLength,
    },
    source: { kind: "sanitized-log", sha256: sourceHash, rawInputStored: false },
    environment: {
      os: input.targetOS,
      sandbox: "docker",
      sandboxImage: input.sandboxImage,
      network: "disabled",
    },
    policy: {
      version: "1.0.0",
      input: inputPolicy.allowed ? "passed" : "blocked",
      generatedOutput: outputPolicy.allowed ? "passed" : "blocked",
      package: packagePolicy.allowed ? "passed" : "blocked",
      findings,
    },
    verification: {
      status: input.verification.status,
      level: input.verification.level,
      checks: input.verification.checks,
    },
    provenance: {
      forgeVersion: input.forgeVersion,
      templateVersion: input.templateVersion,
      modelProvider: input.modelProvider ?? "fallback-deterministic",
      modelVersion: input.modelVersion ?? null,
    },
  };

  // Self-check against our own schema before handing this out: a builder that produces
  // schema-invalid evidence is a bug, and it must fail loudly here rather than downstream.
  return EvidenceSchema.parse(evidence);
}
