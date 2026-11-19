import { createHash } from "node:crypto";
import type { CatalogArtifact } from "../../types/catalog.js";
import { independentlyVerify } from "../evidence/independent-verifier.js";

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export type CatalogAdmissionResult =
  | { admitted: true; artifact: CatalogArtifact }
  | { admitted: false; reasons: string[] };

/**
 * The single, non-model-controlled gate into the catalog (blueprint 11.1 / 14.3): nothing else in
 * this codebase constructs a CatalogArtifact with status "approved". Admission always goes
 * through the independent verifier -- never through the evidence's own self-reported status.
 *
 * "diff" format is a deliberate exception (docs/ASSUMPTIONS.md A-026 in alex-core): it has no
 * registered-action allowlist constraining what it can change, so even a fully passing
 * independent verification lands as "needs_human_approval", never "approved", directly from this
 * function. Only {@link approveCatalogArtifact} -- a separate, explicit human step -- may flip
 * that to "approved", and it re-runs the same independent verification before doing so rather
 * than trusting the stored record.
 */
export function admitToCatalog(
  rawEvidence: unknown,
  artifactBytes: Uint8Array,
  evidenceBytes: Uint8Array,
  forgeVersion: string,
  trustedPublicKeyPem?: string,
): CatalogAdmissionResult {
  const verification = independentlyVerify(rawEvidence, artifactBytes, trustedPublicKeyPem);
  if (!verification.verified || !verification.evidence) {
    return { admitted: false, reasons: verification.reasons };
  }

  const evidence = verification.evidence;
  const isDiffFormat = evidence.artifact.format === "diff";
  return {
    admitted: true,
    artifact: {
      artifactId: evidence.artifactId,
      artifactHash: evidence.artifact.sha256,
      format: evidence.artifact.format,
      status: isDiffFormat ? "needs_human_approval" : "approved",
      evidenceHash: sha256Hex(evidenceBytes),
      createdAt: new Date().toISOString(),
      forgeVersion,
    },
  };
}

/**
 * The only function in this codebase allowed to turn a "needs_human_approval" record into
 * "approved". Deliberately re-runs independent verification against the stored evidence/artifact
 * bytes rather than trusting the existing catalog record -- a record that was tampered with
 * between admission and this call must still fail here. `approvedBy` is required and is never
 * defaulted, so an approval can always be attributed to a real human-in-the-loop actor.
 */
export function approveCatalogArtifact(
  existing: CatalogArtifact,
  rawEvidence: unknown,
  artifactBytes: Uint8Array,
  trustedPublicKeyPem: string | undefined,
  approvedBy: string,
): CatalogAdmissionResult {
  if (existing.status !== "needs_human_approval") {
    return { admitted: false, reasons: [`catalog record ${existing.artifactId} is not pending human approval`] };
  }
  const verification = independentlyVerify(rawEvidence, artifactBytes, trustedPublicKeyPem);
  if (!verification.verified || !verification.evidence) {
    return { admitted: false, reasons: verification.reasons };
  }
  if (verification.evidence.artifact.sha256 !== existing.artifactHash) {
    return { admitted: false, reasons: ["artifact hash no longer matches the stored catalog record"] };
  }

  return {
    admitted: true,
    artifact: {
      ...existing,
      status: "approved",
      approvedAt: new Date().toISOString(),
      approvedBy,
    },
  };
}
