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
 */
export function admitToCatalog(
  rawEvidence: unknown,
  artifactBytes: Uint8Array,
  evidenceBytes: Uint8Array,
  forgeVersion: string,
): CatalogAdmissionResult {
  const verification = independentlyVerify(rawEvidence, artifactBytes);
  if (!verification.verified || !verification.evidence) {
    return { admitted: false, reasons: verification.reasons };
  }

  const evidence = verification.evidence;
  return {
    admitted: true,
    artifact: {
      artifactId: evidence.artifactId,
      artifactHash: evidence.artifact.sha256,
      format: evidence.artifact.format,
      status: "approved",
      evidenceHash: sha256Hex(evidenceBytes),
      createdAt: new Date().toISOString(),
      forgeVersion,
    },
  };
}
