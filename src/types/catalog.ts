export interface CatalogArtifact {
  artifactId: string;
  artifactHash: string;
  format: "cli" | "html" | "extension" | "diff";
  /**
   * "diff" format can never be admitted directly as "approved" -- see
   * core/catalog/catalog.ts::admitToCatalog(). It always lands as "needs_human_approval" first;
   * only approveCatalogArtifact() (an explicit, separate human step) may flip it to "approved".
   */
  status: "approved" | "needs_human_approval";
  evidenceHash: string;
  createdAt: string;
  forgeVersion: string;
  /** Set only by approveCatalogArtifact(); absent on every other record. */
  approvedAt?: string;
  approvedBy?: string;
}
