export interface CatalogArtifact {
  artifactId: string;
  artifactHash: string;
  format: "cli" | "html" | "extension";
  status: "approved";
  evidenceHash: string;
  createdAt: string;
  forgeVersion: string;
}
