import AdmZip from "adm-zip";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, rename, rm } from "node:fs/promises";
import path from "node:path";
import type { EvidencePackage } from "../evidence/schema.js";

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

// Entry names we control ourselves (artifact file name, fixed structural files). Anything that
// doesn't match this is rejected before it's ever added to the archive -- defense against path
// traversal / absolute-path / symlink-style entry names, per the blueprint's export checklist.
const SAFE_ZIP_ENTRY_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*(\/[A-Za-z0-9][A-Za-z0-9._-]*)*$/;

function assertSafeZipEntryName(entryName: string): void {
  if (entryName.includes("..") || entryName.startsWith("/") || entryName.includes("\\")) {
    throw new Error(`unsafe ZIP entry name rejected: ${entryName}`);
  }
  if (!SAFE_ZIP_ENTRY_NAME.test(entryName)) {
    throw new Error(`ZIP entry name does not match the allowed pattern: ${entryName}`);
  }
}

export interface ExportInput {
  artifactFileName: string;
  artifactBytes: Uint8Array;
  evidence: EvidencePackage;
  readmeContent: string;
}

export interface ManifestEntry {
  path: string;
  sha256: string;
  sizeBytes: number;
}

export interface ExportManifest {
  schemaVersion: "1.0.0";
  artifactId: string;
  createdAt: string;
  files: ManifestEntry[];
}

export interface ExportResult {
  zipPath: string;
  manifest: ExportManifest;
}

/**
 * Writes a reproducible repair-artifact ZIP package (artifact/, evidence.json, manifest.json,
 * README.md, checksums.txt). Writes to a hidden temp name inside `outDir` first and only renames
 * it into place once the archive is fully written -- a crash mid-write never leaves a partial
 * package visible under its real name.
 */
export async function exportRepairPackage(
  outDir: string,
  packageBaseName: string,
  input: ExportInput,
): Promise<ExportResult> {
  const artifactEntryName = `artifact/${input.artifactFileName}`;
  assertSafeZipEntryName(artifactEntryName);
  assertSafeZipEntryName("evidence.json");
  assertSafeZipEntryName("manifest.json");
  assertSafeZipEntryName("README.md");
  assertSafeZipEntryName("checksums.txt");

  const evidenceBytes = new TextEncoder().encode(`${JSON.stringify(input.evidence, null, 2)}\n`);
  const readmeBytes = new TextEncoder().encode(input.readmeContent);

  const manifestEntries: ManifestEntry[] = [
    { path: artifactEntryName, sha256: sha256Hex(input.artifactBytes), sizeBytes: input.artifactBytes.byteLength },
    { path: "evidence.json", sha256: sha256Hex(evidenceBytes), sizeBytes: evidenceBytes.byteLength },
    { path: "README.md", sha256: sha256Hex(readmeBytes), sizeBytes: readmeBytes.byteLength },
  ];

  const manifest: ExportManifest = {
    schemaVersion: "1.0.0",
    artifactId: input.evidence.artifactId,
    createdAt: input.evidence.createdAt,
    files: manifestEntries,
  };
  const manifestBytes = new TextEncoder().encode(`${JSON.stringify(manifest, null, 2)}\n`);

  const checksumLines = [...manifestEntries, { path: "manifest.json", sha256: sha256Hex(manifestBytes), sizeBytes: manifestBytes.byteLength }]
    .map((entry) => `${entry.sha256}  ${entry.path}`)
    .join("\n");
  const checksumBytes = new TextEncoder().encode(`${checksumLines}\n`);

  const zip = new AdmZip();
  zip.addFile(artifactEntryName, Buffer.from(input.artifactBytes));
  zip.addFile("evidence.json", Buffer.from(evidenceBytes));
  zip.addFile("manifest.json", Buffer.from(manifestBytes));
  zip.addFile("README.md", Buffer.from(readmeBytes));
  zip.addFile("checksums.txt", Buffer.from(checksumBytes));

  await mkdir(outDir, { recursive: true });
  const finalZipPath = path.join(outDir, `${packageBaseName}.zip`);
  const tempZipPath = path.join(outDir, `.tmp-${packageBaseName}-${randomUUID()}.zip`);

  try {
    await zip.writeZipPromise(tempZipPath);
    await rename(tempZipPath, finalZipPath);
  } catch (error) {
    await rm(tempZipPath, { force: true });
    throw error;
  }

  return { zipPath: finalZipPath, manifest };
}

export interface ReadBackResult {
  artifactBytes: Uint8Array;
  evidence: unknown;
}

/**
 * Re-opens an exported package from disk and returns the raw bytes exactly as stored, so the
 * independent verifier can recompute hashes over what was actually written rather than over the
 * in-memory values the exporter happened to have a moment earlier.
 */
export function readArtifactAndEvidenceFromZip(zipPath: string, artifactFileName: string): ReadBackResult {
  const zip = new AdmZip(zipPath);
  const artifactEntry = zip.getEntry(`artifact/${artifactFileName}`);
  const evidenceEntry = zip.getEntry("evidence.json");
  if (!artifactEntry || !evidenceEntry) {
    throw new Error("exported package is missing required entries (artifact/ or evidence.json)");
  }
  const artifactBytes = new Uint8Array(artifactEntry.getData());
  const evidence = JSON.parse(evidenceEntry.getData().toString("utf-8"));
  return { artifactBytes, evidence };
}
