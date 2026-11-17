import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { main } from "./cli.js";
import { buildEvidence, signEvidence } from "./core/evidence/evidence.js";
import { loadOrCreateKeypair, type ForgeKeypair } from "./core/evidence/keystore.js";
import { exportRepairPackage } from "./core/export/zip-exporter.js";

const artifactContent = new TextEncoder().encode("#!/bin/sh\necho hello\n");

const ALL_MANDATORY_PASSED = [
  "precondition_oracle",
  "check_before_fix",
  "dry_run",
  "dry_run_oracle",
  "fix",
  "postcondition_oracle",
  "check_after_fix",
  "verify",
].map((name) => ({ name, status: "passed" as const, exitCode: 0 }));

let tempDirs: string[] = [];
async function tempDir(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "forge-verify-cli-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempDirs.map((dir) => rm(dir, { recursive: true, force: true })));
  tempDirs = [];
});

/** Builds a signed, exportable package and the trust-anchor PEM file a third party would get
 * alongside it -- exactly the two inputs `forge verify` is specified to need, nothing else. */
async function buildSignedPackage(workDir: string): Promise<{ zipPath: string; publicKeyPath: string; keypair: ForgeKeypair }> {
  const keystoreDir = path.join(workDir, "keystore");
  const keypair = loadOrCreateKeypair(keystoreDir);

  const unsignedEvidence = buildEvidence({
    artifactId: "forge-repair-test-verify-cli",
    artifactFileName: "repair.sh",
    artifactFormat: "cli",
    artifactContent,
    sourceLogRedactedText: "service exited with code 1",
    targetOS: "linux",
    sandboxImage: "alpine:3.20",
    verification: { status: "passed", level: "L3_state_transition_verified", checks: ALL_MANDATORY_PASSED },
    forgeVersion: "0.0.1",
    templateVersion: "1.0.0",
  });
  const evidence = signEvidence(unsignedEvidence, keypair);

  const { zipPath } = await exportRepairPackage(workDir, "forge-repair-test-verify-cli", {
    artifactFileName: "repair.sh",
    artifactBytes: artifactContent,
    evidence,
    readmeContent: "# test package\n",
  });

  const publicKeyPath = path.join(workDir, "forge-trust-anchor.pub.pem");
  await writeFile(publicKeyPath, keypair.publicKeyPem);

  return { zipPath, publicKeyPath, keypair };
}

describe("forge verify (CLI)", () => {
  it("exits 0 and reports verified:true for a genuine package checked against its real trust anchor", async () => {
    const workDir = await tempDir();
    const { zipPath, publicKeyPath } = await buildSignedPackage(workDir);

    const result = await main(["verify", zipPath, "--public-key", publicKeyPath, "--json"]);

    expect(result.exitCode).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({ verified: true });
  });

  it("exits 1 and names reasons when the public key does not match the signature", async () => {
    const workDir = await tempDir();
    const { zipPath } = await buildSignedPackage(workDir);
    const impostorKeypair = loadOrCreateKeypair(path.join(workDir, "impostor-keystore"));
    const impostorPublicKeyPath = path.join(workDir, "impostor.pub.pem");
    await writeFile(impostorPublicKeyPath, impostorKeypair.publicKeyPem);

    const result = await main(["verify", zipPath, "--public-key", impostorPublicKeyPath, "--json"]);

    expect(result.exitCode).toBe(1);
    const payload = JSON.parse(result.stdout);
    expect(payload.verified).toBe(false);
    expect(payload.reasons.some((reason: string) => reason.includes("signature"))).toBe(true);
  });

  it("exits 2 when the ZIP does not exist, without touching a private key or Docker", async () => {
    const workDir = await tempDir();
    const { publicKeyPath } = await buildSignedPackage(workDir);

    const result = await main(["verify", path.join(workDir, "does-not-exist.zip"), "--public-key", publicKeyPath]);

    expect(result.exitCode).toBe(2);
    expect(result.stderr).toMatch(/could not read package/);
  });

  it("exits 2 when --public-key is missing", async () => {
    const workDir = await tempDir();
    const { zipPath } = await buildSignedPackage(workDir);

    const result = await main(["verify", zipPath]);

    expect(result.exitCode).toBe(2);
    expect(result.stderr).toMatch(/missing required flag: --public-key/);
  });
});
