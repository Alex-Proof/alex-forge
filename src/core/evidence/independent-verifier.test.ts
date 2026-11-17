import { createHash } from "node:crypto";
import { rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { independentlyVerify } from "./independent-verifier.js";
import { buildEvidence, signEvidence } from "./evidence.js";
import { loadOrCreateKeypair } from "./keystore.js";
import * as rfc3161 from "./rfc3161-timestamp.js";
import type { Rfc3161Timestamp } from "./rfc3161-timestamp.js";

const ARBITRARY_TIMESTAMP: Rfc3161Timestamp = {
  schema_version: "rfc3161-timestamp@1.0",
  tsa_url: "https://freetsa.org/tsr",
  timestamped_sha256: "0".repeat(64),
  gen_time: "2026-09-05T09:32:37.000Z",
  token_der_base64: "dGVzdA==",
};

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

function validEvidence() {
  return buildEvidence({
    artifactId: "forge-repair-test-002",
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
}

let tempDirs: string[] = [];
function tempKeystoreDir(): string {
  const dir = path.join(os.tmpdir(), `forge-verifier-test-${Math.random().toString(36).slice(2)}`);
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempDirs.map((dir) => rm(dir, { recursive: true, force: true })));
  tempDirs = [];
});

describe("independentlyVerify", () => {
  it("verifies a genuinely passing, internally consistent evidence package", () => {
    const result = independentlyVerify(validEvidence(), artifactContent);
    expect(result.verified).toBe(true);
    expect(result.reasons).toEqual([]);
  });

  it("rejects evidence whose claimed artifact hash does not match the actual bytes", () => {
    const evidence = validEvidence();
    const tampered = { ...evidence, artifact: { ...evidence.artifact, sha256: "0".repeat(64) } };
    const result = independentlyVerify(tampered, artifactContent);
    expect(result.verified).toBe(false);
    expect(result.reasons.some((r) => r.includes("hash mismatch"))).toBe(true);
  });

  it("rejects evidence when the artifact bytes it is checked against were swapped out", () => {
    const evidence = validEvidence();
    const differentBytes = new TextEncoder().encode("#!/bin/sh\necho a different artifact entirely\n");
    const result = independentlyVerify(evidence, differentBytes);
    expect(result.verified).toBe(false);
  });

  it(
    "does not trust a claimed passed status when the underlying checks array disagrees " +
      "(the core reason an independent verifier exists)",
    () => {
      const evidence = validEvidence();
      const forged = {
        ...evidence,
        verification: {
          ...evidence.verification,
          status: "passed", // claims success...
          checks: evidence.verification.checks.map((c) =>
            c.name === "postcondition_oracle" ? { ...c, status: "failed" } : c,
          ), // ...but the independent oracle's own check in the raw array actually failed.
        },
      };
      const result = independentlyVerify(forged, artifactContent);
      expect(result.verified).toBe(false);
      expect(result.reasons.some((r) => r.includes("postcondition_oracle"))).toBe(true);
    },
  );

  it("rejects evidence missing a mandatory verification check entirely", () => {
    const evidence = validEvidence();
    const withMissingCheck = {
      ...evidence,
      verification: {
        ...evidence.verification,
        checks: evidence.verification.checks.filter((c) => c.name !== "verify"),
      },
    };
    const result = independentlyVerify(withMissingCheck, artifactContent);
    expect(result.verified).toBe(false);
    expect(result.reasons.some((r) => r.includes("missing mandatory verification check: verify"))).toBe(true);
  });

  it("rejects evidence carrying an unresolved block-severity policy finding", () => {
    const evidence = validEvidence();
    const withBlockFinding = {
      ...evidence,
      policy: {
        ...evidence.policy,
        findings: [...evidence.policy.findings, { ruleId: "secret-aws-access-key-id", severity: "block", message: "x" }],
      },
    };
    const result = independentlyVerify(withBlockFinding, artifactContent);
    expect(result.verified).toBe(false);
  });

  it("rejects malformed evidence that does not even match the schema", () => {
    const result = independentlyVerify({ nonsense: true }, artifactContent);
    expect(result.verified).toBe(false);
    expect(result.evidence).toBeUndefined();
  });

  it("accepts an L2_sandbox_executed result (e.g. HTML's browser functional test) when every recorded check passed", () => {
    const evidence = buildEvidence({
      artifactId: "forge-repair-html-test-001",
      artifactFileName: "repair.html",
      artifactFormat: "html",
      artifactContent: new TextEncoder().encode("<!doctype html><html><body>ok</body></html>"),
      sourceLogRedactedText: "service exited with code 1",
      targetOS: "linux",
      sandboxImage: "n/a",
      verification: {
        status: "passed",
        level: "L2_sandbox_executed",
        checks: [
          { name: "static_html_policy", status: "passed", exitCode: null },
          { name: "dom_xss_injection_does_not_execute", status: "passed", exitCode: null },
        ],
      },
      forgeVersion: "0.0.1",
      templateVersion: "1.0.0",
    });
    const result = independentlyVerify(
      evidence,
      new TextEncoder().encode("<!doctype html><html><body>ok</body></html>"),
    );
    expect(result.verified).toBe(true);
  });

  it("rejects an L2_sandbox_executed claim with no recorded checks at all", () => {
    const evidence = buildEvidence({
      artifactId: "forge-repair-html-test-002",
      artifactFileName: "repair.html",
      artifactFormat: "html",
      artifactContent: new TextEncoder().encode("<!doctype html><html><body>ok</body></html>"),
      sourceLogRedactedText: "service exited with code 1",
      targetOS: "linux",
      sandboxImage: "n/a",
      verification: { status: "passed", level: "L2_sandbox_executed", checks: [] },
      forgeVersion: "0.0.1",
      templateVersion: "1.0.0",
    });
    const result = independentlyVerify(
      evidence,
      new TextEncoder().encode("<!doctype html><html><body>ok</body></html>"),
    );
    expect(result.verified).toBe(false);
    expect(result.reasons.some((r) => r.includes("no checks were recorded"))).toBe(true);
  });

  it("rejects a verification level insufficient for catalog admission (e.g. only static validation)", () => {
    const evidence = buildEvidence({
      artifactId: "forge-repair-html-test-003",
      artifactFileName: "repair.html",
      artifactFormat: "html",
      artifactContent: new TextEncoder().encode("<!doctype html><html><body>ok</body></html>"),
      sourceLogRedactedText: "service exited with code 1",
      targetOS: "linux",
      sandboxImage: "n/a",
      verification: {
        status: "failed",
        level: "L1_static_validated",
        checks: [{ name: "static_html_policy", status: "passed", exitCode: null }],
      },
      forgeVersion: "0.0.1",
      templateVersion: "1.0.0",
    });
    const result = independentlyVerify(
      evidence,
      new TextEncoder().encode("<!doctype html><html><body>ok</body></html>"),
    );
    expect(result.verified).toBe(false);
    expect(result.reasons.some((r) => r.includes("not sufficient for catalog admission"))).toBe(true);
  });

  it("recomputes the hash independently rather than importing the builder's hashing", () => {
    // Sanity cross-check: our own sha256 of the same bytes must equal what the verifier accepts.
    const expectedHash = createHash("sha256").update(artifactContent).digest("hex");
    const evidence = validEvidence();
    expect(evidence.artifact.sha256).toBe(expectedHash);
    expect(independentlyVerify(evidence, artifactContent).verified).toBe(true);
  });

  it("without a trusted public key, accepts unsigned evidence exactly as before (backward compatible)", () => {
    const result = independentlyVerify(validEvidence(), artifactContent);
    expect(result.verified).toBe(true);
  });

  it("with a trusted public key, accepts evidence whose signature verifies against it", () => {
    const keypair = loadOrCreateKeypair(tempKeystoreDir());
    const signed = signEvidence(validEvidence(), keypair);
    const result = independentlyVerify(signed, artifactContent, keypair.publicKeyPem);
    expect(result.verified).toBe(true);
  });

  it("with a trusted public key, rejects unsigned evidence even if otherwise valid", () => {
    const keypair = loadOrCreateKeypair(tempKeystoreDir());
    const result = independentlyVerify(validEvidence(), artifactContent, keypair.publicKeyPem);
    expect(result.verified).toBe(false);
    expect(result.reasons.some((r) => r.includes("no proof"))).toBe(true);
  });

  it("with a trusted public key, rejects evidence signed by a different keypair", () => {
    const realKeypair = loadOrCreateKeypair(tempKeystoreDir());
    const impostorKeypair = loadOrCreateKeypair(tempKeystoreDir());
    const signedByImpostor = signEvidence(validEvidence(), impostorKeypair);
    const result = independentlyVerify(signedByImpostor, artifactContent, realKeypair.publicKeyPem);
    expect(result.verified).toBe(false);
    expect(result.reasons.some((r) => r.includes("does not verify"))).toBe(true);
  });

  it("with a trusted public key, rejects evidence whose signed fields were edited after signing", () => {
    const keypair = loadOrCreateKeypair(tempKeystoreDir());
    const signed = signEvidence(validEvidence(), keypair);
    const tamperedAfterSigning = {
      ...signed,
      verification: { ...signed.verification, status: "passed" as const },
      artifact: { ...signed.artifact, sizeBytes: signed.artifact.sizeBytes + 1 },
    };
    const result = independentlyVerify(tamperedAfterSigning, artifactContent, keypair.publicKeyPem);
    expect(result.verified).toBe(false);
    expect(result.reasons.some((r) => r.includes("does not verify"))).toBe(true);
  });
});

describe("independentlyVerify -- rfc3161 timestamp is optional and best-effort", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("stays verified exactly as before when no timestamp is present (backward compatible)", () => {
    const result = independentlyVerify(validEvidence(), artifactContent);
    expect(result.verified).toBe(true);
    expect(result.reasons).toEqual([]);
  });

  it("stays verified when both the binding and TSA chain checks pass", () => {
    // The real cryptography (binding against a genuine FreeTSA capture, forgery detection, chain
    // verification against the pinned root) is exercised in rfc3161-timestamp.test.ts. Here we
    // only confirm independentlyVerify actually calls both checks and respects their result --
    // spying on the real exported functions rather than re-building a chain-valid token.
    const bindingSpy = vi.spyOn(rfc3161, "verifyRfc3161Binding").mockReturnValue({ ok: true });
    const chainSpy = vi.spyOn(rfc3161, "verifyRfc3161TsaChain").mockReturnValue({ ok: true });

    const evidence = { ...validEvidence(), rfc3161_timestamp: ARBITRARY_TIMESTAMP };
    const result = independentlyVerify(evidence, artifactContent);

    expect(result.verified).toBe(true);
    expect(bindingSpy).toHaveBeenCalledWith(evidence);
    expect(chainSpy).toHaveBeenCalledWith(ARBITRARY_TIMESTAMP);
  });

  it("fails when the binding check passes but the TSA chain check does not", () => {
    vi.spyOn(rfc3161, "verifyRfc3161Binding").mockReturnValue({ ok: true });
    vi.spyOn(rfc3161, "verifyRfc3161TsaChain").mockReturnValue({ ok: false, reason: "chain_untrusted" });

    const evidence = { ...validEvidence(), rfc3161_timestamp: ARBITRARY_TIMESTAMP };
    const result = independentlyVerify(evidence, artifactContent);

    expect(result.verified).toBe(false);
    expect(result.reasons.some((r) => r.includes("rfc3161 timestamp TSA chain check failed: chain_untrusted"))).toBe(true);
  });

  it("fails when the attached timestamp's content binding does not hold", () => {
    const evidence = validEvidence();
    const forgedTimestamp: Rfc3161Timestamp = {
      schema_version: "rfc3161-timestamp@1.0",
      tsa_url: "https://freetsa.org/tsr",
      timestamped_sha256: "0".repeat(64),
      gen_time: "2026-09-05T09:32:37.000Z",
      token_der_base64: "dGVzdA==",
    };
    const tampered = { ...evidence, rfc3161_timestamp: forgedTimestamp };
    const result = independentlyVerify(tampered, artifactContent);
    expect(result.verified).toBe(false);
    expect(result.reasons.some((r) => r.includes("rfc3161 timestamp binding check failed"))).toBe(true);
  });
});
