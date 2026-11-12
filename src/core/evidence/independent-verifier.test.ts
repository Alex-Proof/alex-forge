import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { independentlyVerify } from "./independent-verifier.js";
import { buildEvidence } from "./evidence.js";

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

  it("recomputes the hash independently rather than importing the builder's hashing", () => {
    // Sanity cross-check: our own sha256 of the same bytes must equal what the verifier accepts.
    const expectedHash = createHash("sha256").update(artifactContent).digest("hex");
    const evidence = validEvidence();
    expect(evidence.artifact.sha256).toBe(expectedHash);
    expect(independentlyVerify(evidence, artifactContent).verified).toBe(true);
  });
});
