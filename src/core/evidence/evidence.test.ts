import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { buildEvidence } from "./evidence.js";
import { EvidenceSchema } from "./schema.js";

const PASSED_VERIFICATION = {
  status: "passed" as const,
  level: "L3_state_transition_verified" as const,
  checks: [{ name: "verify", status: "passed" as const, exitCode: 0 }],
};

function baseInput(overrides: Partial<Parameters<typeof buildEvidence>[0]> = {}) {
  return {
    artifactId: "forge-repair-test-001",
    artifactFileName: "repair.sh",
    artifactFormat: "cli" as const,
    artifactContent: new TextEncoder().encode("#!/bin/sh\necho hello\n"),
    sourceLogRedactedText: "service exited with code 1",
    targetOS: "linux" as const,
    sandboxImage: "alpine:3.20",
    verification: PASSED_VERIFICATION,
    forgeVersion: "0.0.1",
    templateVersion: "1.0.0",
    ...overrides,
  };
}

describe("buildEvidence", () => {
  it("produces evidence that validates against its own schema", () => {
    const evidence = buildEvidence(baseInput());
    expect(() => EvidenceSchema.parse(evidence)).not.toThrow();
  });

  it("computes the artifact hash over the actual artifact bytes", () => {
    const input = baseInput();
    const evidence = buildEvidence(input);
    const expectedHash = createHash("sha256").update(input.artifactContent).digest("hex");
    expect(evidence.artifact.sha256).toBe(expectedHash);
    expect(evidence.artifact.sizeBytes).toBe(input.artifactContent.byteLength);
  });

  it("transcribes the verification summary rather than re-deciding it", () => {
    const evidence = buildEvidence(baseInput());
    expect(evidence.verification.status).toBe("passed");
    expect(evidence.verification.level).toBe("L3_state_transition_verified");
  });

  it("marks the generated-output policy as blocked when the artifact content contains a secret", () => {
    const evidence = buildEvidence(
      baseInput({
        artifactContent: new TextEncoder().encode(
          "#!/bin/sh\n# AKIAABCDEFGHIJKLMNOP\necho leaked\n",
        ),
      }),
    );
    expect(evidence.policy.generatedOutput).toBe("blocked");
    expect(evidence.policy.findings.some((f) => f.severity === "block")).toBe(true);
  });

  it("marks the input policy as blocked when the source log contains a private key", () => {
    const evidence = buildEvidence(
      baseInput({
        sourceLogRedactedText: "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----",
      }),
    );
    expect(evidence.policy.input).toBe("blocked");
  });

  it("never stores the raw source log, only its hash", () => {
    const evidence = buildEvidence(baseInput());
    expect(evidence.source.rawInputStored).toBe(false);
    expect(evidence.source.sha256).toMatch(/^[0-9a-f]{64}$/);
  });
});
