import { z } from "zod";

export const EVIDENCE_SCHEMA_VERSION = "1.0.0";

const VerificationStatusSchema = z.enum(["passed", "failed", "blocked", "not_verified", "skipped"]);

const VerificationLevelSchema = z.enum([
  "L0_input_screened",
  "L1_static_validated",
  "L2_sandbox_executed",
  "L3_state_transition_verified",
  "L4_package_verified",
  "none",
]);

const VerificationCheckSchema = z.object({
  name: z.string().min(1),
  status: VerificationStatusSchema,
  exitCode: z.number().int().nullable(),
  expectedExitCode: z.number().int().optional(),
  durationMs: z.number().nonnegative().optional(),
  stdoutExcerpt: z.string().optional(),
  stderrExcerpt: z.string().optional(),
  details: z.record(z.string(), z.unknown()).optional(),
});

const Sha256HexSchema = z.string().regex(/^[0-9a-f]{64}$/, "expected a lowercase hex-encoded SHA-256 digest");

/**
 * Versioned evidence.json schema. Every field here must be populated from something that was
 * actually observed by the policy engine, the sandbox runner, or verifyRedGreen -- this schema
 * intentionally has no optional "trust me" fields that could be filled with a placeholder.
 */
export const EvidenceSchema = z.object({
  schemaVersion: z.literal(EVIDENCE_SCHEMA_VERSION),
  artifactId: z.string().min(1),
  createdAt: z.string().datetime(),
  artifact: z.object({
    fileName: z.string().min(1),
    format: z.enum(["cli", "html", "extension"]),
    sha256: Sha256HexSchema,
    sizeBytes: z.number().int().nonnegative(),
  }),
  source: z.object({
    kind: z.literal("sanitized-log"),
    sha256: Sha256HexSchema,
    rawInputStored: z.literal(false),
  }),
  environment: z.object({
    os: z.enum(["linux", "windows", "macos"]),
    sandbox: z.literal("docker"),
    sandboxImage: z.string().min(1),
    network: z.literal("disabled"),
  }),
  policy: z.object({
    version: z.string().min(1),
    input: VerificationStatusSchema,
    generatedOutput: VerificationStatusSchema,
    package: VerificationStatusSchema,
    findings: z.array(
      z.object({
        ruleId: z.string().min(1),
        severity: z.enum(["info", "warning", "block"]),
        message: z.string().min(1),
        location: z.string().optional(),
      }),
    ),
  }),
  verification: z.object({
    status: z.enum(["passed", "failed", "blocked", "not_verified"]),
    level: VerificationLevelSchema,
    checks: z.array(VerificationCheckSchema),
  }),
  provenance: z.object({
    forgeVersion: z.string().min(1),
    templateVersion: z.string().min(1),
    modelProvider: z.string().min(1),
    modelVersion: z.string().nullable(),
  }),
  /** Absent for evidence that was never signed (e.g. older records, or unit tests that build
   * evidence directly without going through the CLI's signing step). Present whenever
   * signEvidence() ran -- a consumer that was handed a trusted public key out of band can then
   * require and check it instead of only trusting the file's own claims. */
  proof: z
    .object({
      keyId: z.string().min(1),
      signature: z.string().min(1),
    })
    .optional(),
  /** Best-effort, optional: absent whenever the TSA was unreachable, timed out, rejected the
   * request, or returned a response that didn't bind to this exact content -- absence is never a
   * failure, see rfc3161-timestamp.ts. Present only once a real external timestamping authority
   * has actually confirmed this content, never a caller-supplied claim. */
  rfc3161_timestamp: z
    .object({
      schema_version: z.literal("rfc3161-timestamp@1.0"),
      tsa_url: z.string().min(1),
      timestamped_sha256: Sha256HexSchema,
      gen_time: z.string().min(1),
      token_der_base64: z.string().min(1),
    })
    .optional(),
});

export type EvidencePackage = z.infer<typeof EvidenceSchema>;
