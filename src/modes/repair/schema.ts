import { z } from "zod";

/**
 * Generic structural schema for a RepairDiagnosis. This only checks shape and types; it does NOT
 * check that fixPlan actionIds are registered or that their parameters match the action's own
 * schema -- that allowlist check happens separately in `validateDiagnosis` (diagnose.ts) so a
 * model response can never add a new, unregistered capability just by matching this shape.
 */
export const RepairDiagnosisSchema = z.object({
  issueTitle: z.string().min(1).max(500),
  rootCause: z.string().min(1).max(2000),
  targetOS: z.enum(["linux", "windows", "macos"]),
  checkPlan: z.array(z.string().min(1).max(500)).max(50),
  fixPlan: z
    .array(
      z.object({
        actionId: z.string().min(1).max(200),
        parameters: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])),
      }),
    )
    .max(10),
  preconditions: z.array(z.string().min(1).max(500)).max(50),
  riskLevel: z.enum(["low", "medium", "high"]),
  needsHumanApproval: z.boolean(),
});

export type RepairDiagnosisInput = z.infer<typeof RepairDiagnosisSchema>;
