export interface RepairDiagnosis {
  issueTitle: string;
  rootCause: string;
  targetOS: "linux" | "windows" | "macos";
  checkPlan: string[];
  fixPlan: Array<{
    actionId: string;
    parameters: Record<string, string | number | boolean>;
  }>;
  preconditions: string[];
  riskLevel: "low" | "medium" | "high";
  needsHumanApproval: boolean;
}

/**
 * Diagnosis shape for the "diff" format (static-finding repairs, e.g. serviceAudit's dangling
 * imports/cycles/dormant files -- see docs/ASSUMPTIONS.md A-026 in alex-core). Deliberately NOT an
 * extension of RepairDiagnosis: there is no registered actionId for an arbitrary source-code diff,
 * and there never will be -- a diff is not a capability this codebase can allowlist in advance the
 * way free-tcp-port/clear-stale-pidfile are. needsHumanApproval is fixed to `true` by the type
 * itself (not a field a model response sets) precisely because this format has no action
 * allowlist to constrain it; see admitToCatalog()'s matching, non-negotiable guard.
 */
export interface StaticFixDiagnosis {
  issueTitle: string;
  rootCause: string;
  /** Free-form label identifying the kind of static finding (e.g. "dangling-import"). Not an
   *  actionId -- it never selects registered fix logic, only describes the finding for evidence. */
  findingType: string;
  targetFiles: string[];
  /** Unified diff text. Applied only via `git apply --check` first; never trusted as already-safe. */
  proposedDiff: string;
  /** Caller-supplied command that must fail before the diff and pass after (red/green). Forge
   *  never invents this command -- an invented check would make the red/green proof meaningless. */
  verificationCommand: string;
  riskLevel: "low" | "medium" | "high";
  readonly needsHumanApproval: true;
}
