export type VerificationStatus =
  | "passed"
  | "failed"
  | "blocked"
  | "not_verified"
  | "skipped";

export type VerificationLevel =
  | "L0_input_screened"
  | "L1_static_validated"
  | "L2_sandbox_executed"
  | "L3_state_transition_verified"
  | "L4_package_verified"
  | "none";

export interface VerificationCheck {
  name: string;
  status: VerificationStatus;
  exitCode: number | null;
  expectedExitCode?: number;
  durationMs?: number;
  stdoutExcerpt?: string;
  stderrExcerpt?: string;
  details?: Record<string, unknown>;
}

export interface VerificationSummary {
  status: Exclude<VerificationStatus, "skipped">;
  level: VerificationLevel;
  checks: VerificationCheck[];
}
