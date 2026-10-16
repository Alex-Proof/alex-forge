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
