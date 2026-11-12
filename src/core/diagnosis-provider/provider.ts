/**
 * The "austauschbares Provider-Interface" the blueprint calls for (section 4, section 14.1,
 * section 20: "Modell ist optional; Fallback ist verpflichtend"). A model response is NEVER
 * trusted more than the deterministic fallback: it is treated as the exact same kind of
 * untrusted candidate object, and goes through the exact same `validateDiagnosis` gate in
 * src/modes/repair/diagnose.ts before anything is generated from it. A provider may propose; it
 * never gets to assert that an action is legitimate just by naming it, and it never produces or
 * asserts a verification result -- that stays entirely Forge's own job, after generation.
 */
export interface DiagnosisProviderResponse {
  /** Untrusted -- must still pass validateDiagnosis before anything is generated from it. */
  candidate: unknown;
  /** The exact model identifier that produced this response, for honest evidence provenance. */
  modelVersion: string;
}

export interface DiagnosisProvider {
  /** A short, stable name for evidence provenance (e.g. "openai"). */
  readonly name: string;
  /**
   * Proposes a diagnosis for an already-redacted, policy-checked log. Must never throw: any
   * network, auth, timeout, or parse failure resolves to `null` so the caller falls back to the
   * deterministic diagnosis -- a missing/broken model is exactly the case blueprint section 20
   * requires a mandatory fallback for.
   */
  propose(redactedLogText: string, targetOS: "linux" | "windows" | "macos"): Promise<DiagnosisProviderResponse | null>;
}
