/**
 * Minimal, deterministic JSON canonicalization (RFC-8785/JCS-lite) for hashing and signing
 * evidence payloads: object keys sorted, no whitespace. Written independently for Forge rather
 * than imported from anywhere else -- a canonicalizer shared between the thing that signs and
 * the thing that verifies would let one bug blind both sides at once.
 */
export function canonicalJson(value: unknown): string {
  return stringify(value);
}

function stringify(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "number" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(stringify).join(",") + "]";
  if (typeof value === "object") {
    const keys = Object.keys(value as Record<string, unknown>).sort();
    const entries = keys.map((k) => JSON.stringify(k) + ":" + stringify((value as Record<string, unknown>)[k]));
    return "{" + entries.join(",") + "}";
  }
  throw new Error(`canonicalJson: unsupported value type ${typeof value}`);
}
