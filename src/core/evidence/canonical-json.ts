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
    const obj = value as Record<string, unknown>;
    // A key whose value is `undefined` must be omitted entirely here, matching what
    // JSON.stringify does to that same object (e.g. on the way into evidence.json in the
    // exported ZIP): an object round-tripped through real JSON ends up with that key missing,
    // not present-with-null. If this function instead rendered it as "null" (as the top-level
    // null/undefined check above does for a *value*), re-signing after a JSON round-trip would
    // canonicalize differently from the original in-memory object and break every signature.
    const keys = Object.keys(obj)
      .filter((k) => obj[k] !== undefined)
      .sort();
    const entries = keys.map((k) => JSON.stringify(k) + ":" + stringify(obj[k]));
    return "{" + entries.join(",") + "}";
  }
  throw new Error(`canonicalJson: unsupported value type ${typeof value}`);
}
