import { PATTERNS, SENSITIVE_KEY_RE } from "./patterns.js";

/** Run all redaction patterns against a string. Idempotent. */
export function scrubString(input: string): string {
  if (!input) return input;
  let s = input;
  for (const rule of PATTERNS) {
    if (typeof rule.replacement === "function") {
      s = s.replace(rule.re, rule.replacement);
    } else {
      s = s.replace(rule.re, rule.replacement);
    }
  }
  return s;
}

/**
 * Recursively redact a JSON-shaped value. Strings get pattern-scrubbed;
 * object properties whose KEY name looks sensitive (`apiKey`, `password`,
 * etc.) have their entire string value replaced — that catches arbitrary
 * secrets that don't match any provider pattern.
 *
 * Cycle-safe via a WeakSet seen.
 */
export function scrubAny<T>(value: T, seen: WeakSet<object> = new WeakSet()): T {
  if (value == null) return value;
  if (typeof value === "string") return scrubString(value) as T;
  if (typeof value !== "object") return value;
  if (seen.has(value as object)) return value;
  seen.add(value as object);

  if (Array.isArray(value)) {
    return value.map((v) => scrubAny(v, seen)) as T;
  }

  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (SENSITIVE_KEY_RE.test(k) && typeof v === "string" && v.length >= 4) {
      out[k] = "[REDACTED:by-key-name]";
    } else {
      out[k] = scrubAny(v, seen);
    }
  }
  return out as T;
}
