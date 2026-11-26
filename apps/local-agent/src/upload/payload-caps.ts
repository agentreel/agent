/**
 * CLI-side caps on event payload fields, applied just before upload.
 *
 * The cloud ingest route rejects the WHOLE session when any string field in
 * an event payload is over its limit (field-too-long), so one huge command
 * output would stop every event of that session from syncing. Truncating the
 * known big fields here, with a visible marker, keeps the session uploading.
 *
 * INGEST_FIELD_LIMITS is the single place the numbers live. It is meant to be
 * replaced by, or checked against, the limits map the web contract exports
 * (apps/web lib/govern/contract.ts) once that lands. Keys are payload field
 * names. A field is capped wherever it appears in the payload, at any depth,
 * the same way the server checks by key name at any depth.
 */
export const INGEST_FIELD_LIMITS: Readonly<Record<string, number>> = {
  prompt: 64_000,
  output: 64_000,
  patch: 64_000,
  stdout: 64_000,
  stderr: 64_000,
  contents: 64_000,
};

/** Deeper than the server accepts (32), so anything this deep is rejected anyway. */
const MAX_WALK_DEPTH = 64;

export function truncationMarker(originalLength: number): string {
  return `\n[agentreel: truncated, original length ${originalLength} chars]`;
}

function isHighSurrogate(code: number): boolean {
  return code >= 0xd800 && code <= 0xdbff;
}

function isLowSurrogate(code: number): boolean {
  return code >= 0xdc00 && code <= 0xdfff;
}

/**
 * Returns `value` unchanged when it is at most `cap` UTF-16 code units (the
 * unit the server counts with .length). Otherwise returns a prefix plus a
 * marker that carries the original length, and the whole result is at most
 * `cap` code units. The cut never lands between the two halves of a
 * surrogate pair, so the prefix never ends in a lone high surrogate that the
 * cut itself created.
 */
export function truncateField(value: string, cap: number): string {
  if (value.length <= cap) return value;
  const marker = truncationMarker(value.length);
  let keep = Math.max(0, cap - marker.length);
  if (
    keep > 0 &&
    isHighSurrogate(value.charCodeAt(keep - 1)) &&
    isLowSurrogate(value.charCodeAt(keep))
  ) {
    keep -= 1;
  }
  return value.slice(0, keep) + marker;
}

function setOwn(target: Record<string, unknown>, key: string, value: unknown): void {
  // defineProperty, not assignment: a JSON payload can carry an own
  // "__proto__" key, and assigning to it would change the prototype instead.
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
}

/**
 * Walks a parsed payload and truncates every string stored under a key in
 * `limits`. Copy on write: returns the same object when nothing is over a
 * limit, and never mutates its input.
 */
export function capPayloadFields(
  payload: unknown,
  limits: Readonly<Record<string, number>> = INGEST_FIELD_LIMITS,
  depth = 0,
): unknown {
  if (payload === null || typeof payload !== "object") return payload;
  if (depth > MAX_WALK_DEPTH) return payload;

  if (Array.isArray(payload)) {
    let out: unknown[] | null = null;
    for (let i = 0; i < payload.length; i++) {
      const next = capPayloadFields(payload[i], limits, depth + 1);
      if (next !== payload[i]) {
        out ??= payload.slice();
        out[i] = next;
      }
    }
    return out ?? payload;
  }

  const obj = payload as Record<string, unknown>;
  let out: Record<string, unknown> | null = null;
  for (const key of Object.keys(obj)) {
    const value = obj[key];
    let next: unknown;
    if (typeof value === "string") {
      const cap = Object.hasOwn(limits, key) ? limits[key]! : undefined;
      next = cap === undefined ? value : truncateField(value, cap);
    } else {
      next = capPayloadFields(value, limits, depth + 1);
    }
    if (next !== value) {
      out ??= { ...obj };
      setOwn(out, key, next);
    }
  }
  return out ?? payload;
}
