/**
 * CLI-side caps on event payload strings, applied just before upload.
 *
 * The cloud ingest route rejects the WHOLE session when any string in an
 * event payload is over its limit (field-too-long), so one huge command
 * output or one long message would stop every event of that session from
 * syncing. Truncating here, with a visible marker, keeps the session
 * uploading.
 *
 * Every number sits below the server's limit for the same field, marker
 * included. The server side is apps/web/lib/govern/contract.ts on
 * agentreel/web main (55dac0a, PR #38):
 *   INGEST_LIMITS (lines 1625-1645): MAX_FREE_TEXT_LENGTH 10_000 (line 1643),
 *     MAX_PAYLOAD_TEXT_LENGTH 100_000 (line 1644), MAX_REASON_LENGTH 1_000.
 *   INGEST_COMMON_NESTED_STRING_CAPS (lines 3235-3298): reason (3289), and
 *     title, label, rule_name, summary, detail, description, rationale and
 *     message at MAX_FREE_TEXT_LENGTH (3290-3297).
 *   INGEST_EVENT_PAYLOAD_STRING_CAPS (lines 3300-3308): prompt, output, patch,
 *     stdout, stderr and contents at MAX_PAYLOAD_TEXT_LENGTH.
 *   hasValidIngestStringLengths (lines 3324-3352): a string under any other
 *     key, and every array element, is capped at MAX_FREE_TEXT_LENGTH (3335).
 *
 * INGEST_FIELD_LIMITS is the single place the numbers live, so it can later be
 * checked against, or built from, the exported INGEST_LIMITS. Keys are field
 * names. A field is capped wherever it appears, at any depth, the same way
 * the server checks by the key a string sits directly under.
 */
const PAYLOAD_TEXT_CAP = 64_000; // server: 100_000
const FREE_TEXT_CAP = 9_500; // server: 10_000
const REASON_CAP = 950; // server: 1_000

export const INGEST_FIELD_LIMITS: Readonly<Record<string, number>> = {
  prompt: PAYLOAD_TEXT_CAP,
  output: PAYLOAD_TEXT_CAP,
  patch: PAYLOAD_TEXT_CAP,
  stdout: PAYLOAD_TEXT_CAP,
  stderr: PAYLOAD_TEXT_CAP,
  contents: PAYLOAD_TEXT_CAP,
  title: FREE_TEXT_CAP,
  label: FREE_TEXT_CAP,
  rule_name: FREE_TEXT_CAP,
  summary: FREE_TEXT_CAP,
  detail: FREE_TEXT_CAP,
  description: FREE_TEXT_CAP,
  rationale: FREE_TEXT_CAP,
  message: FREE_TEXT_CAP,
  reason: REASON_CAP,
};

/**
 * Cap for a string under any key that is not in INGEST_FIELD_LIMITS (the
 * server treats those as free text too), and for array elements.
 */
export const DEFAULT_FREE_TEXT_LIMIT = FREE_TEXT_CAP;

/**
 * Short identifier, version and path keys that the server limits to 4,096
 * characters or fewer (ids, tool and model names, shas, branches, repo URLs,
 * cwd and file paths). They are never truncated: cutting an id or a path
 * would change what it means. A value over its server cap here is a real
 * data problem, not oversized text.
 */
export const UNTRUNCATED_IDENTIFIER_KEYS: ReadonlySet<string> = new Set([
  "id", "session_id", "finding_id", "rule_id", "rule", "approval_id",
  "decision_id", "tool_use_id", "generation_id", "org_id", "orgId",
  "workspace_id", "workspaceId", "tool", "tool_name", "model", "type",
  "cursor_hook", "source", "composer_mode", "mcp_server_name", "category",
  "severity", "action", "status", "final_status", "failure_type",
  "agent_version", "client_version", "version", "os_user", "platform",
  "agentreel_version", "hostname_mode", "head_start", "head_end",
  "timestamp", "branch", "branch_start", "branch_end", "machine", "hostname",
  "user_name", "user_email", "root", "repo", "remote_url", "mcp_server_url",
  "cwd", "file_path", "path", "target_file", "working_directory",
]);

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
  // A cap too small to hold the marker: plain cut, never longer than the cap.
  if (marker.length >= cap) return cutWithoutSplittingPair(value, cap);
  let keep = cap - marker.length;
  if (
    keep > 0 &&
    isHighSurrogate(value.charCodeAt(keep - 1)) &&
    isLowSurrogate(value.charCodeAt(keep))
  ) {
    keep -= 1;
  }
  return value.slice(0, keep) + marker;
}

function cutWithoutSplittingPair(value: string, keep: number): string {
  if (
    keep > 0 &&
    isHighSurrogate(value.charCodeAt(keep - 1)) &&
    isLowSurrogate(value.charCodeAt(keep))
  ) {
    keep -= 1;
  }
  return value.slice(0, keep);
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
 * Walks a parsed payload and truncates every string to the cap for the key it
 * sits directly under: INGEST_FIELD_LIMITS for known fields, nothing for
 * UNTRUNCATED_IDENTIFIER_KEYS, DEFAULT_FREE_TEXT_LIMIT for any other key and
 * for array elements. Copy on write: returns the same object when nothing is
 * over a limit, and never mutates its input.
 */
export function capPayloadFields(
  payload: unknown,
  limits: Readonly<Record<string, number>> = INGEST_FIELD_LIMITS,
  depth = 0,
  key?: string,
): unknown {
  if (typeof payload === "string") {
    if (key !== undefined && Object.hasOwn(limits, key)) {
      return truncateField(payload, limits[key]!);
    }
    if (key !== undefined && UNTRUNCATED_IDENTIFIER_KEYS.has(key)) return payload;
    return truncateField(payload, DEFAULT_FREE_TEXT_LIMIT);
  }
  if (payload === null || typeof payload !== "object") return payload;
  if (depth > MAX_WALK_DEPTH) return payload;

  if (Array.isArray(payload)) {
    let out: unknown[] | null = null;
    for (let i = 0; i < payload.length; i++) {
      const next = capPayloadFields(payload[i], limits, depth + 1, undefined);
      if (next !== payload[i]) {
        out ??= payload.slice();
        out[i] = next;
      }
    }
    return out ?? payload;
  }

  const obj = payload as Record<string, unknown>;
  let out: Record<string, unknown> | null = null;
  for (const k of Object.keys(obj)) {
    const value = obj[k];
    const next = capPayloadFields(value, limits, depth + 1, k);
    if (next !== value) {
      out ??= { ...obj };
      setOwn(out, k, next);
    }
  }
  return out ?? payload;
}
