import { getMeta, setMeta } from "../db.js";
import { readConfig } from "../config.js";
import { IngestError, postIngest } from "./client.js";
import { MAX_BATCH_BYTES, MAX_BATCH_EVENTS, markUploaded, takePendingBatch } from "./queue.js";

export const META_LAST_SYNC_AT = "last_sync_at";
export const META_LAST_ERROR_AT = "last_error_at";
export const META_LAST_ERROR_MSG = "last_error_msg";
export const META_CONSECUTIVE_FAILS = "consecutive_failures";
export const META_NEXT_ATTEMPT_AT = "next_attempt_at";

const BACKOFF_BASE_MS = 1_000;
const BACKOFF_MAX_MS = 5 * 60_000;

export interface FlushResult {
  uploadedEvents: number;
  uploadedSessions: number;
  /** True if there are still events pending after this flush (hit batch cap, more to do). */
  moreAvailable: boolean;
}

/** Compute the wall-clock time the next attempt is allowed to start. */
export function nextAttemptAt(): number {
  const raw = getMeta(META_NEXT_ATTEMPT_AT);
  return raw ? Number(raw) : 0;
}

export function consecutiveFailures(): number {
  const raw = getMeta(META_CONSECUTIVE_FAILS);
  return raw ? Number(raw) : 0;
}

function recordSuccess() {
  const now = Date.now();
  setMeta(META_LAST_SYNC_AT, String(now));
  setMeta(META_LAST_ERROR_AT, null);
  setMeta(META_LAST_ERROR_MSG, null);
  setMeta(META_CONSECUTIVE_FAILS, "0");
  setMeta(META_NEXT_ATTEMPT_AT, "0");
}

function recordFailure(err: Error, permanent: boolean) {
  const now = Date.now();
  const fails = consecutiveFailures() + 1;
  setMeta(META_LAST_ERROR_AT, String(now));
  setMeta(META_LAST_ERROR_MSG, truncate(err.message, 500));
  setMeta(META_CONSECUTIVE_FAILS, String(fails));
  if (permanent) {
    // Permanent errors (4xx like bad-prefix, plan-limit) — back off the
    // longest window so we don't hammer the server, but don't give up
    // forever; user may upgrade plan or re-link, and we want the next
    // tick to recover within minutes.
    setMeta(META_NEXT_ATTEMPT_AT, String(now + BACKOFF_MAX_MS));
    return;
  }
  // Exponential: 1s, 2s, 4s, ..., capped at 5min, with 0–25% jitter.
  const exp = Math.min(BACKOFF_MAX_MS, BACKOFF_BASE_MS * 2 ** (fails - 1));
  const jitter = exp * 0.25 * Math.random();
  setMeta(META_NEXT_ATTEMPT_AT, String(now + exp + jitter));
}

function truncate(s: string, n: number) {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

/**
 * Flush a single batch. Returns moreAvailable=true if the queue still has
 * events the daemon should pick up on the next tick (we hit the byte/event
 * cap mid-flush). Throws on failure — caller decides whether to swallow.
 */
export async function flushOnce(): Promise<FlushResult> {
  const cfg = readConfig();
  if (!cfg.apiKey) {
    throw new Error("Not linked. Run: agentreel link <api-key>");
  }
  const batch = takePendingBatch(MAX_BATCH_EVENTS, MAX_BATCH_BYTES);
  if (batch.events.length === 0) {
    // Nothing to do isn't an error — but don't stamp last_sync, since
    // we didn't actually round-trip anything.
    return { uploadedEvents: 0, uploadedSessions: 0, moreAvailable: false };
  }
  try {
    const res = await postIngest(cfg, { sessions: batch.sessions, events: batch.events });
    markUploaded(batch.eventIds);
    recordSuccess();
    return {
      uploadedEvents: res.events_written ?? 0,
      uploadedSessions: res.sessions_written ?? 0,
      moreAvailable: batch.events.length === MAX_BATCH_EVENTS,
    };
  } catch (err) {
    const permanent = err instanceof IngestError && err.isPermanent;
    recordFailure(err as Error, permanent);
    throw err;
  }
}
