import type { AgentConfig } from "../config.js";
import type { PolicyDecisionRecord } from "../policy/enforce.js";

export interface IngestSession {
  id: string;
  tool: string;
  started_at: number;
  ended_at?: number | null;
  cwd?: string | null;
  total_cost_cents?: number | null;
  total_tokens?: number | null;
  /** Who/where ran the agent (agent >= 0.1.7). Older servers ignore it. */
  attribution?: unknown;
  /** AgentReel Guard findings (agent >= 0.2.0). Optional, additive field. */
  guard_findings?: {
    version: number;
    risk_score: number;
    findings: Array<{
      rule_id: string;
      severity: string;
      category: string;
      timestamp: number;
      evidence: string;
    }>;
  };
  /** AgentReel Govern policy decisions (v2, agent >= 0.3.0). Optional, additive field. */
  policy_decisions?: {
    version: 2;
    decisions: PolicyDecisionRecord[];
  };
}

export interface IngestEvent {
  id: string;
  session_id: string;
  ts: number;
  type: string;
  tool: string;
  cwd?: string | null;
  payload: unknown;
}

export interface IngestResponse {
  ok: boolean;
  sessions_written?: number;
  events_written?: number;
  error?: string;
  reason?: string;
  message?: string;
  /** Sessions the server refused (e.g. over the plan's active-session limit). */
  rejected_sessions?: Array<{ id: string; reason: string }>;
  plan_limit?: {
    plan: string;
    limit: number;
    active_sessions: number;
    retry_after_seconds?: number;
    message: string;
  };
}

export class IngestError extends Error {
  /** Server Retry-After, in ms, when it sent one. */
  retryAfterMs: number | null = null;
  constructor(
    message: string,
    readonly status: number,
    readonly body: IngestResponse | null,
  ) {
    super(message);
    this.name = "IngestError";
  }
  /** 4xx (except 408/429): a payload-shaped problem the agent can't fix by retrying. Status 0 is a timeout. */
  get isPermanent(): boolean {
    return this.status >= 400 && this.status < 500 && this.status !== 408 && this.status !== 429;
  }
}

/** Per-attempt timeout, covering the request and reading the response body. */
export const INGEST_TIMEOUT_MS = 15_000;
/** Total attempts per postIngest call (1 try plus 3 retries). */
export const INGEST_MAX_ATTEMPTS = 4;
export const INGEST_BACKOFF_BASE_MS = 500;
export const INGEST_BACKOFF_MAX_MS = 8_000;

export interface PostIngestOptions {
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  maxAttempts?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  sleep?: (ms: number) => Promise<void>;
  /** Returns [0, 1); injectable so tests can pin the jitter. */
  random?: () => number;
}

/**
 * Exponential backoff with full jitter: a uniform delay in
 * [0, min(maxMs, baseMs * 2^retry)). `retry` is 0 for the first retry.
 */
export function backoffDelayMs(
  retry: number,
  baseMs: number = INGEST_BACKOFF_BASE_MS,
  maxMs: number = INGEST_BACKOFF_MAX_MS,
  random: () => number = Math.random,
): number {
  const cap = Math.min(maxMs, baseMs * 2 ** retry);
  return Math.floor(random() * cap);
}

/** Retry-After in seconds (or an HTTP date), in ms, or null. */
function retryAfterMs(res: Response, now = Date.now()): number | null {
  const h = res.headers.get("retry-after");
  if (!h) return null;
  const secs = Number(h);
  if (Number.isFinite(secs) && secs >= 0) return secs * 1000;
  const at = Date.parse(h);
  return Number.isFinite(at) ? Math.max(0, at - now) : null;
}

function isRetryableStatus(status: number): boolean {
  return status >= 500 || status === 408 || status === 429;
}

const defaultSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * POST one ingest batch. Each attempt times out after `timeoutMs`; timeouts,
 * network errors, 5xx, 408 and 429 are retried with exponential backoff and
 * full jitter (a 429/503 Retry-After is honored, capped at `maxDelayMs`).
 * Other 4xx fail at once. The batch is idempotent (event ids), so a retry
 * after a lost response is safe.
 */
export async function postIngest(
  cfg: AgentConfig,
  body: { sessions?: IngestSession[]; events?: IngestEvent[] },
  opts: PostIngestOptions = {},
): Promise<IngestResponse> {
  if (!cfg.apiKey) {
    throw new Error("Not linked. Run: agentreel link <key>");
  }
  const url = `${cfg.apiBaseUrl.replace(/\/$/, "")}/api/v1/sessions/ingest`;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? INGEST_TIMEOUT_MS;
  const maxAttempts = Math.max(1, opts.maxAttempts ?? INGEST_MAX_ATTEMPTS);
  const baseDelayMs = opts.baseDelayMs ?? INGEST_BACKOFF_BASE_MS;
  const maxDelayMs = opts.maxDelayMs ?? INGEST_BACKOFF_MAX_MS;
  const sleep = opts.sleep ?? defaultSleep;
  const random = opts.random ?? Math.random;
  const payload = JSON.stringify(body);

  let lastErr: unknown;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    let hint: number | null = null;
    try {
      return await postIngestOnce(fetchImpl, url, cfg.apiKey, payload, timeoutMs);
    } catch (err) {
      lastErr = err;
      if (err instanceof IngestError) {
        if (!isRetryableStatus(err.status) && err.status !== 0) throw err;
        hint = err.retryAfterMs ?? null;
      }
    }
    if (attempt + 1 >= maxAttempts) break;
    const delay = hint !== null ? Math.min(hint, maxDelayMs) : backoffDelayMs(attempt, baseDelayMs, maxDelayMs, random);
    await sleep(delay);
  }
  throw lastErr;
}

async function postIngestOnce(
  fetchImpl: typeof fetch,
  url: string,
  apiKey: string,
  payload: string,
  timeoutMs: number,
): Promise<IngestResponse> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    let res: Response;
    let data: IngestResponse | null = null;
    try {
      res = await fetchImpl(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${apiKey}`,
          // Tells the server we understand per-session rejections, so it can
          // accept the rest of the batch with a 200 instead of a 402.
          "x-agentreel-partial": "1",
        },
        body: payload,
        signal: ctrl.signal,
      });
      try {
        data = (await res.json()) as IngestResponse;
      } catch {
        // Non-JSON body: treat as transient if 5xx, permanent otherwise.
        if (ctrl.signal.aborted) throw new Error("aborted");
      }
    } catch (err) {
      if (ctrl.signal.aborted) {
        throw new IngestError(`timeout after ${timeoutMs}ms`, 0, null);
      }
      throw err;
    }
    if (!res.ok || !data?.ok) {
      const reason = data?.reason ? ` (${data.reason})` : "";
      const tag = data?.error ?? `http-${res.status}`;
      const e = new IngestError(`${tag}${reason}`, res.status, data);
      e.retryAfterMs = retryAfterMs(res);
      throw e;
    }
    return data;
  } finally {
    clearTimeout(timer);
  }
}
