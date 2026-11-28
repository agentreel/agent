/**
 * Daemon heartbeat (re-audit item 3, gap G7), built against the web contract
 * `POST /api/v1/agent/heartbeat` (agentreel/web PR "daemon heartbeat contract",
 * docs/agent-heartbeat-api.md and lib/agent/heartbeat-contract.ts).
 *
 * The daemon beats every `interval_s`. The server uses the beats to tell a
 * covered device from one that went quiet, and receives the hook gaps found by
 * the transcript watcher. A dead daemon simply stops beating, which is the
 * signal. Nothing here ever blocks or fails an upload or a hook.
 *
 * Privacy: the body has counts, states and ids only. No command text, paths,
 * prompts, tool input or hostname.
 */
import { nanoid } from "nanoid";
import { platform as osPlatform } from "node:os";
import { isCapturePaused, readConfig, type AgentConfig } from "../config.js";
import { countEvents, getMeta, setMeta } from "../db.js";
import { nativeCursorHooksInstalled } from "../cursor/hook-runner.js";
import { inspectClaudePreExecHook } from "../hooks/install.js";
import { readCachedPolicy } from "../policy/cache.js";
import { META_LAST_SYNC_AT, consecutiveFailures } from "../upload/flush.js";
import {
  countUnreportedGaps,
  getWatcherTotals,
  listUnreportedGaps,
  markGapsReported,
  readWatcherStatus,
} from "../watcher/transcript.js";

declare const __AGENTREEL_VERSION__: string;
const VERSION = typeof __AGENTREEL_VERSION__ === "string" ? __AGENTREEL_VERSION__ : "dev";

// Mirrors lib/agent/heartbeat-contract.ts. Keep in step with the web contract.
export const HEARTBEAT_ROUTE = "/api/v1/agent/heartbeat";
export const HEARTBEAT_SCHEMA_VERSION = 1;
export const DEFAULT_HEARTBEAT_INTERVAL_S = 60;
export const MIN_HEARTBEAT_INTERVAL_S = 30;
export const MAX_HEARTBEAT_INTERVAL_S = 900;
export const HEARTBEAT_LIVE_INTERVALS = 3;
export const HEARTBEAT_MISSING_AFTER_S = 24 * 60 * 60;
export const MAX_GAPS_PER_BEAT = 50;
export const HEARTBEAT_TIMEOUT_MS = 10_000;
/** Longest wait after repeated failures. */
export const HEARTBEAT_BACKOFF_MAX_MS = 15 * 60_000;
/** When more gaps wait than fit in one beat, send the next batch after this. */
export const HEARTBEAT_CATCHUP_MS = 15_000;

export const META_DEVICE_ID = "device_id";
export const META_HB_LAST_OK_AT = "hb_last_ok_at";
export const META_HB_LAST_ERROR_AT = "hb_last_error_at";
export const META_HB_LAST_ERROR = "hb_last_error";
export const META_HB_FAILURES = "hb_failures";
export const META_HB_INTERVAL_S = "hb_interval_s";

export interface HeartbeatBody {
  version: 1;
  device_id: string;
  sent_at: string;
  interval_s: number;
  agent_version: string;
  platform: "darwin" | "linux" | "win32" | "other";
  capture: "active" | "paused";
  hosts: { claude_code: { hooks_installed: boolean }; cursor: { hooks_installed: boolean } };
  policy_mode: "observe" | "enforce" | null;
  transcript_watcher: {
    state: "running" | "idle" | "disabled" | "error";
    files_watched: number;
    tool_uses_seen: number;
    hook_gaps_total: number;
    last_scan_at: string | null;
    errors: { permission_denied: number; rotated_or_truncated: number; unreadable: number };
  };
  queue: { pending_events: number; last_sync_at: string | null; consecutive_failures: number };
  hook_gaps: Array<{
    tool_use_id: string;
    session_id: string;
    tool_name: string;
    source: "claude-code" | "cursor";
    transcript_ts: string | null;
    detected_at: string;
  }>;
}

export function heartbeatEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const v = env.AGENTREEL_HEARTBEAT;
  return !(v === "0" || v === "false" || v === "no" || v === "off");
}

/** Random per install, stored in the local db. Never derived from the hostname. */
export function getDeviceId(): string {
  const existing = getMeta(META_DEVICE_ID);
  if (existing && /^[A-Za-z0-9_-]{8,64}$/.test(existing)) return existing;
  const id = nanoid(24);
  setMeta(META_DEVICE_ID, id);
  return id;
}

const iso = (ms: number | null | undefined): string | null =>
  typeof ms === "number" && Number.isFinite(ms) && ms > 0 ? new Date(ms).toISOString() : null;

function platformName(): HeartbeatBody["platform"] {
  const p = osPlatform();
  return p === "darwin" || p === "linux" || p === "win32" ? p : "other";
}

function safe<T>(fn: () => T, fallback: T): T {
  try {
    return fn();
  } catch {
    return fallback;
  }
}

export interface BuildOptions {
  now?: number;
  intervalS?: number;
  /** Leave the gaps out (used after the server rejected a beat as invalid). */
  omitGaps?: boolean;
  config?: AgentConfig;
}

export function buildHeartbeat(opts: BuildOptions = {}): HeartbeatBody {
  const now = opts.now ?? Date.now();
  const cfg = opts.config ?? readConfig();
  const status = readWatcherStatus();
  const totals = getWatcherTotals();
  const gaps = opts.omitGaps ? [] : listUnreportedGaps(MAX_GAPS_PER_BEAT);
  const counts = safe(() => countEvents(now), { total: 0, pending: 0, held: 0 });
  const lastSync = Number(getMeta(META_LAST_SYNC_AT) ?? "0");
  const mode = safe(() => readCachedPolicy()?.policy.mode ?? null, null);

  return {
    version: HEARTBEAT_SCHEMA_VERSION,
    device_id: getDeviceId(),
    sent_at: new Date(now).toISOString(),
    interval_s: clampInterval(opts.intervalS ?? DEFAULT_HEARTBEAT_INTERVAL_S),
    agent_version: VERSION.slice(0, 32) || "dev",
    platform: platformName(),
    capture: isCapturePaused(cfg) ? "paused" : "active",
    hosts: {
      claude_code: { hooks_installed: safe(() => inspectClaudePreExecHook().preToolUseInstalled, false) },
      cursor: { hooks_installed: safe(() => nativeCursorHooksInstalled(), false) },
    },
    policy_mode: mode === "observe" || mode === "enforce" ? mode : null,
    transcript_watcher: {
      state: status?.state ?? "idle",
      files_watched: status?.files_watched ?? 0,
      tool_uses_seen: totals.tool_uses_seen,
      hook_gaps_total: totals.hook_gaps_total,
      last_scan_at: iso(status?.last_scan_at),
      errors: status?.errors ?? { permission_denied: 0, rotated_or_truncated: 0, unreadable: 0 },
    },
    queue: {
      pending_events: Math.max(0, counts.pending - counts.held),
      last_sync_at: iso(lastSync),
      consecutive_failures: safe(() => consecutiveFailures(), 0),
    },
    hook_gaps: gaps.map((g) => ({
      tool_use_id: g.tool_use_id,
      session_id: g.session_id,
      tool_name: g.tool_name,
      source: g.source,
      transcript_ts: iso(g.transcript_ts),
      detected_at: iso(g.detected_at) ?? new Date(now).toISOString(),
    })),
  };
}

export function clampInterval(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return DEFAULT_HEARTBEAT_INTERVAL_S;
  return Math.min(MAX_HEARTBEAT_INTERVAL_S, Math.max(MIN_HEARTBEAT_INTERVAL_S, Math.round(value)));
}

export class HeartbeatError extends Error {
  constructor(
    message: string,
    /** HTTP status, or 0 for a network error or timeout. */
    readonly status: number,
    readonly retryAfterMs: number | null = null,
  ) {
    super(message);
    this.name = "HeartbeatError";
  }
  /** Network error, timeout, 408, 429 and 5xx are retried with backoff. */
  get retryable(): boolean {
    return this.status === 0 || this.status === 408 || this.status === 429 || this.status >= 500;
  }
}

export interface HeartbeatResponseBody {
  ok: true;
  server_time: string;
  next_interval_s: number;
  gaps_recorded: number;
}

function parseRetryAfter(h: string | null): number | null {
  if (!h) return null;
  const n = Number(h);
  if (Number.isFinite(n) && n >= 0) return Math.min(n, 3600) * 1000;
  return null;
}

export async function postHeartbeat(
  cfg: AgentConfig,
  body: HeartbeatBody,
  opts: { timeoutMs?: number; fetchImpl?: typeof fetch } = {},
): Promise<HeartbeatResponseBody> {
  if (!cfg.apiKey) throw new HeartbeatError("not linked", 401);
  const f = opts.fetchImpl ?? fetch;
  const url = `${cfg.apiBaseUrl.replace(/\/$/, "")}${HEARTBEAT_ROUTE}`;
  let res: Response;
  try {
    res = await f(url, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${cfg.apiKey}` },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(opts.timeoutMs ?? HEARTBEAT_TIMEOUT_MS),
    });
  } catch (err) {
    const name = (err as Error)?.name;
    throw new HeartbeatError(name === "TimeoutError" || name === "AbortError" ? "timeout" : "network error", 0);
  }
  if (!res.ok) {
    throw new HeartbeatError(`http-${res.status}`, res.status, parseRetryAfter(res.headers.get("retry-after")));
  }
  let data: unknown;
  try {
    data = await res.json();
  } catch {
    throw new HeartbeatError("bad response body", 502);
  }
  const d = data as Partial<HeartbeatResponseBody> | null;
  if (!d || d.ok !== true || typeof d.next_interval_s !== "number") {
    throw new HeartbeatError("bad response body", 502);
  }
  return d as HeartbeatResponseBody;
}

export interface SchedulerOptions {
  now?: () => number;
  random?: () => number;
  config?: () => AgentConfig;
  send?: (cfg: AgentConfig, body: HeartbeatBody) => Promise<HeartbeatResponseBody>;
  log?: (line: string) => void;
  enabled?: () => boolean;
}

export type TickResult =
  | { kind: "skipped"; reason: "not_due" | "disabled" | "unlinked" | "key_rejected" }
  | { kind: "sent"; gapsAcknowledged: number }
  | { kind: "failed"; status: number; retryInMs: number };

/**
 * Drives the beat from the daemon loop. `tick()` is cheap when nothing is due
 * and never throws. State that matters to `agentreel status` is kept in the
 * local db; scheduling state is in memory, so a restarted daemon beats at once.
 */
export class HeartbeatScheduler {
  private readonly o: Required<SchedulerOptions>;
  private nextAt = 0;
  private intervalS = DEFAULT_HEARTBEAT_INTERVAL_S;
  private failures = 0;
  /** apiKey the server refused with 401. We stop until the key changes. */
  private rejectedKey: string | null = null;
  private omitGapsNext = false;
  private loggedStatuses = new Set<number>();

  constructor(opts: SchedulerOptions = {}) {
    this.o = {
      now: opts.now ?? Date.now,
      random: opts.random ?? Math.random,
      config: opts.config ?? readConfig,
      send: opts.send ?? ((cfg, body) => postHeartbeat(cfg, body)),
      log: opts.log ?? (() => {}),
      enabled: opts.enabled ?? (() => heartbeatEnabled()),
    };
  }

  get nextDueAt(): number {
    return this.nextAt;
  }

  async tick(): Promise<TickResult> {
    const now = this.o.now();
    try {
      if (!this.o.enabled()) return { kind: "skipped", reason: "disabled" };
      if (now < this.nextAt) return { kind: "skipped", reason: "not_due" };
      const cfg = this.o.config();
      if (!cfg.apiKey) return { kind: "skipped", reason: "unlinked" };
      if (this.rejectedKey !== null) {
        if (cfg.apiKey === this.rejectedKey) return { kind: "skipped", reason: "key_rejected" };
        this.rejectedKey = null; // the user linked a new key
      }

      const omitGaps = this.omitGapsNext;
      this.omitGapsNext = false;
      const body = buildHeartbeat({ now, intervalS: this.intervalS, omitGaps, config: cfg });
      let res: HeartbeatResponseBody;
      try {
        res = await this.o.send(cfg, body);
      } catch (err) {
        return this.onFailure(err, now, cfg.apiKey, body.hook_gaps.length > 0);
      }
      return this.onSuccess(res, body, now);
    } catch (err) {
      // Building the body failed (for example the db is locked). Try again soon.
      this.nextAt = now + MIN_HEARTBEAT_INTERVAL_S * 1000;
      recordError(`internal: ${(err as Error)?.message ?? "error"}`, now);
      return { kind: "failed", status: -1, retryInMs: MIN_HEARTBEAT_INTERVAL_S * 1000 };
    }
  }

  private onSuccess(res: HeartbeatResponseBody, body: HeartbeatBody, now: number): TickResult {
    this.failures = 0;
    this.intervalS = clampInterval(res.next_interval_s);
    markGapsReported(body.hook_gaps.map((g) => g.tool_use_id), now);
    setMeta(META_HB_LAST_OK_AT, String(now));
    setMeta(META_HB_FAILURES, "0");
    setMeta(META_HB_INTERVAL_S, String(this.intervalS));
    setMeta(META_HB_LAST_ERROR, null);
    setMeta(META_HB_LAST_ERROR_AT, null);
    this.loggedStatuses.clear();
    const more = countUnreportedGaps() > 0 && !this.omitGapsNext;
    this.nextAt = now + (more ? HEARTBEAT_CATCHUP_MS : this.intervalS * 1000);
    return { kind: "sent", gapsAcknowledged: body.hook_gaps.length };
  }

  private onFailure(err: unknown, now: number, apiKey: string, hadGaps: boolean): TickResult {
    const e = err instanceof HeartbeatError ? err : new HeartbeatError("error", 0);
    recordError(e.status === 0 ? e.message : `http ${e.status}`, now);

    if (e.status === 401) {
      this.rejectedKey = apiKey;
      this.log401();
      return { kind: "failed", status: 401, retryInMs: Number.POSITIVE_INFINITY };
    }
    if (!e.retryable) {
      // 409 (device cap), 413, 422 or another 4xx: resending the same body
      // cannot work. Keep the normal interval and say so once.
      if (!this.loggedStatuses.has(e.status)) {
        this.loggedStatuses.add(e.status);
        this.o.log(`heartbeat rejected by the server (http ${e.status}); keeping the normal interval`);
      }
      // A body the server calls invalid must not stall liveness: the next beat
      // leaves the gaps out. They stay unreported locally.
      if ((e.status === 422 || e.status === 413) && hadGaps) this.omitGapsNext = true;
      const wait = this.intervalS * 1000;
      this.nextAt = now + wait;
      return { kind: "failed", status: e.status, retryInMs: wait };
    }
    this.failures += 1;
    setMeta(META_HB_FAILURES, String(this.failures));
    const base = Math.min(HEARTBEAT_BACKOFF_MAX_MS, this.intervalS * 1000 * 2 ** (this.failures - 1));
    const jittered = base + base * 0.25 * this.o.random();
    const wait = Math.min(
      HEARTBEAT_BACKOFF_MAX_MS,
      Math.max(jittered, e.retryAfterMs ?? 0, MIN_HEARTBEAT_INTERVAL_S * 1000),
    );
    this.nextAt = now + wait;
    return { kind: "failed", status: e.status, retryInMs: wait };
  }

  private log401(): void {
    if (this.loggedStatuses.has(401)) return;
    this.loggedStatuses.add(401);
    this.o.log("heartbeat: the server rejected the API key (401); paused until you run `agentreel link`");
  }
}

function recordError(message: string, now: number): void {
  try {
    setMeta(META_HB_LAST_ERROR, message.slice(0, 200));
    setMeta(META_HB_LAST_ERROR_AT, String(now));
  } catch {
    // db locked: the error is logged by the caller if it matters
  }
}

export interface HeartbeatHealth {
  /** live: recent beat. stale: the daemon stopped beating. missing: very old. never: no beat ever. */
  liveness: "live" | "stale" | "missing" | "never";
  lastOkAt: number | null;
  ageMs: number | null;
  intervalS: number;
  failures: number;
  lastError: string | null;
}

/** Same thresholds the server uses (classifyHeartbeat in the web contract). */
export function heartbeatHealth(now: number = Date.now()): HeartbeatHealth {
  const lastOk = Number(getMeta(META_HB_LAST_OK_AT) ?? "0");
  const intervalS = clampInterval(Number(getMeta(META_HB_INTERVAL_S) ?? DEFAULT_HEARTBEAT_INTERVAL_S));
  const failures = Number(getMeta(META_HB_FAILURES) ?? "0") || 0;
  const lastError = getMeta(META_HB_LAST_ERROR);
  if (!Number.isFinite(lastOk) || lastOk <= 0) {
    return { liveness: "never", lastOkAt: null, ageMs: null, intervalS, failures, lastError };
  }
  const ageMs = Math.max(0, now - lastOk);
  const ageS = ageMs / 1000;
  const liveness =
    ageS <= HEARTBEAT_LIVE_INTERVALS * intervalS ? "live" : ageS <= HEARTBEAT_MISSING_AFTER_S ? "stale" : "missing";
  return { liveness, lastOkAt: lastOk, ageMs, intervalS, failures, lastError };
}
