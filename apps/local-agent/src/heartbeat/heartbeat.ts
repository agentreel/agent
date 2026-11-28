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
import { createHash } from "node:crypto";
import { platform as osPlatform } from "node:os";
import { isCapturePaused, readConfig, type AgentConfig } from "../config.js";
import { countEvents, getMeta, setMeta } from "../db.js";
import { nativeCursorHooksInstalled } from "../cursor/hook-runner.js";
import { inspectClaudePreExecHook } from "../hooks/install.js";
import { readCachedPolicy } from "../policy/cache.js";
import { getPolicyOrgId } from "../policy/types.js";
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
/** 404 handling: when to check again (ms epoch), how many 404s in a row, and for which agent version. */
export const META_HB_404_NEXT_AT = "hb_404_next_at";
export const META_HB_404_COUNT = "hb_404_count";
export const META_HB_404_VERSION = "hb_404_version";
/** SHA-256 prefix of the API key the server refused with 401. */
export const META_HB_REJECTED_KEY = "hb_rejected_key";
/** Last send attempt (ms epoch), so no restart or timer bug can send faster than the floor. */
export const META_HB_LAST_ATTEMPT_AT = "hb_last_attempt_at";

/**
 * A 404 means the server does not have the heartbeat route yet. Check again
 * after a random 6 to 24 hours, quietly.
 */
export const HEARTBEAT_404_MIN_MS = 6 * 60 * 60_000;
export const HEARTBEAT_404_MAX_MS = 24 * 60 * 60_000;
/**
 * After this many 404s in a row the daemon stops checking until the agent
 * version or the API key changes (an upgrade or a relink starts over).
 */
export const HEARTBEAT_404_MAX_CHECKS = 14;
/**
 * No two send attempts closer than this, whatever the timers, restarts or the
 * clock do. Below the 15 s gap catch-up, far above a tight loop.
 */
export const HEARTBEAT_MIN_SEND_GAP_MS = 10_000;

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

/** The env switch only: `AGENTREEL_HEARTBEAT=0|false|no|off` turns the heartbeat off, always. */
export function heartbeatEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const v = env.AGENTREEL_HEARTBEAT;
  return !(v === "0" || v === "false" || v === "no" || v === "off");
}

export type HeartbeatReason =
  /** AGENTREEL_HEARTBEAT=0 (or false, no, off). Beats everything else. */
  | "disabled_by_env"
  /** No API key: nothing to send to. */
  | "not_linked"
  /** The user ran `agentreel heartbeat off`. */
  | "opted_out"
  /** On because the device is linked to an org workspace. */
  | "org_default"
  /** On because the user ran `agentreel heartbeat on` (personal or unlinked install). */
  | "opt_in"
  /** Personal install, nothing chosen: off. */
  | "off_by_default";

export interface HeartbeatDecision {
  enabled: boolean;
  reason: HeartbeatReason;
  orgLinked: boolean;
}

/**
 * True when this device belongs to an org workspace: the cached policy came
 * from an org (`org_id` set), or the config records an org. A personal key has
 * an `org_id: null` policy or none at all.
 */
export function isOrgLinked(cfg: AgentConfig = readConfig()): boolean {
  if (typeof cfg.orgSlug === "string" && cfg.orgSlug.length > 0) return true;
  return safe(() => getPolicyOrgId(readCachedPolicy()?.policy) !== null, false);
}

/**
 * Whether the heartbeat runs, and why. Order: the env switch, then no key,
 * then an explicit `heartbeat off`, then the org default, then an explicit
 * `heartbeat on`, else off.
 */
export function heartbeatDecision(
  cfg: AgentConfig = readConfig(),
  env: NodeJS.ProcessEnv = process.env,
  orgLinked: boolean = isOrgLinked(cfg),
): HeartbeatDecision {
  if (!heartbeatEnabled(env)) return { enabled: false, reason: "disabled_by_env", orgLinked };
  if (!cfg.apiKey) return { enabled: false, reason: "not_linked", orgLinked };
  if (cfg.heartbeat === false) return { enabled: false, reason: "opted_out", orgLinked };
  if (orgLinked) return { enabled: true, reason: "org_default", orgLinked };
  if (cfg.heartbeat === true) return { enabled: true, reason: "opt_in", orgLinked };
  return { enabled: false, reason: "off_by_default", orgLinked };
}

export function describeHeartbeatReason(d: HeartbeatDecision): string {
  switch (d.reason) {
    case "disabled_by_env":
      return "off (AGENTREEL_HEARTBEAT=0 is set)";
    case "not_linked":
      return "off (not linked; run `agentreel link`)";
    case "opted_out":
      return "off (you ran `agentreel heartbeat off`)";
    case "org_default":
      return "on (org default: this device is linked to an org workspace)";
    case "opt_in":
      return "on (you opted in with `agentreel heartbeat on`)";
    case "off_by_default":
      return "off (personal install; opt in with `agentreel heartbeat on`)";
  }
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

/** How often a disabled scheduler looks at the config again. */
export const DISABLED_RECHECK_MS = 30_000;

export interface SchedulerOptions {
  now?: () => number;
  random?: () => number;
  config?: () => AgentConfig;
  send?: (cfg: AgentConfig, body: HeartbeatBody) => Promise<HeartbeatResponseBody>;
  log?: (line: string) => void;
  /** Whether to beat for this config. Default: `heartbeatDecision(cfg).enabled`. */
  enabled?: (cfg: AgentConfig) => boolean;
}

export type TickResult =
  | { kind: "skipped"; reason: "not_due" | "disabled" | "unlinked" | "key_rejected" | "not_available" }
  | { kind: "sent"; gapsAcknowledged: number }
  | { kind: "failed"; status: number; retryInMs: number };

/**
 * Drives the beat from the daemon loop. `tick()` is cheap when nothing is due
 * and never throws. State that matters to `agentreel status` is kept in the
 * local db. Normal scheduling is in memory, so a restarted daemon beats at
 * once, except: a 404 recheck time, a 401-rejected key, and the last attempt
 * time are persisted, so a restart cannot loop on a 404 or a 401, and no two
 * attempts are ever closer than HEARTBEAT_MIN_SEND_GAP_MS.
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
      enabled:
        opts.enabled ??
        // Unlinked stays "unlinked" unless the env switch is off.
        ((cfg) => (cfg.apiKey ? heartbeatDecision(cfg).enabled : heartbeatEnabled())),
    };
  }

  get nextDueAt(): number {
    return this.nextAt;
  }

  async tick(): Promise<TickResult> {
    const now = this.o.now();
    try {
      // AGENTREEL_HEARTBEAT=0 always wins, over config, org default and any
      // enabled() override.
      if (!heartbeatEnabled()) {
        this.nextAt = now + DISABLED_RECHECK_MS;
        return { kind: "skipped", reason: "disabled" };
      }
      if (now < this.nextAt) return { kind: "skipped", reason: "not_due" };
      const cfg = this.o.config();
      if (!this.o.enabled(cfg)) {
        // Re-check soon (a `heartbeat on` or a policy sync can change it) without reading the policy cache every loop.
        this.nextAt = now + DISABLED_RECHECK_MS;
        return { kind: "skipped", reason: "disabled" };
      }
      if (!cfg.apiKey) return { kind: "skipped", reason: "unlinked" };
      const keyHash = keyFingerprint(cfg.apiKey);
      const persistedRejected = getMeta(META_HB_REJECTED_KEY);
      if (this.rejectedKey !== null || persistedRejected !== null) {
        if (cfg.apiKey === this.rejectedKey || keyHash === persistedRejected) {
          return { kind: "skipped", reason: "key_rejected" };
        }
        // The user linked a new key.
        this.rejectedKey = null;
        setMeta(META_HB_REJECTED_KEY, null);
        clear404State();
      }
      const gate = this.notAvailableGate(now, keyHash);
      if (gate) return gate;
      // Floor between attempts. A clock that went backwards is clamped to now.
      const lastAttempt = Number(getMeta(META_HB_LAST_ATTEMPT_AT) ?? "0") || 0;
      if (lastAttempt > now) setMeta(META_HB_LAST_ATTEMPT_AT, String(now));
      const since = now - Math.min(lastAttempt, now);
      if (lastAttempt > 0 && since < HEARTBEAT_MIN_SEND_GAP_MS) {
        this.nextAt = now + (HEARTBEAT_MIN_SEND_GAP_MS - since);
        return { kind: "skipped", reason: "not_due" };
      }
      setMeta(META_HB_LAST_ATTEMPT_AT, String(now));

      const omitGaps = this.omitGapsNext;
      this.omitGapsNext = false;
      const body = buildHeartbeat({ now, intervalS: this.intervalS, omitGaps, config: cfg });
      let res: HeartbeatResponseBody;
      try {
        res = await this.o.send(cfg, body);
      } catch (err) {
        return this.onFailure(err, now, cfg.apiKey, body.hook_gaps.length > 0, keyHash);
      }
      return this.onSuccess(res, body, now);
    } catch (err) {
      // Building the body failed (for example the db is locked). Try again soon.
      this.nextAt = now + MIN_HEARTBEAT_INTERVAL_S * 1000;
      recordError(`internal: ${(err as Error)?.message ?? "error"}`, now);
      return { kind: "failed", status: -1, retryInMs: MIN_HEARTBEAT_INTERVAL_S * 1000 };
    }
  }

  /**
   * While a 404 recheck is pending (persisted), or the 404 cap is reached for
   * this agent version and key, skip quietly.
   */
  private notAvailableGate(now: number, keyHash: string): TickResult | null {
    const version = getMeta(META_HB_404_VERSION);
    if (version !== null && version !== `${VERSION}:${keyHash}`) {
      // Upgraded or relinked since the 404s: start over.
      clear404State();
      return null;
    }
    const count = Number(getMeta(META_HB_404_COUNT) ?? "0") || 0;
    if (count >= HEARTBEAT_404_MAX_CHECKS) {
      this.nextAt = now + HEARTBEAT_404_MAX_MS;
      return { kind: "skipped", reason: "not_available" };
    }
    const raw = Number(getMeta(META_HB_404_NEXT_AT) ?? "0");
    if (!Number.isFinite(raw) || raw <= 0) return null;
    // A stored time further out than the longest wait means the clock moved
    // back: pull it in to now + the longest wait.
    const nextAt = Math.min(raw, now + HEARTBEAT_404_MAX_MS);
    if (nextAt !== raw) setMeta(META_HB_404_NEXT_AT, String(nextAt));
    if (now < nextAt) {
      this.nextAt = nextAt;
      return { kind: "skipped", reason: "not_available" };
    }
    return null;
  }

  private onNotFound(now: number, keyHash: string): TickResult {
    const count = (Number(getMeta(META_HB_404_COUNT) ?? "0") || 0) + 1;
    const r = Math.min(1, Math.max(0, Number(this.o.random()) || 0));
    const wait = Math.round(HEARTBEAT_404_MIN_MS + (HEARTBEAT_404_MAX_MS - HEARTBEAT_404_MIN_MS) * r);
    setMeta(META_HB_404_COUNT, String(count));
    setMeta(META_HB_404_NEXT_AT, String(now + wait));
    setMeta(META_HB_404_VERSION, `${VERSION}:${keyHash}`);
    this.nextAt = now + wait;
    // Quiet: no log line. `agentreel status` shows the last error.
    return { kind: "failed", status: 404, retryInMs: count >= HEARTBEAT_404_MAX_CHECKS ? Number.POSITIVE_INFINITY : wait };
  }

  private onSuccess(res: HeartbeatResponseBody, body: HeartbeatBody, now: number): TickResult {
    this.failures = 0;
    clear404State();
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

  private onFailure(err: unknown, now: number, apiKey: string, hadGaps: boolean, keyHash: string): TickResult {
    const e = err instanceof HeartbeatError ? err : new HeartbeatError("error", 0);
    recordError(
      e.status === 0 ? e.message : e.status === 404 ? "http 404 (heartbeat not available on the server yet)" : `http ${e.status}`,
      now,
    );

    if (e.status === 404) return this.onNotFound(now, keyHash);
    if (e.status === 401) {
      this.rejectedKey = apiKey;
      setMeta(META_HB_REJECTED_KEY, keyHash);
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

function keyFingerprint(apiKey: string): string {
  return createHash("sha256").update(apiKey).digest("hex").slice(0, 16);
}

function clear404State(): void {
  setMeta(META_HB_404_NEXT_AT, null);
  setMeta(META_HB_404_COUNT, null);
  setMeta(META_HB_404_VERSION, null);
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
