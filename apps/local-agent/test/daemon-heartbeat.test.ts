import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { hostname } from "node:os";
import { join } from "node:path";
import { closeDb, getMeta, getDb } from "../src/db.js";
import { installClaudeCodeHooks } from "../src/hooks/install.js";
import { heartbeatStatusLines, watcherStatusLines } from "../src/commands/status.js";
import { runHeartbeatTick } from "../src/commands/daemon.js";
import { resetWatcherSchemaFlag, TranscriptWatcher, DEFAULT_GRACE_MS } from "../src/watcher/transcript.js";
import {
  HEARTBEAT_BACKOFF_MAX_MS,
  HEARTBEAT_CATCHUP_MS,
  HEARTBEAT_LIVE_INTERVALS,
  HEARTBEAT_MISSING_AFTER_S,
  HeartbeatError,
  HeartbeatScheduler,
  MAX_GAPS_PER_BEAT,
  META_HB_FAILURES,
  META_HB_LAST_OK_AT,
  META_HB_INTERVAL_S,
  buildHeartbeat,
  clampInterval,
  getDeviceId,
  heartbeatEnabled,
  heartbeatHealth,
  postHeartbeat,
  type HeartbeatBody,
  type HeartbeatResponseBody,
} from "../src/heartbeat/heartbeat.js";
import { countUnreportedGaps, listUnreportedGaps } from "../src/watcher/transcript.js";
import type { AgentConfig } from "../src/config.js";

let home: string;
let suiteHome: string;
let clock: number;
const T0 = 1_800_000_000_000;

beforeEach(() => {
  suiteHome = process.env.HOME!;
  home = mkdtempSync(join(tmpdir(), "ar-hb-"));
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  closeDb();
  resetWatcherSchemaFlag();
  clock = T0;
});

afterEach(() => {
  closeDb();
  resetWatcherSchemaFlag();
  process.env.HOME = suiteHome;
  process.env.USERPROFILE = suiteHome;
  rmSync(home, { recursive: true, force: true });
  vi.restoreAllMocks();
});

const cfg = (over: Partial<AgentConfig> = {}): AgentConfig => ({
  apiBaseUrl: "https://api.example.test/",
  apiKey: "ar_live_testkey",
  schemaVersion: 1,
  ...over,
});

const okRes = (next = 60, gaps = 0): HeartbeatResponseBody => ({
  ok: true,
  server_time: new Date(clock).toISOString(),
  next_interval_s: next,
  gaps_recorded: gaps,
});

/** Mirror of heartbeatRequestSchema in the web contract (strict keys and ranges). */
function assertContract(b: HeartbeatBody) {
  const keys = (o: object) => Object.keys(o).sort();
  const iso = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
  expect(keys(b)).toEqual(
    ["agent_version", "capture", "device_id", "hook_gaps", "hosts", "interval_s", "platform", "policy_mode", "queue", "sent_at", "transcript_watcher", "version"],
  );
  expect(b.version).toBe(1);
  expect(b.device_id).toMatch(/^[A-Za-z0-9_-]{8,64}$/);
  expect(b.sent_at).toMatch(iso);
  expect(Number.isInteger(b.interval_s) && b.interval_s >= 30 && b.interval_s <= 900).toBe(true);
  expect(b.agent_version.length).toBeGreaterThan(0);
  expect(b.agent_version.length).toBeLessThanOrEqual(32);
  expect(["darwin", "linux", "win32", "other"]).toContain(b.platform);
  expect(["active", "paused"]).toContain(b.capture);
  expect(keys(b.hosts)).toEqual(["claude_code", "cursor"]);
  expect(keys(b.hosts.claude_code)).toEqual(["hooks_installed"]);
  expect([null, "observe", "enforce"]).toContain(b.policy_mode);
  const w = b.transcript_watcher;
  expect(keys(w)).toEqual(["errors", "files_watched", "hook_gaps_total", "last_scan_at", "state", "tool_uses_seen"]);
  expect(["running", "idle", "disabled", "error"]).toContain(w.state);
  expect(keys(w.errors)).toEqual(["permission_denied", "rotated_or_truncated", "unreadable"]);
  if (w.last_scan_at) expect(w.last_scan_at).toMatch(iso);
  expect(keys(b.queue)).toEqual(["consecutive_failures", "last_sync_at", "pending_events"]);
  if (b.queue.last_sync_at) expect(b.queue.last_sync_at).toMatch(iso);
  for (const n of [w.files_watched, w.tool_uses_seen, w.hook_gaps_total, b.queue.pending_events, b.queue.consecutive_failures]) {
    expect(Number.isInteger(n) && n >= 0).toBe(true);
  }
  expect(b.hook_gaps.length).toBeLessThanOrEqual(50);
  for (const g of b.hook_gaps) {
    expect(keys(g)).toEqual(["detected_at", "session_id", "source", "tool_name", "tool_use_id", "transcript_ts"]);
    expect(g.detected_at).toMatch(iso);
    if (g.transcript_ts) expect(g.transcript_ts).toMatch(iso);
    expect(g.tool_use_id.length).toBeLessThanOrEqual(128);
  }
}

/** Create n gaps through the real watcher so the rows match production. */
function makeGaps(n: number) {
  const projects = join(home, ".claude", "projects");
  mkdirSync(join(projects, "p"), { recursive: true });
  let t = clock;
  const w = new TranscriptWatcher({ projectsDir: projects, now: () => t });
  w.scan();
  const lines = Array.from({ length: n }, (_, i) =>
    JSON.stringify({
      type: "assistant",
      sessionId: "s1",
      timestamp: "2026-11-27T21:00:00.000Z",
      message: { content: [{ type: "tool_use", id: `toolu_${i}`, name: "Bash", input: { command: "echo SECRET" } }] },
    }),
  );
  writeFileSync(join(projects, "p", "a.jsonl"), lines.join("\n") + "\n");
  w.scan();
  t += DEFAULT_GRACE_MS + 1;
  w.scan();
}

describe("buildHeartbeat", () => {
  it("matches the web contract and carries no host, path or command data", () => {
    const b = buildHeartbeat({ now: T0, config: cfg() });
    assertContract(b);
    const text = JSON.stringify(b);
    expect(text).not.toContain(hostname());
    expect(text).not.toContain(home);
    expect(b.capture).toBe("active");
    expect(b.hosts).toEqual({ claude_code: { hooks_installed: false }, cursor: { hooks_installed: false } });
    expect(b.policy_mode).toBeNull();
    expect(b.interval_s).toBe(60);
  });

  it("uses a stable random device id, not derived from the hostname", () => {
    const a = getDeviceId();
    expect(getDeviceId()).toBe(a);
    expect(a).toMatch(/^[A-Za-z0-9_-]{8,64}$/);
    expect(a).not.toContain(hostname());
    closeDb();
    expect(getDeviceId()).toBe(a);
  });

  it("repairs a corrupt stored device id", () => {
    getDb().prepare(`INSERT INTO meta (key, value) VALUES ('device_id', 'bad id!')`).run();
    expect(getDeviceId()).toMatch(/^[A-Za-z0-9_-]{8,64}$/);
  });

  it("reports paused capture and installed hooks from the real files", () => {
    installClaudeCodeHooks("agentreel");
    const b = buildHeartbeat({ now: T0, config: cfg({ paused: true }) });
    expect(b.capture).toBe("paused");
    expect(b.hosts.claude_code.hooks_installed).toBe(true);
    assertContract(b);
  });

  it("includes at most 50 gaps oldest first, as ISO times, and no command text", () => {
    makeGaps(60);
    const b = buildHeartbeat({ now: T0, config: cfg() });
    assertContract(b);
    expect(b.hook_gaps).toHaveLength(MAX_GAPS_PER_BEAT);
    expect(b.transcript_watcher.hook_gaps_total).toBe(60);
    expect(JSON.stringify(b)).not.toContain("SECRET");
    expect(buildHeartbeat({ now: T0, config: cfg(), omitGaps: true }).hook_gaps).toEqual([]);
  });

  it("clamps a bad interval into 30..900", () => {
    expect(clampInterval(5)).toBe(30);
    expect(clampInterval(99999)).toBe(900);
    expect(clampInterval(Number.NaN)).toBe(60);
    expect(clampInterval("x")).toBe(60);
    expect(buildHeartbeat({ now: T0, config: cfg(), intervalS: 1 }).interval_s).toBe(30);
  });

  it("can be switched off with AGENTREEL_HEARTBEAT=0", () => {
    expect(heartbeatEnabled({ AGENTREEL_HEARTBEAT: "0" } as never)).toBe(false);
    expect(heartbeatEnabled({ AGENTREEL_HEARTBEAT: "off" } as never)).toBe(false);
    expect(heartbeatEnabled({} as never)).toBe(true);
  });
});

describe("postHeartbeat", () => {
  const body = () => buildHeartbeat({ now: T0, config: cfg() });
  const resp = (status: number, json?: unknown, headers: Record<string, string> = {}) =>
    new Response(json === undefined ? "not json" : JSON.stringify(json), { status, headers });

  it("posts to the contract route with the Bearer key and returns the response", async () => {
    const f = vi.fn(async () => resp(200, okRes(120, 2)));
    const r = await postHeartbeat(cfg(), body(), { fetchImpl: f as never });
    expect(r.next_interval_s).toBe(120);
    const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://api.example.test/api/v1/agent/heartbeat");
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>).authorization).toBe("Bearer ar_live_testkey");
    expect(JSON.parse(init.body as string).version).toBe(1);
  });

  it("maps statuses: 401 permanent, 409 and 422 permanent, 429 with Retry-After, 5xx retryable", async () => {
    const rejects = async (status: number, headers = {}) =>
      postHeartbeat(cfg(), body(), { fetchImpl: (async () => resp(status, { error: { code: "x" } }, headers)) as never }).catch((e) => e as HeartbeatError);
    const e401 = await rejects(401);
    expect(e401).toBeInstanceOf(HeartbeatError);
    expect([e401.status, e401.retryable]).toEqual([401, false]);
    expect((await rejects(409)).retryable).toBe(false);
    expect((await rejects(422)).retryable).toBe(false);
    const e429 = await rejects(429, { "retry-after": "90" });
    expect([e429.retryable, e429.retryAfterMs]).toEqual([true, 90_000]);
    expect((await rejects(429, { "retry-after": "junk" })).retryAfterMs).toBeNull();
    expect((await rejects(429, { "retry-after": "999999" })).retryAfterMs).toBe(3_600_000);
    expect((await rejects(503)).retryable).toBe(true);
    expect((await rejects(408)).retryable).toBe(true);
  });

  it("turns a network error and a timeout into retryable status 0", async () => {
    const net = await postHeartbeat(cfg(), body(), {
      fetchImpl: (async () => { throw new TypeError("fetch failed"); }) as never,
    }).catch((e) => e as HeartbeatError);
    expect([net.status, net.retryable, net.message]).toEqual([0, true, "network error"]);
    const slow = await postHeartbeat(cfg(), body(), {
      timeoutMs: 20,
      fetchImpl: ((_u: string, init: RequestInit) =>
        new Promise((_res, rej) => {
          init.signal!.addEventListener("abort", () => rej(init.signal!.reason));
        })) as never,
    }).catch((e) => e as HeartbeatError);
    expect([slow.status, slow.message]).toEqual([0, "timeout"]);
  });

  it("rejects a 200 with a bad body as retryable, and refuses to send when not linked", async () => {
    const bad = await postHeartbeat(cfg(), body(), { fetchImpl: (async () => resp(200)) as never }).catch((e) => e as HeartbeatError);
    expect([bad.status, bad.retryable]).toEqual([502, true]);
    const wrong = await postHeartbeat(cfg(), body(), { fetchImpl: (async () => resp(200, { ok: false })) as never }).catch((e) => e as HeartbeatError);
    expect(wrong.status).toBe(502);
    const f = vi.fn();
    const unlinked = await postHeartbeat(cfg({ apiKey: undefined }), body(), { fetchImpl: f as never }).catch((e) => e as HeartbeatError);
    expect(unlinked.status).toBe(401);
    expect(f).not.toHaveBeenCalled();
  });
});

describe("HeartbeatScheduler", () => {
  function sched(send: (c: AgentConfig, b: HeartbeatBody) => Promise<HeartbeatResponseBody>, extra: Partial<ConstructorParameters<typeof HeartbeatScheduler>[0]> = {}) {
    const logs: string[] = [];
    const s = new HeartbeatScheduler({ now: () => clock, random: () => 0, config: () => cfg(), enabled: () => true, send, log: (l) => logs.push(l), ...extra });
    return { s, logs };
  }

  it("sends, adopts the server interval, and is not due again until then", async () => {
    const send = vi.fn(async () => okRes(120));
    const { s } = sched(send);
    expect(await s.tick()).toEqual({ kind: "sent", gapsAcknowledged: 0 });
    expect(s.nextDueAt).toBe(T0 + 120_000);
    clock += 119_000;
    expect(await s.tick()).toEqual({ kind: "skipped", reason: "not_due" });
    expect(send).toHaveBeenCalledTimes(1);
    clock += 1_000;
    expect((await s.tick()).kind).toBe("sent");
    expect(getMeta(META_HB_INTERVAL_S)).toBe("120");
    expect(getMeta(META_HB_LAST_OK_AT)).toBe(String(clock));
  });

  it("clamps a hostile server interval", async () => {
    const { s } = sched(async () => okRes(1));
    await s.tick();
    expect(s.nextDueAt).toBe(T0 + 30_000);
    const { s: s2 } = sched(async () => okRes(10 ** 9));
    await s2.tick();
    expect(s2.nextDueAt).toBe(T0 + 900_000);
  });

  it("acknowledges gaps only after a 200, so a failed beat loses nothing", async () => {
    makeGaps(3);
    let fail = true;
    const sent: HeartbeatBody[] = [];
    const { s } = sched(async (_c, b) => {
      sent.push(b);
      if (fail) throw new HeartbeatError("http-503", 503);
      return okRes(60, b.hook_gaps.length);
    });
    expect((await s.tick()).kind).toBe("failed");
    expect(countUnreportedGaps()).toBe(3);
    fail = false;
    clock += 10 * 60_000;
    expect(await s.tick()).toEqual({ kind: "sent", gapsAcknowledged: 3 });
    expect(countUnreportedGaps()).toBe(0);
    expect(sent[1]!.hook_gaps.map((g) => g.tool_use_id)).toEqual(sent[0]!.hook_gaps.map((g) => g.tool_use_id));
  });

  it("sends more than 50 gaps over several beats without duplicates", async () => {
    makeGaps(120);
    const seen: string[] = [];
    const { s } = sched(async (_c, b) => {
      seen.push(...b.hook_gaps.map((g) => g.tool_use_id));
      return okRes(60);
    });
    await s.tick();
    expect(s.nextDueAt).toBe(T0 + HEARTBEAT_CATCHUP_MS);
    clock += HEARTBEAT_CATCHUP_MS;
    await s.tick();
    clock += HEARTBEAT_CATCHUP_MS;
    await s.tick();
    expect(seen).toHaveLength(120);
    expect(new Set(seen).size).toBe(120);
    expect(countUnreportedGaps()).toBe(0);
    expect(s.nextDueAt).toBe(clock + 60_000);
  });

  it("server unreachable: exponential backoff with jitter, capped, then recovers", async () => {
    let up = false;
    const { s } = sched(
      async () => {
        if (!up) throw new HeartbeatError("network error", 0);
        return okRes(60);
      },
      { random: () => 0.5 },
    );
    const waits: number[] = [];
    for (let i = 0; i < 8; i += 1) {
      const r = await s.tick();
      expect(r.kind).toBe("failed");
      waits.push((r as { retryInMs: number }).retryInMs);
      clock = s.nextDueAt;
    }
    // base 60s * 2^n with +12.5% jitter at random=0.5, capped at 15 min
    expect(waits.slice(0, 4)).toEqual([67_500, 135_000, 270_000, 540_000]);
    expect(waits.slice(4).every((w) => w === HEARTBEAT_BACKOFF_MAX_MS)).toBe(true);
    expect(getMeta(META_HB_FAILURES)).toBe("8");
    up = true;
    expect((await s.tick()).kind).toBe("sent");
    expect(getMeta(META_HB_FAILURES)).toBe("0");
    expect(s.nextDueAt).toBe(clock + 60_000);
  });

  it("never retries faster than the minimum interval and honours Retry-After", async () => {
    const { s } = sched(async () => { throw new HeartbeatError("http-429", 429, 300_000); });
    const r = await s.tick();
    expect((r as { retryInMs: number }).retryInMs).toBe(300_000);
    const { s: s2 } = sched(async () => { throw new HeartbeatError("http-429", 429, 1); }, { random: () => 0 });
    const r2 = await s2.tick();
    expect((r2 as { retryInMs: number }).retryInMs).toBe(60_000);
  });

  it("stops on 401 until the API key changes, and says so once", async () => {
    let key = "ar_live_old";
    const send = vi.fn(async () => { throw new HeartbeatError("http-401", 401); });
    const { s, logs } = sched(send, { config: () => cfg({ apiKey: key }) });
    expect((await s.tick()).kind).toBe("failed");
    clock += 3_600_000;
    expect(await s.tick()).toEqual({ kind: "skipped", reason: "key_rejected" });
    clock += 3_600_000;
    expect(await s.tick()).toEqual({ kind: "skipped", reason: "key_rejected" });
    expect(send).toHaveBeenCalledTimes(1);
    expect(logs).toHaveLength(1);
    key = "ar_live_new";
    send.mockImplementationOnce(async () => okRes(60) as never);
    expect((await s.tick()).kind).toBe("sent");
  });

  it("on 409 keeps the normal interval and logs once; on 422 the next beat drops the gaps", async () => {
    makeGaps(2);
    const bodies: HeartbeatBody[] = [];
    let status = 422;
    const { s, logs } = sched(async (_c, b) => {
      bodies.push(b);
      if (status) throw new HeartbeatError(`http-${status}`, status);
      return okRes(60);
    });
    const r = await s.tick();
    expect(r).toMatchObject({ kind: "failed", status: 422, retryInMs: 60_000 });
    clock += 60_000;
    status = 0;
    await s.tick();
    expect(bodies[0]!.hook_gaps).toHaveLength(2);
    expect(bodies[1]!.hook_gaps).toHaveLength(0);
    expect(countUnreportedGaps()).toBe(2);
    expect(logs).toHaveLength(1);
    const { s: s409, logs: l409 } = sched(async () => { throw new HeartbeatError("http-409", 409); });
    await s409.tick();
    clock = s409.nextDueAt;
    await s409.tick();
    expect(l409).toHaveLength(1);
    expect(s409.nextDueAt).toBe(clock + 60_000);
  });

  it("skips when disabled or not linked, and never throws when building the body fails", async () => {
    const send = vi.fn(async () => okRes());
    expect((await sched(send, { enabled: () => false }).s.tick())).toEqual({ kind: "skipped", reason: "disabled" });
    expect((await sched(send, { config: () => cfg({ apiKey: undefined }) }).s.tick())).toEqual({ kind: "skipped", reason: "unlinked" });
    expect(send).not.toHaveBeenCalled();
    const boom = sched(send, { config: () => { throw new Error("config read failed"); } }).s;
    const r = await boom.tick();
    expect(r).toMatchObject({ kind: "failed", status: -1 });
    expect(boom.nextDueAt).toBe(T0 + 30_000);
  });

  it("treats a non-HeartbeatError from send as a retryable network failure", async () => {
    const { s } = sched(async () => { throw new Error("weird"); });
    expect(await s.tick()).toMatchObject({ kind: "failed", status: 0 });
  });

  it("the daemon helper swallows anything", async () => {
    const broken = { tick: async () => { throw new Error("x"); } } as unknown as HeartbeatScheduler;
    await expect(runHeartbeatTick(broken)).resolves.toBeUndefined();
  });
});

describe("stale heartbeat and a dead daemon", () => {
  const setLast = (ms: number, interval = 60) => {
    getDb().prepare(`INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)`).run(META_HB_LAST_OK_AT, String(ms));
    getDb().prepare(`INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)`).run(META_HB_INTERVAL_S, String(interval));
  };

  it("never, live, stale and missing at the server's thresholds", () => {
    expect(heartbeatHealth(T0).liveness).toBe("never");
    setLast(T0);
    const live = HEARTBEAT_LIVE_INTERVALS * 60 * 1000;
    expect(heartbeatHealth(T0 + live).liveness).toBe("live");
    expect(heartbeatHealth(T0 + live + 1).liveness).toBe("stale");
    expect(heartbeatHealth(T0 + HEARTBEAT_MISSING_AFTER_S * 1000).liveness).toBe("stale");
    expect(heartbeatHealth(T0 + HEARTBEAT_MISSING_AFTER_S * 1000 + 1).liveness).toBe("missing");
  });

  it("scales with the server interval and survives corrupt meta", () => {
    setLast(T0, 300);
    expect(heartbeatHealth(T0 + 800_000).liveness).toBe("live");
    getDb().prepare(`INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)`).run(META_HB_LAST_OK_AT, "garbage");
    expect(heartbeatHealth(T0).liveness).toBe("never");
  });

  it("when the daemon dies the beats stop and status says stale, with the daemon not running", async () => {
    const { s } = (() => {
      const s = new HeartbeatScheduler({ now: () => clock, config: () => cfg(), enabled: () => true, send: async () => okRes(60), log: () => {} });
      return { s };
    })();
    await s.tick();
    expect(heartbeatHealth(clock + 30_000).liveness).toBe("live");
    // The daemon is killed: no more ticks.
    const later = clock + 10 * 60_000;
    expect(heartbeatHealth(later).liveness).toBe("stale");
    const text = heartbeatStatusLines(false, later).join("\n");
    expect(text).toMatch(/stale/);
    expect(text).toMatch(/daemon is not running/);
    expect(text).toMatch(/uncovered/);
    expect(heartbeatStatusLines(true, later).join("\n")).toMatch(/unreachable or rejecting/);
  });

  it("status shows the last error and the failure count after the server went away", async () => {
    const s = new HeartbeatScheduler({ now: () => clock, config: () => cfg(), enabled: () => true, send: async () => okRes(60), log: () => {} });
    await s.tick();
    const down = new HeartbeatScheduler({
      now: () => clock + 5 * 60_000,
      config: () => cfg(), enabled: () => true,
      send: async () => { throw new HeartbeatError("network error", 0); },
      log: () => {},
    });
    clock += 5 * 60_000;
    await down.tick();
    const text = heartbeatStatusLines(true, clock).join("\n");
    expect(text).toMatch(/stale/);
    expect(text).toMatch(/last error: network error/);
    expect(watcherStatusLines(true, clock).join("\n")).toMatch(/heartbeat:/);
  });

  it("never sent: status says to start the daemon", () => {
    expect(heartbeatStatusLines(false, T0).join("")).toMatch(/never sent/);
    expect(heartbeatStatusLines(true, T0).join("")).toMatch(/none sent yet/);
  });
});

describe("gaps reported through the scheduler are the watcher's gaps", () => {
  it("round trips ids through listUnreportedGaps", async () => {
    makeGaps(2);
    const ids = listUnreportedGaps().map((g) => g.tool_use_id);
    const sent: string[] = [];
    const s = new HeartbeatScheduler({
      now: () => clock,
      config: () => cfg(), enabled: () => true,
      send: async (_c, b) => { sent.push(...b.hook_gaps.map((g) => g.tool_use_id)); return okRes(60); },
      log: () => {},
    });
    await s.tick();
    expect(sent).toEqual(ids);
    expect(listUnreportedGaps()).toEqual([]);
  });
});
