import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { closeDb } from "../src/db.js";
import { readConfig, writeConfig, type AgentConfig } from "../src/config.js";
import { writeCachedPolicyAtomic } from "../src/policy/cache.js";
import type { Policy } from "../src/policy/types.js";
import {
  HeartbeatScheduler,
  heartbeatDecision,
  isOrgLinked,
  type HeartbeatBody,
  type HeartbeatResponseBody,
} from "../src/heartbeat/heartbeat.js";
import { heartbeatCommand } from "../src/commands/heartbeat.js";
import { formatDoctorReport, inspectDoctorState } from "../src/commands/doctor.js";
import { heartbeatStatusLines } from "../src/commands/status.js";
import { resetWatcherSchemaFlag } from "../src/watcher/transcript.js";

let home: string;
let suiteHome: string;
let savedEnv: string | undefined;
const T0 = 1_800_000_000_000;

beforeEach(() => {
  suiteHome = process.env.HOME!;
  savedEnv = process.env.AGENTREEL_HEARTBEAT;
  delete process.env.AGENTREEL_HEARTBEAT;
  home = mkdtempSync(join(tmpdir(), "ar-hbd-"));
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  closeDb();
  resetWatcherSchemaFlag();
});

afterEach(() => {
  closeDb();
  resetWatcherSchemaFlag();
  process.env.HOME = suiteHome;
  process.env.USERPROFILE = suiteHome;
  if (savedEnv === undefined) delete process.env.AGENTREEL_HEARTBEAT;
  else process.env.AGENTREEL_HEARTBEAT = savedEnv;
  rmSync(home, { recursive: true, force: true });
  vi.restoreAllMocks();
});

const cfg = (over: Partial<AgentConfig> = {}): AgentConfig => ({
  apiBaseUrl: "https://api.example.test/",
  apiKey: "ar_live_testkey",
  schemaVersion: 1,
  ...over,
});

function cachePolicy(over: Partial<Policy>): void {
  const policy: Policy = {
    version: 1,
    etag: "e1",
    workspace_id: "ws_1",
    updated_at: "2026-11-27T00:00:00Z",
    mode: "observe",
    offline: "last_known",
    builtin: {},
    custom: [],
    allow: { commands: [], paths: [], repos: [] },
    ...over,
  };
  writeCachedPolicyAtomic({ policy, etag: "e1", fetched_at: T0 });
}

const ORG = { org_id: "org_acme", workspace_id: "org_acme", org_slug: "acme" } as const;
const PERSONAL = { org_id: null } as const;

describe("heartbeat default: on only for org-linked devices", () => {
  it("case 1: org-linked device beats by default", () => {
    cachePolicy(ORG);
    expect(isOrgLinked(cfg())).toBe(true);
    expect(heartbeatDecision(cfg(), {})).toMatchObject({ enabled: true, reason: "org_default", orgLinked: true });
  });

  it("case 2: personal install (policy with org_id null) is off by default", () => {
    cachePolicy(PERSONAL);
    expect(isOrgLinked(cfg())).toBe(false);
    expect(heartbeatDecision(cfg(), {})).toMatchObject({ enabled: false, reason: "off_by_default" });
  });

  it("case 2b: no cached policy at all is off by default, and a stale personal config stays off", () => {
    expect(isOrgLinked(cfg())).toBe(false);
    expect(heartbeatDecision(cfg(), {}).enabled).toBe(false);
  });

  it("case 3: a personal install can opt in with config", () => {
    cachePolicy(PERSONAL);
    expect(heartbeatDecision(cfg({ heartbeat: true }), {})).toMatchObject({ enabled: true, reason: "opt_in" });
  });

  it("case 4: AGENTREEL_HEARTBEAT=0 overrides the org default and an opt-in, for every off value", () => {
    cachePolicy(ORG);
    for (const v of ["0", "false", "no", "off"]) {
      expect(heartbeatDecision(cfg(), { AGENTREEL_HEARTBEAT: v } as never)).toMatchObject({
        enabled: false,
        reason: "disabled_by_env",
      });
      expect(heartbeatDecision(cfg({ heartbeat: true }), { AGENTREEL_HEARTBEAT: v } as never).enabled).toBe(false);
    }
    // Other values do not switch it off.
    expect(heartbeatDecision(cfg(), { AGENTREEL_HEARTBEAT: "1" } as never).enabled).toBe(true);
  });

  it("an explicit `heartbeat off` wins over the org default", () => {
    cachePolicy(ORG);
    expect(heartbeatDecision(cfg({ heartbeat: false }), {})).toMatchObject({ enabled: false, reason: "opted_out" });
  });

  it("no API key means off, whatever else is set", () => {
    cachePolicy(ORG);
    expect(heartbeatDecision(cfg({ apiKey: undefined, heartbeat: true }), {})).toMatchObject({
      enabled: false,
      reason: "not_linked",
    });
  });

  it("the env switch is reported before the missing key", () => {
    expect(heartbeatDecision(cfg({ apiKey: undefined }), { AGENTREEL_HEARTBEAT: "0" } as never).reason).toBe("disabled_by_env");
  });

  it("org linkage also comes from the config orgSlug", () => {
    expect(isOrgLinked(cfg({ orgSlug: "acme" }))).toBe(true);
  });

  it("a corrupt policy cache counts as not org-linked, never throws", () => {
    cachePolicy(ORG);
    const p = join(home, ".agentreel", "policy.json");
    expect(existsSync(p)).toBe(true);
    writeFileSync(p, "{not json");
    expect(isOrgLinked(cfg())).toBe(false);
  });
});

describe("the scheduler uses the default", () => {
  const ok: HeartbeatResponseBody = { ok: true, server_time: new Date(T0).toISOString(), next_interval_s: 60, gaps_recorded: 0 };
  const make = (config: AgentConfig) => {
    const send = vi.fn(async (_c: AgentConfig, _b: HeartbeatBody) => ok);
    let clock = T0;
    const s = new HeartbeatScheduler({ now: () => clock, random: () => 0, config: () => config, send });
    return { s, send, tick: (ms = 0) => ((clock += ms), s.tick()) };
  };

  it("beats for an org-linked device with no setting", async () => {
    cachePolicy(ORG);
    const { send, tick } = make(cfg());
    expect((await tick()).kind).toBe("sent");
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("does not beat, and sends nothing, for a personal install", async () => {
    cachePolicy(PERSONAL);
    const { send, tick } = make(cfg());
    expect(await tick()).toEqual({ kind: "skipped", reason: "disabled" });
    expect(send).not.toHaveBeenCalled();
  });

  it("beats once a personal install opts in", async () => {
    cachePolicy(PERSONAL);
    const { send, tick } = make(cfg({ heartbeat: true }));
    expect((await tick()).kind).toBe("sent");
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("AGENTREEL_HEARTBEAT=0 stops an org-linked device", async () => {
    cachePolicy(ORG);
    process.env.AGENTREEL_HEARTBEAT = "0";
    const { send, tick } = make(cfg());
    expect(await tick()).toEqual({ kind: "skipped", reason: "disabled" });
    expect(send).not.toHaveBeenCalled();
  });

  it("picks up a policy sync or opt-in within the recheck window, without reading config every loop", async () => {
    cachePolicy(PERSONAL);
    const { send, tick, s } = make(cfg());
    expect(await tick()).toEqual({ kind: "skipped", reason: "disabled" });
    expect(s.nextDueAt).toBe(T0 + 30_000);
    expect(await tick(1_000)).toEqual({ kind: "skipped", reason: "not_due" });
    cachePolicy(ORG); // the daemon synced an org policy
    expect(await tick(1_000)).toEqual({ kind: "skipped", reason: "not_due" });
    expect((await tick(30_000)).kind).toBe("sent");
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("an unlinked install still reports unlinked", async () => {
    const { tick } = make(cfg({ apiKey: undefined }));
    expect(await tick()).toEqual({ kind: "skipped", reason: "unlinked" });
  });
});

describe("agentreel heartbeat on|off|status", () => {
  const out = () => {
    const lines: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...a: unknown[]) => void lines.push(a.join(" ")));
    vi.spyOn(console, "error").mockImplementation((...a: unknown[]) => void lines.push(a.join(" ")));
    return lines;
  };

  it("on and off persist in the config and keep other settings", () => {
    writeConfig(cfg({ hostnameMode: "hash" }));
    out();
    heartbeatCommand("on");
    expect(readConfig().heartbeat).toBe(true);
    expect(readConfig().hostnameMode).toBe("hash");
    heartbeatCommand("off");
    expect(readConfig().heartbeat).toBe(false);
  });

  it("on warns when AGENTREEL_HEARTBEAT=0 still wins, and when there is no key", () => {
    writeConfig(cfg({ apiKey: undefined }));
    process.env.AGENTREEL_HEARTBEAT = "0";
    const lines = out();
    heartbeatCommand("on");
    const text = lines.join("\n");
    expect(text).toContain("AGENTREEL_HEARTBEAT=0");
    expect(text).toContain("agentreel link");
  });

  it("off tells an org device it will show as uncovered", () => {
    writeConfig(cfg());
    const lines = out();
    heartbeatCommand("off");
    expect(lines.join("\n")).toContain("uncovered");
  });

  it("status explains the state and what is sent, Claude Code only", () => {
    writeConfig(cfg());
    cachePolicy(ORG);
    const lines = out();
    heartbeatCommand("status");
    const text = lines.join("\n");
    expect(text).toContain("org default");
    expect(text).toContain("counts, states and gaps only");
    expect(text).toContain("Never command text");
    expect(text).toContain("Claude Code only");
    expect(text).not.toMatch(/cursor/i);
  });

  it("rejects an unknown action without changing anything", () => {
    writeConfig(cfg());
    const lines = out();
    heartbeatCommand("maybe");
    expect(process.exitCode).toBe(1);
    process.exitCode = 0;
    expect(lines.join("\n")).toContain("Usage: agentreel heartbeat [on|off|status]");
    expect(readConfig().heartbeat).toBeUndefined();
  });
});

describe("agentreel doctor and status show the state and the reason", () => {
  const doctor = (config: AgentConfig, env: NodeJS.ProcessEnv = {}) =>
    formatDoctorReport(
      inspectDoctorState({
        config,
        env,
        claudeSettingsPath: join(home, "none-claude.json"),
        cursorHooksPath: join(home, "none-cursor.json"),
      }),
    );
  // strip ANSI colour codes
  const plain = (s: string) => s.replace(new RegExp(String.fromCharCode(27) + "\\[[0-9;]*m", "g"), "");
  const hbLine = (s: string) => plain(s).split("\n").find((l) => l.includes("heartbeat:")) ?? "";

  it("org default", () => {
    cachePolicy(ORG);
    expect(hbLine(doctor(cfg()))).toContain("on (org default");
  });

  it("opt-in", () => {
    cachePolicy(PERSONAL);
    expect(hbLine(doctor(cfg({ heartbeat: true })))).toContain("on (you opted in");
  });

  it("personal, not opted in", () => {
    cachePolicy(PERSONAL);
    expect(hbLine(doctor(cfg()))).toContain("off (personal install; opt in with `agentreel heartbeat on`)");
  });

  it("disabled by env", () => {
    cachePolicy(ORG);
    expect(hbLine(doctor(cfg(), { AGENTREEL_HEARTBEAT: "0" }))).toContain("off (AGENTREEL_HEARTBEAT=0 is set)");
  });

  it("states the payload limit and Claude Code only, and never claims Cursor gap detection", () => {
    cachePolicy(ORG);
    const text = plain(doctor(cfg()));
    expect(text).toContain("counts, states and gaps only; never command text");
    expect(text).toContain("Hook-gap detection: Claude Code only");
    const gapLines = text.split("\n").filter((l) => /gap/i.test(l)).join("\n");
    expect(gapLines).not.toMatch(/cursor/i);
  });

  it("status shows why the heartbeat is off for a personal install, and says nothing about Cursor gaps", () => {
    writeConfig(cfg());
    cachePolicy(PERSONAL);
    const lines = plain(heartbeatStatusLines(true).join("\n"));
    expect(lines).toContain("off (personal install");
    expect(lines).not.toMatch(/cursor/i);
  });

  it("status reports env-off even when org-linked", () => {
    writeConfig(cfg());
    cachePolicy(ORG);
    process.env.AGENTREEL_HEARTBEAT = "0";
    expect(plain(heartbeatStatusLines(true).join("\n"))).toContain("AGENTREEL_HEARTBEAT=0");
  });
});

describe("docs say what is sent, and Claude Code only", () => {
  const root = join(__dirname, "..", "..", "..");
  const read = (p: string) => readFileSync(join(root, p), "utf8");

  it("docs/heartbeat.md documents the payload, the default and the switches", () => {
    const d = read("docs/heartbeat.md");
    expect(d).toContain("Claude Code only");
    expect(d).toContain("Never command text");
    for (const k of ["org_default", "opt-in", "AGENTREEL_HEARTBEAT=0", "agentreel heartbeat on", "agentreel doctor"]) {
      expect(d).toContain(k);
    }
    expect(d).toMatch(/migration|0024/i);
  });

  it("README and docs/heartbeat.md state counts and gaps only, the default, and Claude Code only", () => {
    const r = read("README.md");
    const bullet = r.split("\n").find((l) => l.startsWith("- **Heartbeat and hook gaps**")) ?? "";
    expect(bullet).toContain("counts and gaps only");
    expect(bullet).toContain("Claude Code only");
    expect(bullet).toContain("org");
    expect(bullet).toContain("agentreel heartbeat on");
    expect(bullet).not.toMatch(/cursor/i);
    // Customer-facing CHANGELOG entries are written by Salmon; the
    // technical contract is in README and docs/heartbeat.md.
    const d = read("docs/heartbeat.md");
    expect(d).toContain("Claude Code only");
    expect(d).toContain("Never command text");
    expect(d).toContain("agentreel heartbeat on");
    expect(d).toContain("AGENTREEL_HEARTBEAT=0");
  });
});
