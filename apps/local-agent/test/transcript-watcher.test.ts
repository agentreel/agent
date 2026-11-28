import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { appendFileSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, truncateSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { closeDb, getMeta, insertEvent } from "../src/db.js";
import { writeConfig } from "../src/config.js";
import { handleClaudeHookInput } from "../src/hooks/handler.js";
import { runTranscriptScan } from "../src/commands/daemon.js";
import { watcherStatusLines } from "../src/commands/status.js";
import { uninstallCommand } from "../src/commands/auth.js";
import {
  DEFAULT_GRACE_MS,
  META_WATCHER_STATE,
  TranscriptWatcher,
  WATCHER_STALE_AFTER_MS,
  countUnreportedGaps,
  defaultProjectsDir,
  extractToolUses,
  getWatcherTotals,
  listUnreportedGaps,
  markGapsReported,
  realIo,
  resetWatcherSchemaFlag,
  transcriptWatchEnabled,
  watcherHealth,
  type WatcherIo,
} from "../src/watcher/transcript.js";

let home: string;
let projects: string;
let suiteHome: string;
let clock: number;
const now = () => clock;

beforeEach(() => {
  suiteHome = process.env.HOME!;
  home = mkdtempSync(join(tmpdir(), "ar-tw-"));
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  closeDb();
  resetWatcherSchemaFlag();
  projects = join(home, ".claude", "projects");
  mkdirSync(join(projects, "proj-a"), { recursive: true });
  clock = 1_800_000_000_000;
});

afterEach(() => {
  closeDb();
  resetWatcherSchemaFlag();
  process.env.HOME = suiteHome;
  process.env.USERPROFILE = suiteHome;
  rmSync(home, { recursive: true, force: true });
  vi.restoreAllMocks();
});

const tu = (id: string, name = "Bash", session = "sess-1", ts = "2026-11-27T21:00:00.000Z") =>
  JSON.stringify({
    type: "assistant",
    sessionId: session,
    timestamp: ts,
    message: { content: [{ type: "text", text: "ok".repeat(200) }, { type: "tool_use", id, name, input: { command: "rm -rf /secret" } }] },
  }) + "\n";

const file = (name = "s1.jsonl") => join(projects, "proj-a", name);

function mk(over: Partial<ConstructorParameters<typeof TranscriptWatcher>[0]> = {}) {
  return new TranscriptWatcher({ projectsDir: projects, now, ...over });
}

function hookEvent(toolUseId: string, type = "tool_use_pre") {
  insertEvent({
    id: `e-${type}-${toolUseId}`,
    sessionId: "sess-1",
    tool: "claude-code",
    type: type as never,
    ts: clock,
    payload: { tool_use_id: toolUseId, tool_name: "Bash" },
  });
}

/** Prime the watcher so later files count as new (the first scan skips history). */
function prime(w: TranscriptWatcher) {
  w.scan();
}

describe("extractToolUses", () => {
  it("reads tool_use blocks and ignores everything else", () => {
    expect(extractToolUses(tu("toolu_1"), "fallback")).toEqual([
      { id: "toolu_1", name: "Bash", sessionId: "sess-1", ts: Date.parse("2026-11-27T21:00:00.000Z") },
    ]);
    expect(extractToolUses(JSON.stringify({ type: "user", message: { content: [{ type: "tool_use", id: "x" }] } }), "f")).toEqual([]);
    expect(extractToolUses(JSON.stringify({ type: "assistant", message: { content: "text" } }), "f")).toEqual([]);
    expect(extractToolUses(JSON.stringify({ type: "assistant", message: { content: [{ type: "server_tool_use", id: "x" }] } }), "f")).toEqual([]);
  });

  it("returns null for malformed JSON and skips bad ids, defaulting name and session", () => {
    expect(extractToolUses("{not json", "f")).toBeNull();
    expect(extractToolUses("42", "f")).toBeNull();
    const long = "x".repeat(129);
    const line = JSON.stringify({ type: "assistant", message: { content: [{ type: "tool_use", id: long }, { type: "tool_use", id: "" }, { type: "tool_use", id: 7 }, { type: "tool_use", id: "ok1" }] } });
    expect(extractToolUses(line, "fallback-session")).toEqual([{ id: "ok1", name: "unknown", sessionId: "fallback-session", ts: null }]);
  });
});

describe("hook gap detection", () => {
  it("matches a tool call to the real PreToolUse hook event (scrubber keeps the id)", async () => {
    const w = mk();
    prime(w);
    const id = "toolu_01A09q90qw90lq917835lq9a";
    writeFileSync(file(), tu(id));
    await handleClaudeHookInput(
      "PreToolUse",
      { session_id: "sess-1", hook_event_name: "PreToolUse", tool_name: "Bash", tool_use_id: id, tool_input: { command: "ls" }, cwd: home } as never,
      { config: { apiBaseUrl: "http://x", schemaVersion: 1 } },
    );
    w.scan();
    clock += DEFAULT_GRACE_MS + 1;
    w.scan();
    expect(listUnreportedGaps()).toEqual([]);
    expect(getWatcherTotals()).toEqual({ tool_uses_seen: 1, hook_gaps_total: 0 });
  });

  it("records a gap when no hook event arrives, only after the grace period", () => {
    const w = mk();
    prime(w);
    writeFileSync(file(), tu("toolu_gap"));
    w.scan();
    clock += DEFAULT_GRACE_MS - 1;
    w.scan();
    expect(countUnreportedGaps()).toBe(0);
    clock += 2;
    const st = w.scan();
    expect(st.state).toBe("running");
    const gaps = listUnreportedGaps();
    expect(gaps).toHaveLength(1);
    expect(gaps[0]).toMatchObject({ tool_use_id: "toolu_gap", tool_name: "Bash", session_id: "sess-1", source: "claude-code" });
    expect(getWatcherTotals().hook_gaps_total).toBe(1);
    // Nothing about the command is kept.
    expect(JSON.stringify(gaps)).not.toContain("secret");
  });

  it("does not count a PostToolUse or a different id as a match", () => {
    const w = mk();
    prime(w);
    writeFileSync(file(), tu("toolu_a") + tu("toolu_b"));
    hookEvent("toolu_a", "tool_use_post");
    hookEvent("toolu_other");
    w.scan();
    clock += DEFAULT_GRACE_MS + 1;
    w.scan();
    expect(listUnreportedGaps().map((g) => g.tool_use_id).sort()).toEqual(["toolu_a", "toolu_b"]);
  });

  it("does not duplicate a gap across scans and stops listing it once reported", () => {
    const w = mk();
    prime(w);
    writeFileSync(file(), tu("toolu_gap"));
    w.scan();
    clock += DEFAULT_GRACE_MS + 1;
    w.scan();
    w.scan();
    w.scan();
    expect(getWatcherTotals()).toEqual({ tool_uses_seen: 1, hook_gaps_total: 1 });
    markGapsReported(["toolu_gap"], clock);
    expect(listUnreportedGaps()).toEqual([]);
    clock += 10;
    w.scan();
    expect(listUnreportedGaps()).toEqual([]);
  });

  it("does not judge history that existed before the first scan", () => {
    writeFileSync(file(), tu("toolu_old"));
    const w = mk();
    w.scan();
    clock += DEFAULT_GRACE_MS + 1;
    w.scan();
    expect(getWatcherTotals().tool_uses_seen).toBe(0);
    appendFileSync(file(), tu("toolu_new"));
    w.scan();
    clock += DEFAULT_GRACE_MS + 1;
    w.scan();
    expect(listUnreportedGaps().map((g) => g.tool_use_id)).toEqual(["toolu_new"]);
  });

  it("waits for a complete line and skips malformed lines without an error", () => {
    const w = mk();
    prime(w);
    const line = tu("toolu_partial");
    writeFileSync(file(), "{garbage\n" + line.slice(0, 40));
    let st = w.scan();
    expect(getWatcherTotals().tool_uses_seen).toBe(0);
    appendFileSync(file(), line.slice(40));
    st = w.scan();
    expect(getWatcherTotals().tool_uses_seen).toBe(1);
    expect(st.errors).toEqual({ permission_denied: 0, rotated_or_truncated: 0, unreadable: 0 });
  });

  it("reads subagent transcripts in nested folders and skips symlinks", () => {
    const w = mk();
    prime(w);
    mkdirSync(join(projects, "proj-a", "sess-1", "subagents"), { recursive: true });
    writeFileSync(join(projects, "proj-a", "sess-1", "subagents", "agent-1.jsonl"), tu("toolu_sub"));
    const outside = join(home, "outside.jsonl");
    writeFileSync(outside, tu("toolu_outside"));
    symlinkSync(outside, join(projects, "proj-a", "link.jsonl"));
    const st = w.scan();
    expect(st.files_watched).toBe(1);
    clock += DEFAULT_GRACE_MS + 1;
    w.scan();
    expect(listUnreportedGaps().map((g) => g.tool_use_id)).toEqual(["toolu_sub"]);
  });
});

describe("pause, uninstall and off switch", () => {
  it("does not judge anything written while capture is paused", () => {
    let paused = true;
    const w = mk({ isPaused: () => paused });
    prime(w);
    writeFileSync(file(), tu("toolu_during_pause"));
    expect(w.scan()).toMatchObject({ state: "idle", reason: "capture is paused" });
    paused = false;
    clock += DEFAULT_GRACE_MS + 1;
    w.scan();
    expect(listUnreportedGaps()).toEqual([]);
    appendFileSync(file(), tu("toolu_after"));
    w.scan();
    clock += DEFAULT_GRACE_MS + 1;
    w.scan();
    expect(listUnreportedGaps().map((g) => g.tool_use_id)).toEqual(["toolu_after"]);
  });

  it("stays idle when no hooks are expected, and reports no gaps", () => {
    let expected = false;
    const w = mk({ hooksExpected: () => expected });
    prime(w);
    writeFileSync(file(), tu("toolu_nohooks"));
    expect(w.scan()).toMatchObject({ state: "idle", reason: "hooks are not installed" });
    clock += DEFAULT_GRACE_MS + 1;
    w.scan();
    expect(countUnreportedGaps()).toBe(0);
    expected = true;
    clock += 1;
    expect(w.scan().state).toBe("running");
    expect(countUnreportedGaps()).toBe(0);
  });

  it("reports disabled and does not touch the transcript state when switched off", () => {
    const w = mk({ enabled: () => false });
    writeFileSync(file(), tu("toolu_x"));
    expect(w.scan()).toMatchObject({ state: "disabled", files_watched: 0 });
    expect(getWatcherTotals().tool_uses_seen).toBe(0);
    expect(transcriptWatchEnabled({ AGENTREEL_TRANSCRIPT_WATCH: "0" } as never)).toBe(false);
    expect(transcriptWatchEnabled({ AGENTREEL_TRANSCRIPT_WATCH: "off" } as never)).toBe(false);
    expect(transcriptWatchEnabled({} as never)).toBe(true);
  });

  it("agentreel uninstall clears the hooks-expected flag so the watcher goes idle", async () => {
    writeConfig({ apiBaseUrl: "http://x", schemaVersion: 1, hooksInstalled: true });
    vi.spyOn(console, "log").mockImplementation(() => {});
    await uninstallCommand();
    const { readConfig } = await import("../src/config.js");
    expect(readConfig().hooksInstalled).toBe(false);
  });
});

describe("rotated, truncated and deleted transcripts", () => {
  it("rereads a truncated file from the start and counts it", () => {
    const w = mk();
    prime(w);
    writeFileSync(file(), tu("toolu_1") + tu("toolu_2"));
    w.scan();
    truncateSync(file(), 0);
    writeFileSync(file(), tu("toolu_3"));
    const st = w.scan();
    expect(st.errors.rotated_or_truncated).toBe(1);
    expect(getWatcherTotals().tool_uses_seen).toBe(3);
  });

  it("detects a shorter rewrite that keeps the same first bytes (size shrank)", () => {
    const w = mk();
    prime(w);
    writeFileSync(file(), tu("toolu_1") + tu("toolu_2"));
    w.scan();
    writeFileSync(file(), tu("toolu_1"));
    const st = w.scan();
    expect(st.errors.rotated_or_truncated).toBe(1);
  });

  it("detects a replaced file even when it is now larger (head changed)", () => {
    const w = mk();
    prime(w);
    writeFileSync(file(), tu("toolu_1", "Bash", "sess-A"));
    w.scan();
    const bigger = tu("toolu_9", "Bash", "sess-B") + tu("toolu_10", "Bash", "sess-B") + tu("toolu_11", "Bash", "sess-B");
    writeFileSync(file(), bigger);
    const st = w.scan();
    expect(st.errors.rotated_or_truncated).toBeGreaterThanOrEqual(1);
    expect(getWatcherTotals().tool_uses_seen).toBe(4);
  });

  it("forgets a deleted transcript without throwing and keeps already seen calls", () => {
    const w = mk();
    prime(w);
    writeFileSync(file(), tu("toolu_1"));
    w.scan();
    unlinkSync(file());
    const st = w.scan();
    expect(st.state).toBe("running");
    expect(st.files_watched).toBe(0);
    expect(st.errors.rotated_or_truncated).toBe(1);
    clock += DEFAULT_GRACE_MS + 1;
    w.scan();
    // The call was seen before the file vanished, so it is still judged.
    expect(listUnreportedGaps().map((g) => g.tool_use_id)).toEqual(["toolu_1"]);
  });

  it("treats a missing projects dir as normal, not an error", () => {
    rmSync(projects, { recursive: true, force: true });
    const st = mk().scan();
    expect(st).toMatchObject({ state: "running", files_watched: 0 });
    expect(st.errors.unreadable + st.errors.permission_denied).toBe(0);
  });
});

describe("permission and I/O errors", () => {
  const eacces = () => Object.assign(new Error("EACCES: permission denied"), { code: "EACCES" });

  it("reports error state, counts permission_denied and does not throw when the projects dir is unreadable", () => {
    const io: WatcherIo = { ...realIo, readdir: () => { throw eacces(); } };
    const st = mk({ io }).scan();
    expect(st.state).toBe("error");
    expect(st.errors.permission_denied).toBe(1);
    expect(st.reason).toContain("EACCES");
    expect(st.reason).not.toContain(home);
  });

  it("counts an unreadable transcript, keeps the offset and recovers when access returns", () => {
    let deny = true;
    const io: WatcherIo = {
      ...realIo,
      read(p, pos, len) {
        if (deny && p.endsWith("s1.jsonl")) throw eacces();
        return realIo.read(p, pos, len);
      },
    };
    const w = mk({ io });
    prime(w);
    writeFileSync(file(), tu("toolu_locked"));
    const st = w.scan();
    expect(st.errors.permission_denied).toBe(1);
    expect(getWatcherTotals().tool_uses_seen).toBe(0);
    deny = false;
    w.scan();
    expect(getWatcherTotals().tool_uses_seen).toBe(1);
  });

  it("counts a stat failure and a non-permission read failure separately", () => {
    let mode: "stat" | "read" = "stat";
    const io: WatcherIo = {
      ...realIo,
      stat(p) {
        if (mode === "stat") throw eacces();
        return realIo.stat(p);
      },
      read(p, pos, len) {
        if (mode === "read") throw Object.assign(new Error("boom"), { code: "EIO" });
        return realIo.read(p, pos, len);
      },
    };
    const w = mk({ io });
    prime(w);
    writeFileSync(file(), tu("toolu_1"));
    expect(w.scan().errors.permission_denied).toBe(1);
    mode = "read";
    expect(w.scan().errors.unreadable).toBe(1);
  });

  it("never throws out of scan, even if the scan itself blows up", () => {
    const io: WatcherIo = { ...realIo, readdir: () => { throw new TypeError("weird"); } };
    const st = mk({ io }).scan();
    expect(st.state).toBe("error");
    expect(st.errors.unreadable).toBe(1);
  });
});

describe("daemon death and stale scans", () => {
  it("shows never, ok and stale from the persisted status", () => {
    expect(watcherHealth(clock).freshness).toBe("never");
    const w = mk();
    w.scan();
    expect(getMeta(META_WATCHER_STATE)).toBeTruthy();
    expect(watcherHealth(clock + 1000).freshness).toBe("ok");
    expect(watcherHealth(clock + WATCHER_STALE_AFTER_MS).freshness).toBe("ok");
    const stale = watcherHealth(clock + WATCHER_STALE_AFTER_MS + 1);
    expect(stale.freshness).toBe("stale");
    expect(stale.ageMs).toBe(WATCHER_STALE_AFTER_MS + 1);
  });

  it("status lines say the daemon is down when the last scan is stale and no daemon runs", () => {
    mk().scan();
    const later = clock + WATCHER_STALE_AFTER_MS + 60_000;
    const text = watcherStatusLines(false, later).join("\n");
    expect(text).toMatch(/stale/);
    expect(text).toMatch(/daemon is not running/);
    expect(watcherStatusLines(true, later).join("\n")).toMatch(/daemon is up but not scanning/);
  });

  it("status lines show open hook gaps", () => {
    const w = mk();
    prime(w);
    writeFileSync(file(), tu("toolu_g"));
    w.scan();
    clock += DEFAULT_GRACE_MS + 1;
    w.scan();
    expect(watcherStatusLines(true, clock).join("\n")).toMatch(/1 unreported/);
  });

  it("the daemon scan helper logs new gaps and swallows a failing watcher", () => {
    const w = mk();
    prime(w);
    writeFileSync(file(), tu("toolu_g"));
    w.scan();
    clock += DEFAULT_GRACE_MS + 1;
    const lines: string[] = [];
    expect(runTranscriptScan(w, (l) => lines.push(l))).toBe(1);
    expect(lines.join("")).toMatch(/hook gap/);
    expect(runTranscriptScan(w, (l) => lines.push(l))).toBe(0);
    const broken = { scan: () => { throw new Error("db locked"); } } as unknown as TranscriptWatcher;
    expect(runTranscriptScan(broken, () => {})).toBe(0);
  });
});

describe("projects dir resolution", () => {
  it("prefers AGENTREEL_CLAUDE_PROJECTS_DIR, then CLAUDE_CONFIG_DIR, then ~/.claude/projects", () => {
    expect(defaultProjectsDir({ AGENTREEL_CLAUDE_PROJECTS_DIR: "/a", CLAUDE_CONFIG_DIR: "/b" } as never)).toBe("/a");
    expect(defaultProjectsDir({ CLAUDE_CONFIG_DIR: "/b" } as never)).toBe("/b/projects");
    expect(defaultProjectsDir({} as never)).toBe(join(home, ".claude", "projects"));
  });
});
