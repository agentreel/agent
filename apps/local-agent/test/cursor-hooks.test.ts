import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const home = mkdtempSync(join(tmpdir(), "agentreel-cursor-"));
process.env.HOME = home;

const norm = await import("../src/cursor/hook-normalize.js");
const runner = await import("../src/cursor/hook-runner.js");
const install = await import("../src/cursor/hooks-install.js");
const db = await import("../src/db.js");

interface Step {
  delay_ms: number;
  hook: string;
  input: Record<string, unknown>;
}
const FIXTURE_ROOT = "/tmp/ar-cursor-e2e/acme-api";
let repo: string;
let steps: Step[];

beforeAll(() => {
  // A real git repo stands in for the fixture's workspace root.
  repo = mkdtempSync(join(tmpdir(), "acme-api-"));
  const g = (...a: string[]) => execFileSync("git", ["-C", repo, ...a], { stdio: "pipe" });
  g("init", "-q", "-b", "fix/ratelimit");
  g("config", "user.name", "Cursor Dev");
  g("config", "user.email", "cursor.dev@example.com");
  g("remote", "add", "origin", "https://ci-bot:hunter2hunter2@gitlab.example.com/acme/api.git");
  g("-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "init");
  const raw = readFileSync(new URL("./fixtures/cursor-hooks/session.jsonl", import.meta.url), "utf8");
  steps = raw
    .trim()
    .split("\n")
    .map((l) => JSON.parse(l.replaceAll(FIXTURE_ROOT, repo)) as Step);
});
afterAll(() => {
  db.closeDb();
  rmSync(home, { recursive: true, force: true });
  rmSync(repo, { recursive: true, force: true });
});

describe("normalizeCursorHook", () => {
  it("maps every fixture hook to an event", () => {
    let t = 1_700_000_000_000;
    const out = steps.map((s) => norm.normalizeCursorHook(s.hook, s.input as never, (t += s.delay_ms)));
    expect(out.every(Boolean)).toBe(true);
    expect(out.map((o) => o!.type)).toEqual([
      "session_start",
      "user_prompt_submit",
      "tool_use_post",
      "tool_use_post",
      "tool_use_post",
      "tool_use_post",
      "tool_use_post",
      "tool_use_post",
      "tool_use_post",
      "tool_use_post",
      "tool_use_post",
      "tool_use_post",
      "tool_use_post",
      "tool_use_post",
      "tool_use_post",
      "stop",
      "session_end",
    ]);
    expect(new Set(out.map((o) => o!.sessionId))).toEqual(new Set(["cursor-6f1c2a9e-3b7d-4f52-9a10-cc4e0b8d2f71"]));
  });

  it("parses Shell tool_output and keeps exit code, duration and tool_use_id", () => {
    const s = steps.find((x) => x.hook === "postToolUse" && (x.input.tool_name as string) === "Shell")!;
    const n = norm.normalizeCursorHook(s.hook, s.input as never, 1)!;
    expect(n.payload.tool_name).toBe("Shell");
    expect(n.payload.tool_use_id).toBe("toolu_c03");
    expect(n.payload.duration_ms).toBe(2310);
    expect((n.payload.tool_response as { exitCode: number }).exitCode).toBe(1);
    expect((n.payload.tool_input as { command: string }).command).toContain("vitest");
  });

  it("maps Read's target_file to file_path, MCP to MCP:<tool>, failures to is_error", () => {
    const read = norm.normalizeCursorHook("postToolUse", steps[2]!.input as never)!;
    expect((read.payload.tool_input as { file_path: string }).file_path).toMatch(/ratelimit\.ts$/);
    const mcp = norm.normalizeCursorHook("afterMCPExecution", steps.find((s) => s.hook === "afterMCPExecution")!.input as never)!;
    expect(mcp.payload.tool_name).toBe("MCP:search_issues");
    expect(mcp.payload.mcp_server_name).toBe("linear");
    expect(mcp.payload.tool_input).toEqual({ query: "ratelimit flaky" });
    const fail = norm.normalizeCursorHook("postToolUseFailure", steps.find((s) => s.hook === "postToolUseFailure")!.input as never)!;
    expect(fail.payload.tool_response).toMatchObject({ is_error: true, failure_type: "timeout" });
  });

  it("keeps only attachment paths from prompts and clips huge outputs", () => {
    const p = norm.normalizeCursorHook("beforeSubmitPrompt", {
      conversation_id: "c",
      prompt: "hi",
      attachments: [{ type: "file", file_path: "/a.ts", content: "SECRET" } as never],
    })!;
    expect(JSON.stringify(p.payload)).not.toContain("SECRET");
    const big = norm.normalizeCursorHook("afterShellExecution", { conversation_id: "c", command: "cat x", output: "y".repeat(50_000) })!;
    const out = (big.payload.tool_response as { output: string }).output;
    expect(out.length).toBeLessThan(17_000);
    expect(out).toContain("[truncated");
  });

  it("accepts Claude-style names from Cursor's third-party hook import", () => {
    expect(norm.canonicalHookName("PostToolUse")).toBe("postToolUse");
    expect(norm.canonicalHookName("UserPromptSubmit")).toBe("beforeSubmitPrompt");
    expect(norm.canonicalHookName("Stop")).toBe("stop");
  });

  it("answers with observe-only JSON for non-pre-exec hooks and permission JSON for pre-exec hooks", () => {
    expect(norm.cursorHookResponse("beforeSubmitPrompt")).toBe('{"continue":true}');
    expect(norm.cursorHookResponse("postToolUse")).toBe("{}");
    expect(norm.cursorHookResponse("afterShellExecution")).toBe("{}");
    expect(norm.cursorHookResponse("beforeShellExecution")).toBe('{"permission":"allow"}');
    expect(
      norm.cursorHookResponse("beforeShellExecution", {
        permission: "deny",
        user_message: "Blocked",
        agent_message: "Blocked",
      }),
    ).toBe('{"permission":"deny","user_message":"Blocked","agent_message":"Blocked"}');
  });
});

describe("recordCursorHook (fixture session into SQLite)", () => {
  it("stores events, attribution and redacts secrets", () => {
    let t = 1_700_000_000_000;
    for (const s of steps) runner.recordCursorHook(s.hook, s.input as never, (t += s.delay_ms));
    const sid = "cursor-6f1c2a9e-3b7d-4f52-9a10-cc4e0b8d2f71";
    const d = db.getDb();
    const sess = d.prepare(`SELECT * FROM sessions WHERE id = ?`).get(sid) as Record<string, unknown>;
    expect(sess.tool).toBe("cursor");
    expect(sess.ended_at).toBe(t);
    expect(sess.cwd).toBe(repo);
    const events = d.prepare(`SELECT payload FROM events WHERE session_id = ? ORDER BY ts`).all(sid) as Array<{ payload: string }>;
    expect(events).toHaveLength(17);
    const all = events.map((e) => e.payload).join("\n");
    expect(all).not.toContain("S3cr3tPass");
    expect(all).toContain("psql");

    const attr = db.getSessionAttribution<Record<string, any>>(sid)!;
    expect(attr.agent).toEqual({ tool: "cursor", version: "2.1.42", model: "claude-4.5-sonnet" });
    expect(attr.git.user_email).toBe("cursor.dev@example.com");
    expect(attr.git.remote_url).toBe("https://gitlab.example.com/acme/api.git");
    expect(attr.git.branch_start).toBe("fix/ratelimit");
    expect(attr.git.head_end).toBe(attr.git.head_start);
    expect(attr.os_user).toBeTruthy();
  });

  it("sends attribution with the session in the upload batch", async () => {
    const { takePendingBatch } = await import("../src/upload/queue.js");
    const batch = takePendingBatch(500, 1024 * 1024, Date.now());
    const s = batch.sessions.find((x) => x.tool === "cursor")!;
    expect((s.attribution as { agent: { tool: string } }).agent.tool).toBe("cursor");
    expect(batch.events.filter((e) => e.session_id === s.id)).toHaveLength(17);
  });
});

describe("hooks.json install", () => {
  it("adds our hooks, keeps others, is idempotent and uninstalls cleanly", () => {
    const dir = join(home, "cur");
    mkdirSync(dir, { recursive: true });
    const path = join(dir, "hooks.json");
    writeFileSync(
      path,
      JSON.stringify({ version: 1, hooks: { afterFileEdit: [{ command: "./hooks/format.sh" }] } }),
    );
    install.installCursorHooks("/usr/local/bin/agentreel", path);
    install.installCursorHooks("/usr/local/bin/agentreel", path);
    const f = JSON.parse(readFileSync(path, "utf8"));
    expect(f.version).toBe(1);
    expect(Object.keys(f.hooks).sort()).toEqual([...norm.CURSOR_HOOK_EVENTS].sort());
    expect(f.hooks.afterFileEdit).toEqual([
      { command: "./hooks/format.sh" },
      { command: "/usr/local/bin/agentreel cursor-hook afterFileEdit", timeout: 5 },
    ]);
    expect(f.hooks.postToolUse).toHaveLength(1);
    // pre-exec hooks get the long approval timeout (130s); other hooks keep 5s
    for (const k of ["preToolUse", "beforeShellExecution", "beforeMCPExecution", "beforeReadFile"]) {
      expect(f.hooks[k]).toEqual([
        { command: `/usr/local/bin/agentreel cursor-hook ${k}`, timeout: 130, failClosed: true },
      ]);
    }
    expect(f.hooks.beforeSubmitPrompt).toEqual([
      { command: "/usr/local/bin/agentreel cursor-hook beforeSubmitPrompt", timeout: 5 },
    ]);
    expect(runner.nativeCursorHooksInstalled(path)).toBe(true);
    const { removed } = install.uninstallCursorHooks(path);
    expect(removed).toBe(norm.CURSOR_HOOK_EVENTS.length);
    expect(JSON.parse(readFileSync(path, "utf8")).hooks).toEqual({ afterFileEdit: [{ command: "./hooks/format.sh" }] });
    expect(runner.nativeCursorHooksInstalled(path)).toBe(false);
  });

  it("detects Cursor payloads", () => {
    expect(runner.isCursorPayload({ cursor_version: "2.1.0" })).toBe(true);
    expect(runner.isCursorPayload({ session_id: "x", hook_event_name: "PostToolUse" })).toBe(false);
  });
});
