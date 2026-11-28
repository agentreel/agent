import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { AgentConfig } from "../src/config.js";
import type { Policy } from "../src/policy/types.js";

const testHome = mkdtempSync(join(tmpdir(), "agentreel-db-order-"));
process.env.HOME = testHome;

const db = await import("../src/db.js");
const cache = await import("../src/policy/cache.js");
const claudeHandler = await import("../src/hooks/handler.js");
const cursorRunner = await import("../src/cursor/hook-runner.js");
const pathsMod = await import("../src/paths.js");

const arDir = join(testHome, ".agentreel");
const cachePath = join(arDir, "policy.json");
const guardConfigPath = join(arDir, "guard-config.json");

function enforcePolicy(): Policy {
  return {
    version: 1,
    etag: "etag-db-order",
    workspace_id: "ws_acme",
    org_name: "Acme Corp",
    org_slug: "acme",
    updated_at: "2026-11-27T00:00:00Z",
    mode: "enforce",
    offline: "last_known",
    builtin: { FS001: { enabled: true, action: "block", severity: "critical" } },
    custom: [],
    allow: { commands: [], paths: [], repos: [] },
  };
}

function config(): AgentConfig {
  return {
    apiBaseUrl: "http://127.0.0.1:1",
    installedHookTimeouts: { claude: 130, cursor: 130 },
    schemaVersion: 1,
  } as AgentConfig;
}

const deps = () => ({ cachePath, guardConfigPath, config: config() });

function claudePre(command: string) {
  return {
    session_id: "sess-db-order",
    hook_event_name: "PreToolUse",
    cwd: "/tmp/fixture-repo",
    tool_name: "Bash",
    tool_input: { command },
    tool_use_id: "toolu_1",
  };
}

function cursorShell(command: string) {
  return {
    conversation_id: "conv-db-order",
    generation_id: "gen-1",
    hook_event_name: "beforeShellExecution",
    cursor_version: "2.0.0-fixture",
    workspace_roots: ["/tmp/fixture-repo"],
    command,
    cwd: "/tmp/fixture-repo",
  };
}

type DbBreak = "corrupt" | "directory";

function breakDb(kind: DbBreak): void {
  db.closeDb();
  const p = pathsMod.dbPath();
  for (const suffix of ["", "-wal", "-shm"]) rmSync(p + suffix, { recursive: true, force: true });
  if (kind === "corrupt") writeFileSync(p, Buffer.from("this is not a sqlite database".repeat(100)));
  else mkdirSync(p, { recursive: true });
}

beforeEach(() => {
  db.closeDb();
  rmSync(arDir, { recursive: true, force: true });
  mkdirSync(arDir, { recursive: true });
  const policy = enforcePolicy();
  cache.writeCachedPolicyAtomic({ policy, etag: policy.etag, fetched_at: Date.now() }, cachePath);
});

afterEach(() => {
  db.closeDb();
});

describe("policy check runs before any DB write", () => {
  for (const kind of ["corrupt", "directory"] as const) {
    it(`Claude PreToolUse still denies rm -rf ~ when sessions.db is ${kind}`, async () => {
      breakDb(kind);
      const res = await claudeHandler.handleClaudeHookInput("PreToolUse", claudePre("rm -rf ~") as never, deps());
      expect(res.outcome?.permitted).toBe(false);
      expect(res.stdout).toContain('"permissionDecision":"deny"');
      // The DB failure is logged, not swallowed into an allow.
      expect(readFileSync(pathsMod.logPath(), "utf8")).toMatch(/hook error/);
    });

    it(`Cursor beforeShellExecution still denies rm -rf ~ when sessions.db is ${kind}`, async () => {
      breakDb(kind);
      const res = await cursorRunner.handleCursorHookInput(
        "beforeShellExecution",
        cursorShell("rm -rf ~") as never,
        deps(),
      );
      expect(res.decision?.permission).toBe("deny");
      expect(JSON.parse(res.response).permission).toBe("deny");
      expect(readFileSync(pathsMod.logPath(), "utf8")).toMatch(/cursor hook error/);
    });

    it(`a benign command is still allowed when sessions.db is ${kind}`, async () => {
      breakDb(kind);
      const claude = await claudeHandler.handleClaudeHookInput("PreToolUse", claudePre("ls -la") as never, deps());
      expect(claude.stdout).toBeNull();
      expect(claude.outcome?.permitted).toBe(true);
      const cursor = await cursorRunner.handleCursorHookInput(
        "beforeShellExecution",
        cursorShell("ls -la") as never,
        deps(),
      );
      expect(cursor.decision?.permission).toBe("allow");
    });
  }

  it("records the decision and then the event when the DB is healthy", async () => {
    const res = await claudeHandler.handleClaudeHookInput("PreToolUse", claudePre("rm -rf ~") as never, deps());
    expect(res.outcome?.permitted).toBe(false);
    const rows = db
      .getDb()
      .prepare(`SELECT type FROM events WHERE session_id = ? ORDER BY rowid`)
      .all("sess-db-order") as Array<{ type: string }>;
    expect(rows.map((r) => r.type)).toEqual(["policy_decision", "tool_use_pre"]);
  });

  it("does not open the DB at all before the decision (deny is decided with no DB handle)", async () => {
    // A path the DB can never open; if any write ran first it would throw
    // before enforcement and the old code turned that into an allow.
    breakDb("directory");
    expect(existsSync(pathsMod.dbPath())).toBe(true);
    const res = await cursorRunner.handleCursorHookInput(
      "preToolUse",
      { ...cursorShell(""), hook_event_name: "preToolUse", command: undefined, tool_name: "Shell", tool_input: { command: "rm -rf ~" } } as never,
      deps(),
    );
    expect(res.decision?.permission).toBe("deny");
  });
});
