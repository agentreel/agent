import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import type { Policy } from "../src/policy/types.js";

const testHome = mkdtempSync(join(tmpdir(), "agentreel-fail-closed-"));
process.env.HOME = testHome;

const db = await import("../src/db.js");
const cache = await import("../src/policy/cache.js");
const enforce = await import("../src/policy/enforce.js");
const types = await import("../src/policy/types.js");
const claudeHandler = await import("../src/hooks/handler.js");
const cursorRunner = await import("../src/cursor/hook-runner.js");
const pathsMod = await import("../src/paths.js");

const arDir = join(testHome, ".agentreel");

function policy(overrides: Record<string, unknown> = {}): Policy {
  return {
    version: 1,
    etag: "etag-fc",
    workspace_id: "ws_acme",
    org_name: "Acme Corp",
    org_slug: "acme",
    updated_at: "2026-11-27T00:00:00Z",
    mode: "enforce",
    offline: "last_known",
    builtin: { FS001: { enabled: true, action: "block", severity: "critical" } },
    custom: [],
    allow: { commands: [], paths: [], repos: [] },
    ...overrides,
  } as Policy;
}

/** Writes the cache file raw (no validation), the way it sits on disk. */
function writeRawPolicy(p: Record<string, unknown>): void {
  writeFileSync(
    pathsMod.policyPath(),
    JSON.stringify({ policy: p, etag: "etag-fc", fetched_at: Date.now() }),
  );
}

async function claude(raw: string, eventArg = "PreToolUse"): Promise<string> {
  let out = "";
  await claudeHandler.runHook(eventArg, { readStdin: async () => raw, writeStdout: (s) => (out += s) });
  return out;
}

async function cursor(raw: string, eventArg = "beforeShellExecution"): Promise<Record<string, unknown>> {
  let out = "";
  await cursorRunner.runCursorHook(eventArg, { readStdin: async () => raw, writeStdout: (s) => (out += s) });
  return JSON.parse(out) as Record<string, unknown>;
}

function claudePayload(toolInput: unknown, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    session_id: "sess-fc",
    hook_event_name: "PreToolUse",
    cwd: "/tmp/fixture-repo",
    tool_name: "Bash",
    tool_input: toolInput,
    tool_use_id: "toolu_fc",
    ...extra,
  });
}

const DENY = '"permissionDecision":"deny"';

beforeEach(() => {
  db.closeDb();
  rmSync(arDir, { recursive: true, force: true });
  rmSync(join(testHome, ".cursor"), { recursive: true, force: true });
  mkdirSync(arDir, { recursive: true });
  writeFileSync(join(arDir, "config.json"), JSON.stringify({ apiBaseUrl: "http://127.0.0.1:1", schemaVersion: 1 }));
});

describe("unknown enum values read as the strictest known value", () => {
  it("maps unknown mode, offline, action, severity and offline_fallback strings", () => {
    const res = types.validatePolicy({
      ...policy(),
      mode: "lockdown",
      offline: "fail_closed",
      builtin: { FS001: { enabled: true, action: "quarantine", severity: "catastrophic" } },
      custom: [
        {
          id: "c1",
          name: "custom",
          enabled: true,
          version: 1,
          message: "m",
          when: [{ field: "command", op: "contains", value: "x" }],
          action: "nuke",
          severity: "extreme",
          approval: { offline_fallback: "ask" },
        },
      ],
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value.mode).toBe("enforce");
    expect(res.value.offline).toBe("last_known");
    expect(res.value.builtin.FS001).toMatchObject({ action: "block", severity: "critical" });
    expect(res.value.custom[0]).toMatchObject({ action: "block", severity: "critical" });
    expect(res.value.custom[0]!.approval?.offline_fallback).toBe("deny");
  });

  it("keeps known values unchanged", () => {
    const res = types.validatePolicy({ ...policy(), mode: "observe", offline: "fail_open" });
    expect(res.ok && res.value.mode).toBe("observe");
    expect(res.ok && res.value.offline).toBe("fail_open");
  });

  it("still rejects non-string enum values", () => {
    expect(types.validatePolicy({ ...policy(), mode: 1 }).ok).toBe(false);
    expect(types.validatePolicy({ ...policy(), offline: false }).ok).toBe(false);
    expect(
      types.validatePolicy({ ...policy(), builtin: { FS001: { enabled: true, action: null } } }).ok,
    ).toBe(false);
  });

  it("a cached policy with offline:\"fail_closed\" now denies instead of being dropped", async () => {
    writeRawPolicy({ ...policy(), offline: "fail_closed" });
    expect(cache.readCachedPolicy()).not.toBeNull();
    expect(await claude(claudePayload({ command: "rm -rf ~" }))).toContain(DENY);
  });
});

describe("internal errors fail closed under an enforcing policy", () => {
  it("denies with reason internal_error when the evaluator throws", async () => {
    const cachePath = pathsMod.policyPath();
    const p = policy();
    cache.writeCachedPolicyAtomic({ policy: p, etag: p.etag, fetched_at: Date.now() }, cachePath);
    const logs: string[] = [];
    const res = await enforce.enforcePreExec(
      { sessionId: "s", tool: "claude-code", toolName: "Bash", command: "ls" },
      {
        cachePath,
        config: { apiBaseUrl: "http://127.0.0.1:1", schemaVersion: 1 } as never,
        evaluateFn: () => {
          throw new Error("simulated evaluator crash");
        },
        log: (m) => logs.push(m),
        recordDecision: () => {},
      },
    );
    expect(res.permitted).toBe(false);
    expect(res.reason).toBe("internal_error");
    expect(res.message).toContain("Blocked by Acme Corp policy");
    expect(logs[0]).toContain("failing closed");
  });
});

describe("malformed Claude Code hook input", () => {
  it("denies malformed JSON on PreToolUse when an enforcing policy is cached", async () => {
    writeRawPolicy(policy());
    expect(await claude('{"tool_name":"Bash","tool_input":{"command":"rm -rf ~"')).toContain(DENY);
  });

  it("denies empty and non-object input on PreToolUse when enforcing", async () => {
    writeRawPolicy(policy());
    expect(await claude("")).toContain(DENY);
    expect(await claude("[1,2]")).toContain(DENY);
    expect(await claude('"rm -rf ~"')).toContain(DENY);
  });

  it("stays silent (fail open) on malformed input with no org policy", async () => {
    expect(await claude("{not json")).toBe("");
  });

  it("stays silent on malformed input for non pre-exec events", async () => {
    writeRawPolicy(policy());
    expect(await claude("{not json", "PostToolUse")).toBe("");
  });

  it("stays silent under an observe policy", async () => {
    writeRawPolicy(policy({ mode: "observe" }));
    expect(await claude("{not json")).toBe("");
  });

  it("parses tool_input sent as a JSON string", async () => {
    writeRawPolicy(policy());
    expect(await claude(claudePayload(JSON.stringify({ command: "rm -rf ~" })))).toContain(DENY);
    expect(await claude(claudePayload(JSON.stringify({ command: "ls" })))).toBe("");
  });

  it("joins a command sent as an argv array", async () => {
    writeRawPolicy(policy());
    expect(await claude(claudePayload({ command: ["rm", "-rf", "~"] }))).toContain(DENY);
    expect(await claude(claudePayload({ command: ["ls", "-la"] }))).toBe("");
  });

  it("enforces a Cursor payload on the Claude path when native Cursor hooks are not installed", async () => {
    writeRawPolicy(policy());
    const raw = claudePayload({ command: "rm -rf ~" }, { cursor_version: "2.0.0-fixture", conversation_id: "c1" });
    expect(await claude(raw)).toContain(DENY);
  });

  it("leaves a Cursor payload to the native hooks when they are installed", async () => {
    writeRawPolicy(policy());
    mkdirSync(join(testHome, ".cursor"), { recursive: true });
    writeFileSync(
      pathsMod.cursorHooksPath(),
      JSON.stringify({ version: 1, hooks: { beforeShellExecution: [{ command: "agentreel cursor-hook beforeShellExecution" }] } }),
    );
    const raw = claudePayload({ command: "rm -rf ~" }, { cursor_version: "2.0.0-fixture", conversation_id: "c1" });
    expect(await claude(raw)).toBe("");
  });
});

describe("malformed Cursor hook input", () => {
  it("denies malformed JSON on a pre-exec hook when enforcing", async () => {
    writeRawPolicy(policy());
    const res = await cursor('{"command":"rm -rf ~"');
    expect(res.permission).toBe("deny");
    expect(String(res.agent_message)).toContain("not valid JSON");
  });

  it("denies empty input on a pre-exec hook when enforcing", async () => {
    writeRawPolicy(policy());
    expect((await cursor("")).permission).toBe("deny");
    expect((await cursor("[]", "preToolUse")).permission).toBe("deny");
  });

  it("allows malformed input with no org policy", async () => {
    expect((await cursor("{bad")).permission).toBe("allow");
  });

  it("does not answer with a permission on non pre-exec hooks", async () => {
    writeRawPolicy(policy());
    expect((await cursor("{bad", "afterFileEdit")).permission).toBeUndefined();
  });

  it("joins a command array on beforeShellExecution", async () => {
    writeRawPolicy(policy());
    const raw = JSON.stringify({
      conversation_id: "c2",
      hook_event_name: "beforeShellExecution",
      cursor_version: "2.0.0-fixture",
      command: ["rm", "-rf", "~"],
      cwd: "/tmp/fixture-repo",
    });
    expect((await cursor(raw)).permission).toBe("deny");
  });
});
