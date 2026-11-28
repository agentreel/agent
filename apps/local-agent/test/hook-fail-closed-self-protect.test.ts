import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Policy } from "../src/policy/types.js";

const testHome = mkdtempSync(join(tmpdir(), "agentreel-selfprotect-"));
process.env.HOME = testHome;
process.env.AGENTREEL_HOOK_COMMAND = "/usr/local/bin/agentreel";

const claudeInstall = await import("../src/hooks/install.js");
const cursorInstall = await import("../src/cursor/hooks-install.js");
const cache = await import("../src/policy/cache.js");
const enforce = await import("../src/policy/enforce.js");
const selfProtect = await import("../src/policy/self-protect.js");
const doctor = await import("../src/commands/doctor.js");
const initMod = await import("../src/commands/init.js");

const work = join(testHome, "work");
const claudeSettings = join(work, "claude-settings.json");
const cursorHooks = join(work, "cursor-hooks.json");
const systemCursorHooks = join(work, "etc-cursor-hooks.json");
const cachePath = join(work, "policy.json");
const guardConfigPath = join(work, "guard-config.json");

beforeEach(() => {
  rmSync(work, { recursive: true, force: true });
  mkdirSync(work, { recursive: true });
});

describe("(c) pre-exec hooks fail closed, lifecycle hooks stay fail-open", () => {
  it("Claude: onFailure block on PreToolUse only", () => {
    claudeInstall.installClaudeCodeHooks("agentreel", { settingsPath: claudeSettings });
    const hooks = JSON.parse(readFileSync(claudeSettings, "utf8")).hooks as Record<string, Array<{ hooks: Array<Record<string, unknown>> }>>;
    expect(hooks.PreToolUse![0]!.hooks[0]!.onFailure).toBe("block");
    for (const ev of ["SessionStart", "SessionEnd", "UserPromptSubmit", "PostToolUse", "Notification", "Stop", "SubagentStop", "PreCompact"]) {
      expect(hooks[ev]![0]!.hooks[0]!.onFailure, ev).toBeUndefined();
    }
    expect(claudeInstall.inspectClaudePreExecHook(claudeSettings).preToolUseFailClosed).toBe(true);
  });

  it("Cursor: failClosed on the 4 pre-exec hooks only", () => {
    const res = cursorInstall.installCursorHooks("agentreel", cursorHooks, { systemHooksPath: systemCursorHooks });
    expect(res.skipped).toBe(false);
    const hooks = JSON.parse(readFileSync(cursorHooks, "utf8")).hooks as Record<string, Array<Record<string, unknown>>>;
    const closed = Object.entries(hooks).filter(([, d]) => d[0]!.failClosed === true).map(([e]) => e).sort();
    expect(closed).toEqual(["beforeMCPExecution", "beforeReadFile", "beforeShellExecution", "preToolUse"]);
    expect(Object.keys(hooks).length).toBe(14);
    expect(cursorInstall.inspectCursorPreExecHooks(cursorHooks).hooks.every((h) => h.failClosed)).toBe(true);
  });

  it("doctor flags hooks installed by an older agent without fail-closed", () => {
    writeFileSync(
      claudeSettings,
      JSON.stringify({ hooks: { PreToolUse: [{ matcher: ".*", __agentreel: claudeInstall.CLAUDE_HOOK_MARKER, hooks: [{ type: "command", command: "agentreel hook PreToolUse", timeout: 130 }] }] } }),
    );
    writeFileSync(
      cursorHooks,
      JSON.stringify({ version: 1, hooks: Object.fromEntries(["preToolUse", "beforeShellExecution", "beforeMCPExecution", "beforeReadFile"].map((e) => [e, [{ command: `agentreel cursor-hook ${e}`, timeout: 130 }]])) }),
    );
    const report = doctor.inspectDoctorState({ claudeSettingsPath: claudeSettings, cursorHooksPath: cursorHooks, systemCursorHooksPath: join(work, "no-system-hooks.json"), cachePath, guardConfigPath, config: { apiBaseUrl: "x", schemaVersion: 1 } as never });
    expect(report.claude.preToolUseFailClosed).toBe(false);
    expect(report.cursor.allFailClosed).toBe(false);
    const text = doctor.formatDoctorReport(report);
    expect(text).toContain('onFailure "block" not set');
    expect(text).toContain("failClosed not set");
  });
});

describe("per-user Cursor install defers to the managed pack", () => {
  it("skips ~/.cursor/hooks.json when the system file already has agentreel entries", () => {
    writeFileSync(systemCursorHooks, JSON.stringify({ version: 1, hooks: { beforeShellExecution: [{ command: "/usr/local/bin/agentreel cursor-hook beforeShellExecution", failClosed: true }] } }));
    const res = cursorInstall.installCursorHooks("agentreel", cursorHooks, { systemHooksPath: systemCursorHooks });
    expect(res.skipped).toBe(true);
    expect(res.skipped && res.managedPath).toBe(systemCursorHooks);
    expect(existsSync(cursorHooks)).toBe(false);
  });

  it("still installs when the system file has only other hooks, or is missing", () => {
    writeFileSync(systemCursorHooks, JSON.stringify({ version: 1, hooks: { beforeShellExecution: [{ command: "/opt/other/audit-hook" }] } }));
    expect(cursorInstall.installCursorHooks("agentreel", cursorHooks, { systemHooksPath: systemCursorHooks }).skipped).toBe(false);
    rmSync(cursorHooks);
    expect(cursorInstall.installCursorHooks("agentreel", cursorHooks, { systemHooksPath: join(work, "nope.json") }).skipped).toBe(false);
  });

  it("treats an unreadable or malformed system file as managed (fail-safe) and does not install per-user hooks", () => {
    writeFileSync(systemCursorHooks, "{not json");
    const res = cursorInstall.installCursorHooks("agentreel", cursorHooks, { systemHooksPath: systemCursorHooks });
    expect(res.skipped).toBe(true);
    expect(res.skipped && res.managedState).toBe("unreadable");
    expect(existsSync(cursorHooks)).toBe(false);
  });

  it("removes stale AgentReel entries from ~/.cursor/hooks.json when skipping, leaving other hooks", () => {
    writeFileSync(systemCursorHooks, JSON.stringify({ version: 1, hooks: { beforeShellExecution: [{ command: "/usr/local/bin/agentreel cursor-hook beforeShellExecution", failClosed: true }] } }));
    writeFileSync(cursorHooks, JSON.stringify({
      version: 1,
      hooks: {
        beforeShellExecution: [
          { command: "agentreel cursor-hook beforeShellExecution", failClosed: true },
          { command: "/opt/other/audit-hook" },
        ],
        preToolUse: [{ command: "agentreel cursor-hook preToolUse", failClosed: true }],
      },
    }));
    const res = cursorInstall.installCursorHooks("agentreel", cursorHooks, { systemHooksPath: systemCursorHooks });
    expect(res.skipped).toBe(true);
    expect(res.skipped && res.removed).toBe(2);
    expect(res.skipped && res.backup).toBeTruthy();
    const file = JSON.parse(readFileSync(cursorHooks, "utf8"));
    expect(file.hooks.beforeShellExecution).toEqual([{ command: "/opt/other/audit-hook" }]);
    expect(file.hooks.preToolUse).toBeUndefined();
    expect(JSON.stringify(file)).not.toContain("cursor-hook");
  });

  it("doctor reports managed hooks instead of telling the user to run agentreel init", () => {
    writeFileSync(systemCursorHooks, JSON.stringify({
      version: 1,
      hooks: Object.fromEntries(
        ["preToolUse", "beforeShellExecution", "beforeMCPExecution", "beforeReadFile"].map((e) => [
          e,
          [{ command: `/usr/local/bin/agentreel cursor-hook ${e}`, timeout: 130, failClosed: true }],
        ]),
      ),
    }));
    const report = doctor.inspectDoctorState({
      claudeSettingsPath: join(work, "no-claude.json"),
      cursorHooksPath: cursorHooks,
      systemCursorHooksPath: systemCursorHooks,
      cachePath,
      guardConfigPath,
      config: { apiBaseUrl: "x", schemaVersion: 1 } as never,
    });
    expect(report.cursor.managed).toBe(true);
    expect(report.cursor.allInstalled).toBe(true);
    expect(report.cursor.allFailClosed).toBe(true);
    const text = doctor.formatDoctorReport(report);
    expect(text).toContain("owned by the managed pack");
    expect(text).not.toMatch(/Cursor[^\n]*(missing|not installed|run `agentreel init`)/i);
    const cursorLine = text.split("\n").find((l) => l.includes("cursor hooks:"));
    expect(cursorLine ?? "").not.toContain("agentreel init");
  });

  it("agentreel init prints that the managed pack owns the Cursor hooks", async () => {
    writeFileSync(systemCursorHooks, JSON.stringify({ version: 1, hooks: { preToolUse: [{ command: "agentreel cursor-hook preToolUse" }] } }));
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      await initMod.initCommand({ claude: false, cursorHooksPath: cursorHooks, systemCursorHooksPath: systemCursorHooks, cachePath, guardConfigPath });
      const out = log.mock.calls.map((c) => String(c[0])).join("\n");
      expect(out).toContain("owned by the managed pack");
      expect(out).not.toContain("Installed 14 Cursor hooks");
    } finally {
      log.mockRestore();
    }
    expect(existsSync(cursorHooks)).toBe(false);
  });

  it("the default system path is /etc/cursor/hooks.json on Linux", () => {
    expect(cursorInstall.systemCursorHooksPath("linux")).toBe("/etc/cursor/hooks.json");
    expect(cursorInstall.systemCursorHooksPath("darwin")).toBe("/Library/Application Support/Cursor/hooks.json");
  });
});

const DENIED: Array<[string, string]> = [
  ["SELF001", "rm ~/.agentreel/policy.json"],
  ["SELF001", "echo '{}' > ~/.agentreel/policy.json"],
  ["SELF001", "printf garbage > ~/.agentreel/sessions.db"],
  ["SELF001", "rm -rf $HOME/.agentreel"],
  ["SELF001", "find ~/.agentreel -delete"],
  ["SELF001", "sed -i 's/agentreel//' ~/.claude/settings.json"],
  ["SELF001", "rm ~/.cursor/hooks.json"],
  ["SELF001", "jq '.hooks={}' ~/.claude/settings.json > /tmp/s && mv /tmp/s ~/.claude/settings.json"],
  ["SELF001", "python3 -c \"open('/home/u/.cursor/hooks.json','w').write('{}')\""],
  ["SELF001", "echo x | sudo tee /etc/claude-code/managed-settings.json"],
  ["SELF001", "sudo rm /etc/cursor/hooks.json"],
  ["SELF001", "sudo rm -rf /etc/cursor"],
  ["SELF001", "sudo rm -rf /etc/cursor/"],
  ["SELF001", "mv /etc/cursor x"],
  ["SELF001", "rm /etc/cursor/*"],
  ["SELF001", "cd /etc/cursor && rm hooks.json"],
  ["SELF001", "sudo rm -rf /etc/claude-code"],
  ["SELF001", "sudo rm '/Library/Application Support/Cursor/hooks.json'"],
  ["SELF001", "sudo rm -rf '/Library/Application Support/Cursor'"],
  ["SELF001", "sudo rm -rf /Library/APPLICATION\\ Support/CURSOR"],
  ["SELF001", "sudo rm /Library/Application\\ Support/ClaudeCode/managed-settings.json"],
  ["SELF001", "sudo rm -rf /Library/Application\\ Support/ClaudeCode"],
  ["SELF001", "rm /usr/local/bin/agentreel"],
  ["SELF001", "sudo rm $(which agentreel)"],
  ["SELF001", "sudo rm -rf /usr/local/lib/node_modules/@agentreel/agent"],
  ["SELF001", "sudo sh -c 'echo x > /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js'"],
  ["SELF001", "sudo chmod -x /usr/local/bin/agentreel"],
  ["SELF001", "cp /tmp/evil.js /opt/agentreel/bin/agentreel"],
  ["SELF003", "sudo agentreel managed install --hook-command /tmp/evil"],
  ["SELF005", "env -u CLAUDECODE -u CLAUDE_CODE_CHILD_SESSION -u CURSOR_AGENT sudo agentreel managed install --hook-command /tmp/evil"],
  ["SELF005", "unset CLAUDECODE; sudo agentreel managed install --allow-user-writable-hook"],
  ["SELF003", "sudo /usr/local/bin/agentreel managed install --root /"],
  ["SELF005", "unset CLAUDECODE"],
  ["SELF005", "unset CURSOR_AGENT"],
  ["SELF005", "env -u CLAUDE_CODE_CHILD_SESSION sudo agentreel managed install --dry-run"],
  ["SELF001", "cp /tmp/x '.claude/settings.local.json'"],
  ["SELF001", "r''m ~/.agentreel/policy.json"],
  ["SELF003", "npx @agentreel/agent uninstall"],
  ["SELF003", "npx -y @agentreel/agent@0.2.4 logout"],
  ["SELF003", "npx @agentreel/agent pause"],
  ["SELF003", "agentreel uninstall"],
  ["SELF003", "/usr/local/bin/agentreel pause"],
  ["SELF003", "npm uninstall -g @agentreel/agent"],
  ["SELF004", "echo '{\"disableAllHooks\":true}' > .claude/settings.local.json"],
  ["SELF004", "claude -p --settings '{\"disableAllHooks\":true}' 'do it'"],
  ["SELF004", "claude --settings=/tmp/s.json -p hi"],
  ["SELF004", "claude --setting-sources project -p hi"],
  ["SELF005", "unset HOME; claude"],
  ["SELF005", "unset AGENTREEL_HOOK_COMMAND"],
  ["SELF005", "env -u HOME claude"],
  ["SELF005", "env -i bash"],
  ["SELF005", "export HOME=/tmp/empty"],
  ["SELF005", "HOME=/tmp/empty claude -p hi"],
  ["SELF005", "CLAUDE_CONFIG_DIR=/tmp/c claude"],
];

const ALLOWED = [
  "cat ~/.claude/settings.json",
  "ls -la ~/.agentreel",
  "grep disableAllHooks ~/.claude/settings.json",
  "jq .hooks ~/.cursor/hooks.json",
  "git status",
  "npm install left-pad",
  "echo hello > out.txt",
  "npx @agentreel/agent status",
  "agentreel doctor",
  "HOME=/tmp/x npm test",
  "claude -p 'summarize'",
  "rm -rf node_modules",
  "cat ./my.agentreel.txt",
  "ls /etc/cursor",
  "cat /etc/cursor/hooks.json",
  "agentreel managed install --dry-run",
  "sudo agentreel managed install --dry-run",
  "rm ./my-agentreel-notes.txt",
  "agentreel init",
  "agentreel status",
];

describe("(d) self-protect matcher", () => {
  for (const [id, cmd] of DENIED) {
    it(`denies ${cmd} (${id})`, () => {
      expect(selfProtect.matchSelfProtect({ toolName: "Bash", command: cmd })?.rule_id).toBe(id);
    });
  }
  for (const cmd of ALLOWED) {
    it(`allows ${cmd}`, () => {
      expect(selfProtect.matchSelfProtect({ toolName: "Bash", command: cmd })).toBeNull();
    });
  }

  it("denies Write/Edit tools on protected paths, including the /etc managed files", () => {
    for (const fp of [
      join(testHome, ".agentreel/policy.json"),
      "/repo/.claude/settings.local.json",
      join(testHome, ".cursor/hooks.json"),
      "/etc/claude-code/managed-settings.json",
      "/etc/cursor/hooks.json",
      "C:\\ProgramData\\Cursor\\hooks.json",
    ]) {
      expect(selfProtect.matchSelfProtect({ toolName: "Write", file_path: fp })?.rule_id, fp).toBe("SELF002");
      expect(selfProtect.matchSelfProtect({ toolName: "Edit", file_path: fp })?.rule_id, fp).toBe("SELF002");
    }
  });

  it("allows reading protected files, and writing ordinary files", () => {
    expect(selfProtect.matchSelfProtect({ toolName: "Read", file_path: "/etc/cursor/hooks.json" })).toBeNull();
    expect(selfProtect.matchSelfProtect({ toolName: "Write", file_path: "/repo/src/app.ts" })).toBeNull();
  });

  it("denies a Write whose content turns hooks off", () => {
    expect(
      selfProtect.matchSelfProtect({ toolName: "Write", file_path: "/tmp/s.json", toolInput: { content: '{"disableAllHooks":true}' } })?.rule_id,
    ).toBe("SELF004");
  });

  it("stays linear on 200k-character inputs", () => {
    const inputs = [
      "<".repeat(200_000),
      "a ".repeat(100_000) + "> ~/.agentreel/x",
      ".agentreel".repeat(20_000),
      "env " + "-u ".repeat(60_000),
      "'".repeat(200_000),
    ];
    for (const input of inputs) {
      const t0 = performance.now();
      selfProtect.matchSelfProtect({ toolName: "Bash", command: input });
      expect(performance.now() - t0).toBeLessThan(1500);
    }
  });
});

function policy(mode: "enforce" | "observe"): Policy {
  return {
    version: 1,
    etag: "etag-sp",
    workspace_id: "ws_acme",
    org_name: "Acme Corp",
    org_slug: "acme",
    updated_at: "2026-11-27T00:00:00Z",
    mode,
    offline: "last_known",
    builtin: {},
    custom: [],
    allow: { commands: [], paths: [], repos: [] },
  };
}

describe("(d) self-protect in enforcePreExec", () => {
  const run = async (command: string) =>
    enforce.enforcePreExec(
      { sessionId: "s", tool: "cursor", toolName: "Shell", command },
      { cachePath, guardConfigPath, config: { apiBaseUrl: "x", schemaVersion: 1 } as never, recordDecision: () => {}, log: () => {} },
    );

  it("blocks under an enforcing policy and records a SELF decision", async () => {
    const p = policy("enforce");
    cache.writeCachedPolicyAtomic({ policy: p, etag: p.etag, fetched_at: Date.now() }, cachePath);
    const res = await run("npx @agentreel/agent uninstall");
    expect(res.permitted).toBe(false);
    expect(res.reason).toBe("self_protect");
    expect(res.decision?.rule_id).toBe("SELF003");
    expect(res.message).toContain("Blocked by Acme Corp policy: self-protection");
  });

  it("does not block under an observe policy or with no policy", async () => {
    expect((await run("npx @agentreel/agent uninstall")).permitted).toBe(true);
    const p = policy("observe");
    cache.writeCachedPolicyAtomic({ policy: p, etag: p.etag, fetched_at: Date.now() }, cachePath);
    expect((await run("rm ~/.agentreel/policy.json")).permitted).toBe(true);
  });
});

describe("hook binary discovered from the managed hook command", () => {
  afterEach(() => selfProtect._setHookConfigPathsForTests(null));

  it("denies writes to a custom binary named in the hook file, and chmod -x on it", () => {
    const hooks = join(work, "managed-hooks.json");
    const bin = join(work, "custom-bin");
    writeFileSync(hooks, JSON.stringify({
      version: 1,
      hooks: { beforeShellExecution: [{ command: `${bin} cursor-hook beforeShellExecution`, failClosed: true }] },
    }));
    selfProtect._setHookConfigPathsForTests([hooks]);
    expect(selfProtect.matchSelfProtect({ toolName: "Bash", command: `rm ${bin}` })?.rule_id).toBe("SELF001");
    expect(selfProtect.matchSelfProtect({ toolName: "Bash", command: `chmod -x ${bin}` })?.rule_id).toBe("SELF001");
    expect(selfProtect.matchSelfProtect({ toolName: "Write", file_path: bin })?.rule_id).toBe("SELF002");
  });

  it("is graceful when the hook file is unreadable and still blocks the standard binary name", () => {
    selfProtect._setHookConfigPathsForTests([join(work, "missing-hooks.json")]);
    expect(selfProtect.matchSelfProtect({ toolName: "Bash", command: "rm /usr/local/bin/agentreel" })?.rule_id).toBe("SELF001");
    expect(selfProtect.matchSelfProtect({ toolName: "Bash", command: "ls /usr/local/bin/agentreel" })).toBeNull();
  });
});
