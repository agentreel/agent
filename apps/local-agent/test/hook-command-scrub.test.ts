import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import {
  buildHookCommand,
  isScrubbedHookCommand,
  stripHookScrubWrapper,
} from "../src/hooks/hook-command.js";
import {
  CLAUDE_HOOK_MARKER,
  inspectClaudeHookScrub,
  installClaudeCodeHooks,
  quotePath,
} from "../src/hooks/install.js";
import { inspectCursorHookScrub, installCursorHooks } from "../src/cursor/hooks-install.js";
import { formatDoctorReport, inspectDoctorState } from "../src/commands/doctor.js";

const home = mkdtempSync(join(tmpdir(), "agentreel-hook-scrub-"));
process.env.HOME = home;
afterAll(() => rmSync(home, { recursive: true, force: true }));

const BIN = "/usr/local/bin/agentreel";

describe("buildHookCommand", () => {
  it("POSIX: drops NODE_OPTIONS with env -u before the program", () => {
    expect(buildHookCommand(BIN, "hook", "PreToolUse", "linux")).toBe(
      "env -u NODE_OPTIONS /usr/local/bin/agentreel hook PreToolUse",
    );
    expect(buildHookCommand(BIN, "cursor-hook", "beforeShellExecution", "darwin")).toBe(
      "env -u NODE_OPTIONS /usr/local/bin/agentreel cursor-hook beforeShellExecution",
    );
  });

  it("Windows: unsets NODE_OPTIONS in cmd.exe, not with env -u", () => {
    const cmd = buildHookCommand('"C:\\Program Files\\agentreel\\cli.js"', "hook", "PreToolUse", "win32");
    expect(cmd).toBe(
      'cmd /d /s /c "set NODE_OPTIONS=&& "C:\\Program Files\\agentreel\\cli.js" hook PreToolUse"',
    );
    expect(cmd).not.toContain("env -u");
  });

  it("keeps quoted and npx prefixes intact", () => {
    expect(buildHookCommand(quotePath("/a b/cli.js"), "hook", "Stop", "linux")).toBe(
      'env -u NODE_OPTIONS "/a b/cli.js" hook Stop',
    );
    expect(buildHookCommand("npx -y @agentreel/agent", "hook", "Stop", "linux")).toBe(
      "env -u NODE_OPTIONS npx -y @agentreel/agent hook Stop",
    );
  });

  it("does not wrap a command twice", () => {
    const once = buildHookCommand(BIN, "hook", "Stop", "linux");
    expect(buildHookCommand(once.replace(/ hook Stop$/, ""), "hook", "Stop", "linux")).toBe(once);
    const win = buildHookCommand(BIN, "hook", "Stop", "win32");
    expect(isScrubbedHookCommand(win)).toBe(true);
  });

  it("isScrubbedHookCommand and stripHookScrubWrapper round-trip on both forms", () => {
    for (const platform of ["linux", "win32"] as const) {
      const cmd = buildHookCommand(BIN, "hook", "Stop", platform);
      expect(isScrubbedHookCommand(cmd), platform).toBe(true);
      expect(stripHookScrubWrapper(cmd), platform).toBe(`${BIN} hook Stop`);
    }
    expect(isScrubbedHookCommand(`${BIN} hook Stop`)).toBe(false);
    expect(stripHookScrubWrapper(`${BIN} hook Stop`)).toBe(`${BIN} hook Stop`);
    // Only the exact NODE_OPTIONS scrub counts, not any other env wrapper.
    expect(isScrubbedHookCommand(`env -u HOME ${BIN} hook Stop`)).toBe(false);
    expect(isScrubbedHookCommand(`env ${BIN} hook Stop`)).toBe(false);
  });
});

describe("installers write the scrubbed command and re-install migrates old entries", () => {
  let claudePath: string;
  let cursorPath: string;
  beforeEach(() => {
    const dir = mkdtempSync(join(home, "case-"));
    claudePath = join(dir, ".claude", "settings.json");
    cursorPath = join(dir, ".cursor", "hooks.json");
  });

  it("Claude: every installed entry starts with the scrub on this platform, and PreToolUse stays onFailure block", () => {
    installClaudeCodeHooks(BIN, { settingsPath: claudePath });
    const settings = JSON.parse(readFileSync(claudePath, "utf8")) as {
      hooks: Record<string, Array<{ hooks: Array<{ command: string; onFailure?: string }> }>>;
    };
    for (const [event, groups] of Object.entries(settings.hooks)) {
      const entry = groups[0]!.hooks[0]!;
      expect(entry.command, event).toBe(buildHookCommand(BIN, "hook", event));
      expect(isScrubbedHookCommand(entry.command), event).toBe(true);
    }
    expect(settings.hooks.PreToolUse![0]!.hooks[0]!.onFailure).toBe("block");
    expect(inspectClaudeHookScrub(claudePath)).toEqual({ entries: 9, unscrubbed: 0 });
  });

  it("Claude: an old unwrapped install is reported, then rewritten by re-running install", () => {
    mkdirSync(dirname(claudePath), { recursive: true });
    const old: Record<string, unknown[]> = {};
    for (const event of ["SessionStart", "PreToolUse", "Stop"]) {
      old[event] = [
        {
          matcher: ".*",
          __agentreel: CLAUDE_HOOK_MARKER,
          hooks: [{ type: "command", command: `${BIN} hook ${event}`, timeout: 5 }],
        },
        { matcher: "Bash", hooks: [{ type: "command", command: "./other.sh" }] },
      ];
    }
    writeFileSync(claudePath, JSON.stringify({ hooks: old }));
    expect(inspectClaudeHookScrub(claudePath)).toEqual({ entries: 3, unscrubbed: 3 });

    installClaudeCodeHooks(BIN, { settingsPath: claudePath });
    expect(inspectClaudeHookScrub(claudePath)).toEqual({ entries: 9, unscrubbed: 0 });
    const after = JSON.parse(readFileSync(claudePath, "utf8")) as {
      hooks: Record<string, Array<{ hooks: Array<{ command: string }> }>>;
    };
    // Other tools' hooks survive, ours are rewritten once each.
    expect(after.hooks.PreToolUse!.map((g) => g.hooks[0]!.command)).toContain("./other.sh");
    expect(after.hooks.PreToolUse!.filter((g) => g.hooks[0]!.command.includes("agentreel"))).toHaveLength(1);
  });

  it("Cursor: every installed entry starts with the scrub, pre-exec stays failClosed, old entries are migrated", () => {
    mkdirSync(dirname(cursorPath), { recursive: true });
    writeFileSync(
      cursorPath,
      JSON.stringify({
        version: 1,
        hooks: {
          beforeShellExecution: [
            { command: "./mine.sh" },
            { command: `${BIN} cursor-hook beforeShellExecution`, timeout: 130, failClosed: true },
          ],
          afterFileEdit: [{ command: `${BIN} cursor-hook afterFileEdit`, timeout: 5 }],
        },
      }),
    );
    expect(inspectCursorHookScrub(cursorPath)).toEqual({ entries: 2, unscrubbed: 2 });

    installCursorHooks(BIN, cursorPath, { systemHooksPath: join(home, "no-system.json") });
    const file = JSON.parse(readFileSync(cursorPath, "utf8")) as {
      hooks: Record<string, Array<{ command: string; failClosed?: boolean }>>;
    };
    expect(file.hooks.beforeShellExecution!.map((d) => d.command)).toEqual([
      "./mine.sh",
      buildHookCommand(BIN, "cursor-hook", "beforeShellExecution"),
    ]);
    expect(file.hooks.beforeShellExecution![1]!.failClosed).toBe(true);
    expect(inspectCursorHookScrub(cursorPath).unscrubbed).toBe(0);
  });
});

describe("doctor reports hook commands that do not scrub NODE_OPTIONS", () => {
  it("warns for an old install, names the fix, and is quiet after a re-install", () => {
    const dir = mkdtempSync(join(home, "doctor-"));
    const claudeSettingsPath = join(dir, ".claude", "settings.json");
    const cursorHooksPath = join(dir, ".cursor", "hooks.json");
    const common = {
      cachePath: join(dir, "policy.json"),
      guardConfigPath: join(dir, "guard-config.json"),
      claudeSettingsPath,
      cursorHooksPath,
      systemCursorHooksPath: join(dir, "no-system.json"),
      config: { apiBaseUrl: "http://127.0.0.1:1", schemaVersion: 1 } as never,
    };
    mkdirSync(dirname(claudeSettingsPath), { recursive: true });
    writeFileSync(
      claudeSettingsPath,
      JSON.stringify({
        hooks: {
          PreToolUse: [
            {
              matcher: ".*",
              __agentreel: CLAUDE_HOOK_MARKER,
              hooks: [{ type: "command", command: `${BIN} hook PreToolUse`, timeout: 130, onFailure: "block" }],
            },
          ],
        },
      }),
    );
    const before = inspectDoctorState(common);
    expect(before.hookScrub.needsMigration).toBe(true);
    expect(before.hookScrub.claude).toEqual({ entries: 1, unscrubbed: 1 });
    const text = formatDoctorReport(before);
    expect(text).toContain("do not drop NODE_OPTIONS");
    expect(text).toContain("init");

    installClaudeCodeHooks(BIN, { settingsPath: claudeSettingsPath });
    installCursorHooks(BIN, cursorHooksPath, { systemHooksPath: common.systemCursorHooksPath });
    const after = inspectDoctorState(common);
    expect(after.hookScrub.needsMigration).toBe(false);
    expect(formatDoctorReport(after)).not.toContain("NODE_OPTIONS");
  });
});
