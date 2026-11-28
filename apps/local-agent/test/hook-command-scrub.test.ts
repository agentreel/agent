import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import {
  applyNpxNodeOptionsFlag,
  buildHookCommand,
  buildHookInvocation,
  isScrubbedHookCommand,
  psSingleQuote,
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

describe("quotePath", () => {
  it("leaves a simple path unquoted", () => {
    expect(quotePath("/usr/local/bin/agentreel")).toBe("/usr/local/bin/agentreel");
  });

  it("quotes spaces and escapes $, backticks, double quotes and backslashes", () => {
    expect(quotePath("/a b/cli.js")).toBe('"/a b/cli.js"');
    expect(quotePath("/tmp/$(id)/cli.js")).toBe('"/tmp/\\$(id)/cli.js"');
    expect(quotePath("/tmp/`id`/cli.js")).toBe('"/tmp/\\`id\\`/cli.js"');
    expect(quotePath('/tmp/say"hi')).toBe('"/tmp/say\\"hi"');
    expect(quotePath("C:\\Program Files\\agentreel\\cli.js")).toBe(
      '"C:\\\\Program Files\\\\agentreel\\\\cli.js"',
    );
  });
});

describe("buildHookCommand", () => {
  const posixScrub = "env -u NODE_OPTIONS -u npm_config_node_options -u NPM_CONFIG_NODE_OPTIONS ";

  it("POSIX: drops NODE_OPTIONS and npm_config_node_options with env -u before the program", () => {
    expect(buildHookCommand(BIN, "hook", "PreToolUse", "linux")).toBe(
      posixScrub + "/usr/local/bin/agentreel hook PreToolUse",
    );
    expect(buildHookCommand(BIN, "cursor-hook", "beforeShellExecution", "darwin")).toBe(
      posixScrub + "/usr/local/bin/agentreel cursor-hook beforeShellExecution",
    );
    expect(isScrubbedHookCommand(`env -u NODE_OPTIONS ${BIN} hook Stop`)).toBe(false);
    expect(isScrubbedHookCommand(`env -u NODE_OPTIONS -u npm_config_node_options ${BIN} hook Stop`)).toBe(false);
  });

  it("Claude on Windows uses the POSIX env -u form and sets shell bash (Git Bash is the default host shell)", () => {
    const inv = buildHookInvocation('"C:\\Program Files\\agentreel\\cli.js"', "hook", "PreToolUse", "win32");
    expect(inv.shell).toBe("bash");
    expect(inv.command).toBe(
      posixScrub + '"C:\\Program Files\\agentreel\\cli.js" hook PreToolUse',
    );
    expect(inv.command).not.toContain("cmd /d");
    expect(buildHookInvocation(BIN, "hook", "Stop", "linux").shell).toBeUndefined();
  });

  it("Cursor on Windows uses PowerShell to drop NODE_OPTIONS, not cmd or env -u", () => {
    const cmd = buildHookCommand('"C:\\Program Files\\agentreel\\cli.js"', "cursor-hook", "beforeShellExecution", "win32");
    expect(cmd).toContain("$OutputEncoding = [Console]::InputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false;");
    expect(cmd).toContain("Remove-Item Env:NODE_OPTIONS");
    expect(cmd).toContain("Remove-Item Env:npm_config_node_options");
    expect(cmd).toContain("Remove-Item Env:NPM_CONFIG_NODE_OPTIONS");
    expect(cmd).toContain("$input | & 'C:\\Program Files\\agentreel\\cli.js'");
    expect(cmd).toContain("cursor-hook beforeShellExecution");
    expect(cmd).not.toContain("cmd /d");
    expect(cmd).not.toContain("env -u");
    expect(buildHookInvocation(BIN, "cursor-hook", "beforeShellExecution", "win32").shell).toBeUndefined();
  });

  it("keeps quoted and npx prefixes intact, and adds --node-options= for npx and bunx", () => {
    expect(buildHookCommand(quotePath("/a b/cli.js"), "hook", "Stop", "linux")).toBe(
      posixScrub + '"/a b/cli.js" hook Stop',
    );
    expect(buildHookCommand("npx -y @agentreel/agent", "hook", "Stop", "linux")).toBe(
      posixScrub + "npx --node-options= -y @agentreel/agent hook Stop",
    );
    expect(buildHookCommand("bunx -y @agentreel/agent", "hook", "Stop", "linux")).toBe(
      posixScrub + "bunx --node-options= -y @agentreel/agent hook Stop",
    );
    expect(buildHookCommand("npx --node-options= -y @agentreel/agent", "hook", "Stop", "linux")).toBe(
      posixScrub + "npx --node-options= -y @agentreel/agent hook Stop",
    );
    expect(isScrubbedHookCommand(posixScrub + "npx -y @agentreel/agent hook Stop")).toBe(false);
  });

  it("keeps quoting when inserting --node-options= into an npx prefix with spaces", () => {
    expect(applyNpxNodeOptionsFlag('"C:\\Program Files\\nodejs\\npx.cmd" -y @agentreel/agent')).toBe(
      '"C:\\Program Files\\nodejs\\npx.cmd" --node-options= -y @agentreel/agent',
    );
    expect(applyNpxNodeOptionsFlag('"/tmp/np dir/npx" -y @agentreel/agent')).toBe(
      '"/tmp/np dir/npx" --node-options= -y @agentreel/agent',
    );
    expect(buildHookCommand('"/tmp/np dir/npx" -y @agentreel/agent', "hook", "Stop", "linux")).toBe(
      posixScrub + '"/tmp/np dir/npx" --node-options= -y @agentreel/agent hook Stop',
    );
  });

  it("psSingleQuote doubles ASCII and typographic single quotes, including in O’Brien paths", () => {
    expect(psSingleQuote("O'Brien")).toBe("'O''Brien'");
    expect(psSingleQuote("O\u2018Brien")).toBe("'O\u2018\u2018Brien'");
    expect(psSingleQuote("O\u2019Brien")).toBe("'O\u2019\u2019Brien'");
    expect(psSingleQuote("O\u201ABrien")).toBe("'O\u201A\u201ABrien'");
    expect(psSingleQuote("O\u201BBrien")).toBe("'O\u201B\u201BBrien'");
    const path = "C:\\Users\\O\u2019Brien\\agentreel\\cli.js";
    const cmd = buildHookCommand(path, "cursor-hook", "beforeShellExecution", "win32");
    expect(cmd).toContain("$input | & 'C:\\Users\\O\u2019\u2019Brien\\agentreel\\cli.js'");
  });

  it("does not wrap a command twice", () => {
    const once = buildHookCommand(BIN, "hook", "Stop", "linux");
    expect(buildHookCommand(once.replace(/ hook Stop$/, ""), "hook", "Stop", "linux")).toBe(once);
    const win = buildHookCommand(BIN, "hook", "Stop", "win32");
    expect(isScrubbedHookCommand(win)).toBe(true);
  });

  it("isScrubbedHookCommand and stripHookScrubWrapper round-trip on both forms", () => {
    const posix = buildHookCommand(BIN, "hook", "Stop", "linux");
    expect(isScrubbedHookCommand(posix)).toBe(true);
    expect(stripHookScrubWrapper(posix)).toBe(`${BIN} hook Stop`);
    const claudeWin = buildHookCommand(BIN, "hook", "Stop", "win32");
    expect(isScrubbedHookCommand(claudeWin)).toBe(true);
    expect(stripHookScrubWrapper(claudeWin)).toBe(`${BIN} hook Stop`);
    const cursorWin = buildHookCommand(BIN, "cursor-hook", "Stop", "win32");
    expect(isScrubbedHookCommand(cursorWin)).toBe(true);
    expect(stripHookScrubWrapper(cursorWin)).toContain(BIN);
    expect(isScrubbedHookCommand(`${BIN} hook Stop`)).toBe(false);
    expect(stripHookScrubWrapper(`${BIN} hook Stop`)).toBe(`${BIN} hook Stop`);
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
      const inv = buildHookInvocation(BIN, "hook", event);
      expect(entry.shell, event).toBe(inv.shell);
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
