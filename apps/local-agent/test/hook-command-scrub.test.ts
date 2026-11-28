import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
  tokenize,
} from "../src/hooks/hook-command.js";
import { hookCommandBinaryPath } from "../src/managed/hook-path.js";
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
  it("always single-quotes, including simple paths with no spaces", () => {
    expect(quotePath("/usr/local/bin/agentreel")).toBe("'/usr/local/bin/agentreel'");
  });

  it("single-quotes spaces, ; & * | $ backticks, quotes, globs and newlines, and escapes apostrophes", () => {
    expect(quotePath("/a b/cli.js")).toBe("'/a b/cli.js'");
    expect(quotePath("/tmp/$(id)/cli.js")).toBe("'/tmp/$(id)/cli.js'");
    expect(quotePath("/tmp/`id`/cli.js")).toBe("'/tmp/`id`/cli.js'");
    expect(quotePath('/tmp/say"hi')).toBe(`'/tmp/say"hi'`);
    expect(quotePath("C:\\Program Files\\agentreel\\cli.js")).toBe(
      "'C:\\Program Files\\agentreel\\cli.js'",
    );
    expect(quotePath("/tmp/agentreel;true")).toBe("'/tmp/agentreel;true'");
    expect(quotePath("/tmp/a&b")).toBe("'/tmp/a&b'");
    expect(quotePath("/tmp/*")).toBe("'/tmp/*'");
    expect(quotePath("/tmp/a|b")).toBe("'/tmp/a|b'");
    expect(quotePath("/tmp/O'Brien/cli.js")).toBe("'/tmp/O'\\''Brien/cli.js'");
    expect(quotePath("/tmp/a\nb")).toBe("'/tmp/a\nb'");
    expect(quotePath("/tmp/with space;x")).toBe("'/tmp/with space;x'");
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
      posixScrub + "'/a b/cli.js' hook Stop",
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

  it("keeps POSIX single quotes when inserting --node-options= into an npx prefix with spaces", () => {
    expect(applyNpxNodeOptionsFlag("'/tmp/np dir/npx' -y @agentreel/agent")).toBe(
      "'/tmp/np dir/npx' --node-options= -y @agentreel/agent",
    );
    expect(buildHookCommand("'/tmp/np dir/npx' -y @agentreel/agent", "hook", "Stop", "linux")).toBe(
      posixScrub + "'/tmp/np dir/npx' --node-options= -y @agentreel/agent hook Stop",
    );
  });

  it("Cursor on Windows single-quotes every PowerShell token, including launchers", () => {
    const cmd = buildHookCommand("npx -y @agentreel/agent", "cursor-hook", "Stop", "win32");
    expect(cmd).toContain("'npx' '--node-options=' '-y' '@agentreel/agent' cursor-hook Stop");
    expect(isScrubbedHookCommand(cmd)).toBe(true);
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

  it("recognizes newly quoted and existing unquoted or double-quoted installs", () => {
    const posixScrub = "env -u NODE_OPTIONS -u npm_config_node_options -u NPM_CONFIG_NODE_OPTIONS ";
    const quoted = buildHookCommand(quotePath(BIN), "hook", "Stop", "linux");
    expect(quoted).toBe(posixScrub + "'/usr/local/bin/agentreel' hook Stop");
    expect(isScrubbedHookCommand(quoted)).toBe(true);
    expect(stripHookScrubWrapper(quoted)).toBe("'/usr/local/bin/agentreel' hook Stop");
    expect(hookCommandBinaryPath(quoted)).toBe(BIN);
    // Existing installs: scrubbed but unquoted, or legacy double quotes.
    const legacy = posixScrub + `${BIN} hook Stop`;
    expect(isScrubbedHookCommand(legacy)).toBe(true);
    expect(hookCommandBinaryPath(legacy)).toBe(BIN);
    const dbl = posixScrub + '"/usr/local/bin/agent reel" hook Stop';
    expect(isScrubbedHookCommand(dbl)).toBe(true);
    expect(hookCommandBinaryPath(dbl)).toBe("/usr/local/bin/agent reel");
    const apostrophe = buildHookCommand(quotePath("/tmp/O'Brien/agentreel"), "hook", "Stop", "linux");
    expect(isScrubbedHookCommand(apostrophe)).toBe(true);
    expect(hookCommandBinaryPath(apostrophe)).toBe("/tmp/O'Brien/agentreel");
    const meta = buildHookCommand(quotePath("/tmp/agentreel;true"), "hook", "PreToolUse", "linux");
    expect(isScrubbedHookCommand(meta)).toBe(true);
    expect(hookCommandBinaryPath(meta)).toBe("/tmp/agentreel;true");
    const claudeWin = buildHookCommand(quotePath("C:\\Program Files\\agentreel\\cli.js"), "hook", "PreToolUse", "win32");
    expect(isScrubbedHookCommand(claudeWin)).toBe(true);
    expect(hookCommandBinaryPath(claudeWin)).toBe("C:\\Program Files\\agentreel\\cli.js");
    const cursorWin = buildHookCommand(quotePath("C:\\Users\\O'Brien\\cli.js"), "cursor-hook", "beforeShellExecution", "win32");
    expect(isScrubbedHookCommand(cursorWin)).toBe(true);
    expect(hookCommandBinaryPath(cursorWin)).toBe("C:\\Users\\O'Brien\\cli.js");
    expect(tokenize("'/tmp/O'\\''Brien/bin' hook")[0]).toBe("/tmp/O'Brien/bin");
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

  it("is quiet for existing scrubbed unquoted commands and for newly single-quoted commands", () => {
    const dir = mkdtempSync(join(home, "doctor-quoted-"));
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
    const posixScrub = "env -u NODE_OPTIONS -u npm_config_node_options -u NPM_CONFIG_NODE_OPTIONS ";
    mkdirSync(dirname(claudeSettingsPath), { recursive: true });
    writeFileSync(
      claudeSettingsPath,
      JSON.stringify({
        hooks: {
          PreToolUse: [
            {
              matcher: ".*",
              __agentreel: CLAUDE_HOOK_MARKER,
              hooks: [{ type: "command", command: `${posixScrub}${BIN} hook PreToolUse`, timeout: 130, onFailure: "block" }],
            },
          ],
        },
      }),
    );
    const legacy = inspectDoctorState(common);
    expect(legacy.hookScrub.needsMigration).toBe(false);
    expect(legacy.hookScrub.claude).toEqual({ entries: 1, unscrubbed: 0 });
    expect(formatDoctorReport(legacy)).not.toContain("NODE_OPTIONS");

    installClaudeCodeHooks(quotePath(BIN), { settingsPath: claudeSettingsPath });
    installCursorHooks(quotePath(BIN), cursorHooksPath, { systemHooksPath: common.systemCursorHooksPath });
    const quoted = inspectDoctorState(common);
    expect(quoted.hookScrub.needsMigration).toBe(false);
    expect(quoted.hookScrub.claude.unscrubbed).toBe(0);
    expect(quoted.hookScrub.cursor.unscrubbed).toBe(0);
    expect(formatDoctorReport(quoted)).not.toContain("NODE_OPTIONS");
  });
});

/**
 * Real-shell tests for quotePath and PowerShell quoting.
 * On Linux they run through /bin/bash and pwsh 7. Git Bash only exists on
 * Windows; the windows-latest hook self-check job already runs this file,
 * and these cases use Git Bash bash.exe and pwsh 7 the same way the host
 * would run the installed hook command.
 */
function posixBash(): string {
  if (process.platform !== "win32") return "/bin/bash";
  const candidates = [
    join(process.env.ProgramFiles || "C:\\Program Files", "Git", "bin", "bash.exe"),
    join(process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)", "Git", "bin", "bash.exe"),
    join(process.env.LOCALAPPDATA || "", "Programs", "Git", "bin", "bash.exe"),
  ];
  const found = candidates.find((p) => p && existsSync(p));
  if (!found) throw new Error("Git Bash bash.exe not found; required to prove quotePath on Windows");
  return found;
}

function findPwsh(): string {
  if (process.platform === "win32") {
    const installed = join(process.env.ProgramFiles || "C:\\Program Files", "PowerShell", "7", "pwsh.exe");
    if (existsSync(installed)) return installed;
  }
  const exe = process.platform === "win32" ? "pwsh.exe" : "pwsh";
  const known = ["/tmp/bin/pwsh", "/tmp/pwsh7/pwsh", "/usr/bin/pwsh", "/usr/local/bin/pwsh"];
  for (const p of known) {
    if (existsSync(p)) return p;
  }
  for (const dir of (process.env.PATH ?? "").split(process.platform === "win32" ? ";" : ":")) {
    const p = join(dir, exe);
    if (dir && existsSync(p)) return p;
  }
  throw new Error("PowerShell 7 (pwsh) not found; required to prove path quoting");
}

function runBash(command: string, env: NodeJS.ProcessEnv) {
  const bash = posixBash();
  const next = { ...env };
  if (process.platform === "win32") {
    const gitRoot = dirname(dirname(bash));
    next.PATH = [join(gitRoot, "usr", "bin"), join(gitRoot, "bin"), next.PATH ?? ""].join(";");
  }
  return spawnSync(bash, ["-c", command], { env: next, encoding: "utf8", timeout: 15_000 });
}

function runPwsh(command: string, env: NodeJS.ProcessEnv, workDir: string) {
  const ps1 = join(workDir, "run-quoted.ps1");
  writeFileSync(ps1, `\uFEFF${command}\n`, "utf8");
  return spawnSync(
    findPwsh(),
    ["-NoProfile", "-NonInteractive", "-NoLogo", "-ExecutionPolicy", "Bypass", "-File", ps1],
    { env, encoding: "utf8", timeout: 15_000 },
  );
}

function writeTaggedJs(path: string, tag: "INTENDED" | "DECOY"): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(
    path,
    `const fs = require("node:fs");\nfs.appendFileSync(process.env.AGENTREEL_QUOTE_LOG, "${tag}\\n");\n`,
  );
}

function writeTaggedSh(path: string, tag: "INTENDED" | "DECOY"): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `#!/bin/sh\nprintf '${tag}\\n' >> "$AGENTREEL_QUOTE_LOG"\n`);
  chmodSync(path, 0o755);
}

function writeTaggedPs1(path: string, tag: "INTENDED" | "DECOY"): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `Add-Content -LiteralPath $env:AGENTREEL_QUOTE_LOG -Value '${tag}'\n`);
}

function canCreateFileName(name: string): boolean {
  if (process.platform !== "win32") return true;
  return !/[<>:"/\\|?*]/.test(name);
}

const QUOTE_CASES: Array<{ label: string; file: string; decoys: string[] }> = [
  { label: "agentreel;true", file: "agentreel;true", decoys: ["agentreel", "true"] },
  { label: "a&b", file: "a&b", decoys: ["a", "b"] },
  { label: "*", file: "*", decoys: ["decoy"] },
  { label: "with space;x", file: "with space;x", decoys: ["with", "with space", "x"] },
  { label: "a|b", file: "a|b", decoys: ["a", "b"] },
];

describe("quotePath real-shell: decoy must not run, intended file must", () => {
  for (const c of QUOTE_CASES) {
    const skip = !canCreateFileName(c.file);
    const suffix = skip ? " (skipped on Windows: the OS rejects this file name)" : "";

    it(`bash: ${c.label}${suffix}`, (ctx) => {
      if (skip) {
        ctx.skip();
        return;
      }
      const root = mkdtempSync(join(home, "quote-bash-"));
      const installDir = join(root, "install");
      const decoyDir = join(root, "decoys");
      mkdirSync(installDir, { recursive: true });
      mkdirSync(decoyDir, { recursive: true });
      const intendedJs = join(installDir, c.file);
      const intendedSh = join(installDir, `${c.file}.sh`);
      const log = join(root, "log.txt");
      writeTaggedJs(intendedJs, "INTENDED");
      writeTaggedSh(intendedSh, "INTENDED");
      for (const name of c.decoys) {
        if (!canCreateFileName(name)) continue;
        writeTaggedJs(join(installDir, name), "DECOY");
        writeTaggedSh(join(installDir, name === c.file ? `${name}.decoy` : name), "DECOY");
        writeTaggedSh(join(decoyDir, name), "DECOY");
      }
      const pathSep = process.platform === "win32" ? ";" : ":";
      const env: NodeJS.ProcessEnv = {
        ...process.env,
        AGENTREEL_QUOTE_LOG: log,
        PATH: `${decoyDir}${pathSep}${process.env.PATH ?? ""}`,
      };
      const nodeCmd = `${quotePath(process.execPath)} ${quotePath(intendedJs)}`;
      const hookCmd = buildHookCommand(nodeCmd, "hook", "Stop", "linux");
      const shCmd = quotePath(intendedSh);
      for (const [label, command] of [
        ["node+js", nodeCmd],
        ["hook command", hookCmd],
        ["first-token script", shCmd],
      ] as const) {
        if (existsSync(log)) writeFileSync(log, "");
        const r = runBash(command, env);
        const body = existsSync(log) ? readFileSync(log, "utf8") : "";
        expect(r.status, `${label} status=${r.status} stderr=${r.stderr} stdout=${r.stdout} log=${body}`).toBe(0);
        expect(body, `${label} log`).toContain("INTENDED");
        expect(body, `${label} log`).not.toContain("DECOY");
      }
    });

    it(`pwsh: ${c.label}${suffix}`, (ctx) => {
      if (skip) {
        ctx.skip();
        return;
      }
      const root = mkdtempSync(join(home, "quote-pwsh-"));
      const installDir = join(root, "install");
      const decoyDir = join(root, "decoys");
      mkdirSync(installDir, { recursive: true });
      mkdirSync(decoyDir, { recursive: true });
      const intendedJs = join(installDir, c.file);
      const intendedPs1 = join(installDir, `${c.file}.ps1`);
      const log = join(root, "log.txt");
      writeTaggedJs(intendedJs, "INTENDED");
      writeTaggedPs1(intendedPs1, "INTENDED");
      for (const name of c.decoys) {
        if (!canCreateFileName(name)) continue;
        writeTaggedJs(join(installDir, name), "DECOY");
        writeTaggedPs1(join(installDir, `${name}.ps1`), "DECOY");
        writeTaggedPs1(join(decoyDir, `${name}.ps1`), "DECOY");
      }
      const pathSep = process.platform === "win32" ? ";" : ":";
      const env: NodeJS.ProcessEnv = {
        ...process.env,
        AGENTREEL_QUOTE_LOG: log,
        PATH: `${decoyDir}${pathSep}${process.env.PATH ?? ""}`,
      };
      const nodeCmd = `& ${psSingleQuote(process.execPath)} ${psSingleQuote(intendedJs)}`;
      const hookCmd = buildHookCommand(
        `${quotePath(process.execPath)} ${quotePath(intendedJs)}`,
        "cursor-hook",
        "beforeShellExecution",
        "win32",
      );
      const ps1Cmd = `& ${psSingleQuote(intendedPs1)}`;
      for (const [label, command] of [
        ["node+js", nodeCmd],
        ["cursor hook command", hookCmd],
        ["first-token script", ps1Cmd],
      ] as const) {
        if (existsSync(log)) writeFileSync(log, "");
        const r = runPwsh(command, env, root);
        const body = existsSync(log) ? readFileSync(log, "utf8") : "";
        expect(r.status, `${label} status=${r.status} stderr=${r.stderr} stdout=${r.stdout} log=${body}`).toBe(0);
        expect(body, `${label} log`).toContain("INTENDED");
        expect(body, `${label} log`).not.toContain("DECOY");
      }
    });
  }
});
