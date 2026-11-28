/**
 * The NODE_OPTIONS self-check, tested on the BUILT bundle (dist/cli.js built
 * fresh into a private directory), through the same entry a host uses:
 *
 *  - the in-process check is detection only: it denies a preload it can see;
 *  - the INSTALLED hook command (`env -u NODE_OPTIONS -u npm_config_node_options
 *    ...` on POSIX and for Claude on Windows with shell: "bash"; PowerShell
 *    unsets for Cursor on Windows) is what stops a preload that deletes
 *    NODE_OPTIONS, because the preload never loads. Both the per-user
 *    installers and the managed pack write that command.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Policy } from "../src/policy/types.js";
import { isScrubbedHookCommand } from "../src/hooks/hook-command.js";
import { installClaudeCodeHooks, quotePath } from "../src/hooks/install.js";
import { installCursorHooks } from "../src/cursor/hooks-install.js";
import { buildClaudeManagedHooks, buildCursorManagedHooks } from "../src/managed/pack.js";
import { writeCachedPolicyAtomic } from "../src/policy/cache.js";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
// Inside node_modules so the bundle still resolves better-sqlite3, and ignored by git.
const buildDir = join(packageRoot, "node_modules", ".cache", `agentreel-selfcheck-${process.pid}`);
const cli = join(buildDir, "cli.js");
const work = mkdtempSync(join(tmpdir(), "agentreel-selfcheck-bundle-"));
// Preloads. `touch*` leave NODE_OPTIONS alone (a visible violation); `delete*`
// remove it first, which is what blinds an in-process check.
const marker = join(work, "preload-ran");
const touchCjs = join(work, "touch.cjs");
const touchMjs = join(work, "touch.mjs");
const deleteCjs = join(work, "delete.cjs");
const deleteMjs = join(work, "delete.mjs");

beforeAll(() => {
  const pnpmCmd = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
  execFileSync(pnpmCmd, ["exec", "tsup", "--out-dir", buildDir], {
    cwd: packageRoot,
    stdio: "pipe",
    shell: process.platform === "win32",
  });
  writeFileSync(touchCjs, `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "ran");\n`);
  writeFileSync(touchMjs, `import { writeFileSync } from "node:fs";\nwriteFileSync(${JSON.stringify(marker)}, "ran");\n`);
  writeFileSync(
    deleteCjs,
    `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "ran");\ndelete process.env.NODE_OPTIONS;\n`,
  );
  writeFileSync(
    deleteMjs,
    `import { writeFileSync } from "node:fs";\nwriteFileSync(${JSON.stringify(marker)}, "ran");\ndelete process.env.NODE_OPTIONS;\n`,
  );
}, 120_000);

afterAll(() => {
  rmSync(buildDir, { recursive: true, force: true });
  rmSync(work, { recursive: true, force: true });
});

function freshHome(): string {
  const home = mkdtempSync(join(work, "home-"));
  rmSync(marker, { force: true });
  return home;
}

function baseEnv(home: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    PATH: process.env.PATH,
    HOME: home,
    USERPROFILE: home,
    NODE_ENV: "production",
    AGENTREEL_TELEMETRY: "0",
    AGENTREEL_TEST_CLI: cli,
    AGENTREEL_TEST_NODE: process.execPath,
  };
  // Windows: cmd, Node and better-sqlite3 need the system directories and
  // temp paths. Do not copy the real user home.
  for (const key of [
    "SystemRoot",
    "SYSTEMROOT",
    "windir",
    "WINDIR",
    "SystemDrive",
    "PATHEXT",
    "COMSPEC",
    "TEMP",
    "TMP",
    "APPDATA",
    "LOCALAPPDATA",
    "ProgramFiles",
    "ProgramData",
    "NUMBER_OF_PROCESSORS",
  ]) {
    if (process.env[key]) env[key] = process.env[key];
  }
  return env;
}

function importSpec(absPath: string): string {
  return pathToFileURL(absPath).href;
}

function windowsGitBash(): string {
  const candidates = [
    join(process.env.ProgramFiles || "C:\\Program Files", "Git", "bin", "bash.exe"),
    join(process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)", "Git", "bin", "bash.exe"),
    join(process.env.LOCALAPPDATA || "", "Programs", "Git", "bin", "bash.exe"),
  ];
  const found = candidates.find((p) => p && existsSync(p));
  if (!found) {
    throw new Error("Git Bash bash.exe not found; required to prove Claude hook commands on Windows");
  }
  return found;
}

function windowsPowerShell(): string {
  const p = join(process.env.SystemRoot || "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  if (existsSync(p)) return p;
  return "powershell.exe";
}

function isPowerShellHookCommand(command: string): boolean {
  return command.includes("Remove-Item Env:NODE_OPTIONS");
}

/** Run an installed hook command the way the host would (sh, Git Bash, or PowerShell). */
function runHost(
  command: string,
  home: string,
  opts: { nodeOptions?: string; npmConfigNodeOptions?: string; input?: string; path?: string } = {},
) {
  const env = baseEnv(home);
  if (opts.nodeOptions !== undefined) env.NODE_OPTIONS = opts.nodeOptions;
  if (opts.npmConfigNodeOptions !== undefined) env.npm_config_node_options = opts.npmConfigNodeOptions;
  if (opts.path !== undefined) env.PATH = opts.path;
  const input = opts.input ?? "";
  let r;
  if (process.platform === "win32") {
    if (isPowerShellHookCommand(command)) {
      r = spawnSync(windowsPowerShell(), ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command], {
        env,
        input,
        encoding: "utf8",
        timeout: 15_000,
      });
    } else {
      const bash = windowsGitBash();
      const gitRoot = dirname(dirname(bash));
      env.PATH = [join(gitRoot, "usr", "bin"), join(gitRoot, "bin"), env.PATH ?? ""].join(";");
      r = spawnSync(bash, ["-c", command], { env, input, encoding: "utf8", timeout: 15_000 });
    }
  } else {
    r = spawnSync("/bin/sh", ["-c", command], { env, input, encoding: "utf8", timeout: 15_000 });
  }
  return {
    status: r.status,
    stdout: r.stdout ?? "",
    stderr: r.stderr ?? "",
    detail: `${r.stderr ?? ""}\n${r.stdout ?? ""}\n${r.error ? String(r.error) : ""}\nsignal=${r.signal}`,
  };
}

function hookPrefix(nodePath: string = process.execPath, cliPath: string = cli): string {
  return `${quotePath(nodePath)} ${quotePath(cliPath)}`;
}

function expectScrubbed(command: string): void {
  expect(isScrubbedHookCommand(command)).toBe(true);
  expect(command).not.toContain("cmd /d");
  if (isPowerShellHookCommand(command)) {
    expect(command).toContain("Remove-Item Env:npm_config_node_options");
  } else {
    expect(command.startsWith("env -u NODE_OPTIONS -u npm_config_node_options ")).toBe(true);
  }
}

function runCli(
  args: string[],
  opts: { home: string; nodeOptions?: string; execArgv?: string[]; input?: string },
) {
  const env = baseEnv(opts.home);
  if (opts.nodeOptions !== undefined) env.NODE_OPTIONS = opts.nodeOptions;
  const r = spawnSync(process.execPath, [...(opts.execArgv ?? []), cli, ...args], {
    env,
    input: opts.input ?? "",
    encoding: "utf8",
  });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

const PRE_TOOL_USE = JSON.stringify({
  session_id: "s1",
  hook_event_name: "PreToolUse",
  cwd: "/tmp",
  tool_name: "Bash",
  tool_input: { command: "git push --force origin main" },
});
const CURSOR_SHELL = JSON.stringify({
  hook_event_name: "beforeShellExecution",
  conversation_id: "c1",
  generation_id: "g1",
  command: "git push --force origin main",
  cwd: "/tmp",
});

function enforcingPolicy(): Policy {
  return {
    version: 1,
    etag: "etag-selfcheck",
    workspace_id: "ws_selfcheck",
    org_name: "Acme Corp",
    org_slug: "acme",
    updated_at: "2026-11-28T00:00:00Z",
    mode: "enforce",
    offline: "last_known",
    builtin: { GIT001: { enabled: true, action: "block", severity: "high" } },
    custom: [],
    allow: { commands: [], paths: [], repos: [] },
  };
}

function cachePolicy(home: string): void {
  const policy = enforcingPolicy();
  writeCachedPolicyAtomic(
    { policy, etag: policy.etag, fetched_at: Date.now() },
    join(home, ".agentreel", "policy.json"),
  );
}

describe("built bundle: a visible bad NODE_OPTIONS or execArgv preload is denied", () => {
  const visible: Array<[string, string]> = [
    [`--require=${touchCjs}`, touchCjs],
    [`-r ${touchCjs}`, touchCjs],
    [`--import=${importSpec(touchMjs)}`, touchMjs],
  ];

  for (const [nodeOptions] of visible) {
    it(`--version exits 1 and does not load the CLI: ${nodeOptions.split(" ")[0]!.split("=")[0]}`, () => {
      const home = freshHome();
      const r = runCli(["--version"], { home, nodeOptions });
      expect(r.status).toBe(1);
      expect(r.stdout).toBe("");
      expect(r.stderr).toContain("SELF005");
      // The CLI proper never ran: no version banner, no telemetry or db state.
      expect(existsSync(join(home, ".agentreel", "telemetry.json"))).toBe(false);
      expect(existsSync(join(home, ".agentreel", "sessions.db"))).toBe(false);
      expect(readFileSync(join(home, ".agentreel", "agent.log"), "utf8")).toContain("SELF005");
    });

    it(`hook PreToolUse prints the Claude deny and exits 2: ${nodeOptions.split(" ")[0]!.split("=")[0]}`, () => {
      const home = freshHome();
      const r = runCli(["hook", "PreToolUse"], { home, nodeOptions, input: PRE_TOOL_USE });
      expect(r.status).toBe(2);
      const body = JSON.parse(r.stdout) as {
        hookSpecificOutput: { hookEventName: string; permissionDecision: string; permissionDecisionReason: string };
      };
      expect(body.hookSpecificOutput.hookEventName).toBe("PreToolUse");
      expect(body.hookSpecificOutput.permissionDecision).toBe("deny");
      expect(body.hookSpecificOutput.permissionDecisionReason).toContain("SELF005");
      expect(r.stderr).toContain("SELF005");
    });

    it(`cursor-hook beforeShellExecution prints the Cursor deny and exits 2: ${nodeOptions.split(" ")[0]!.split("=")[0]}`, () => {
      const home = freshHome();
      const r = runCli(["cursor-hook", "beforeShellExecution"], { home, nodeOptions, input: CURSOR_SHELL });
      expect(r.status).toBe(2);
      const body = JSON.parse(r.stdout) as { permission: string; user_message: string };
      expect(body.permission).toBe("deny");
      expect(body.user_message).toContain("SELF005");
      expect(r.stderr).toContain("SELF005");
    });
  }

  it("a lifecycle hook exits 1 with the reason on stderr and no stdout", () => {
    const home = freshHome();
    const r = runCli(["hook", "SessionStart"], { home, nodeOptions: `--require=${touchCjs}`, input: "{}" });
    expect(r.status).toBe(1);
    expect(r.stdout).toBe("");
    expect(r.stderr).toContain("SELF005");
  });

  it("an allow-listed NODE_OPTIONS still runs the CLI", () => {
    const home = freshHome();
    const r = runCli(["--version"], { home, nodeOptions: "--max-old-space-size=4096 --no-warnings" });
    expect(r.status).toBe(0);
    expect(r.stdout.trim().length).toBeGreaterThan(0);
  });

  it("execArgv: `node --require x cli.js` exits 1", () => {
    const home = freshHome();
    const r = runCli(["--version"], { home, execArgv: ["--require", touchCjs] });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("SELF005");
    expect(r.stdout).toBe("");
  });

  it("execArgv: `node --import x cli.js hook PreToolUse` prints the deny and exits 2", () => {
    const home = freshHome();
    const r = runCli(["hook", "PreToolUse"], { home, execArgv: ["--import", importSpec(touchMjs)], input: PRE_TOOL_USE });
    expect(r.status).toBe(2);
    expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision).toBe("deny");
  });

  it("execArgv: a harmless flag does not trip the check", () => {
    const home = freshHome();
    const r = runCli(["--version"], { home, execArgv: ["--conditions", "development"] });
    expect(r.status).toBe(0);
  });
});

describe("built bundle: a preload that deletes NODE_OPTIONS", () => {
  const deleting: Array<[string, string]> = [
    ["--require", `--require=${deleteCjs}`],
    ["-r", `-r ${deleteCjs}`],
    ["--import", `--import=${importSpec(deleteMjs)}`],
  ];

  const claudeHookCommand = (home: string, event: string, prefix: string = hookPrefix()): string => {
    const settingsPath = join(home, ".claude", "settings.json");
    installClaudeCodeHooks(prefix, { settingsPath });
    const settings = JSON.parse(readFileSync(settingsPath, "utf8")) as {
      hooks: Record<string, Array<{ hooks: Array<{ command: string; shell?: string }> }>>;
    };
    const entry = settings.hooks[event]![0]!.hooks[0]!;
    if (process.platform === "win32") {
      expect(entry.shell).toBe("bash");
    } else {
      expect(entry.shell).toBeUndefined();
    }
    return entry.command;
  };

  const cursorHookCommand = (home: string, event: string): string => {
    const hooksPath = join(home, ".cursor", "hooks.json");
    installCursorHooks(hookPrefix(), hooksPath, {
      systemHooksPath: join(home, "no-system-hooks.json"),
    });
    const file = JSON.parse(readFileSync(hooksPath, "utf8")) as { hooks: Record<string, Array<{ command: string }>> };
    return file.hooks[event]![0]!.command;
  };

  const sources: Array<[string, (home: string) => { command: string; kind: "claude" | "cursor" }]> = [
    ["per-user Claude", (home) => ({ command: claudeHookCommand(home, "PreToolUse"), kind: "claude" })],
    [
      "managed pack Claude",
      () => ({
        command: buildClaudeManagedHooks({ hookCommand: hookPrefix(), platform: process.platform }).PreToolUse![0]!
          .hooks[0]!.command,
        kind: "claude",
      }),
    ],
    [
      "per-user Cursor",
      (home) => ({ command: cursorHookCommand(home, "beforeShellExecution"), kind: "cursor" }),
    ],
    [
      "managed pack Cursor",
      () => ({
        command: buildCursorManagedHooks({ hookCommand: hookPrefix(), platform: process.platform })
          .beforeShellExecution![0]!.command,
        kind: "cursor",
      }),
    ],
  ];

  for (const [source, getCommand] of sources) {
    for (const [label, nodeOptions] of deleting) {
      it(`${source}: ${label} preload that deletes NODE_OPTIONS never runs and the hook enforces`, () => {
        const home = freshHome();
        cachePolicy(home);
        const { command, kind } = getCommand(home);
        expectScrubbed(command);
        const r = runHost(command, home, { nodeOptions, input: kind === "claude" ? PRE_TOOL_USE : CURSOR_SHELL });
        expect(existsSync(marker)).toBe(false);
        expect(r.status, r.detail).toBe(0);
        if (kind === "claude") {
          const body = JSON.parse(r.stdout) as {
            hookSpecificOutput: { permissionDecision: string; permissionDecisionReason: string };
          };
          expect(body.hookSpecificOutput.permissionDecision).toBe("deny");
          expect(body.hookSpecificOutput.permissionDecisionReason).not.toContain("SELF005");
        } else {
          const body = JSON.parse(r.stdout) as { permission: string; user_message?: string };
          expect(body.permission).toBe("deny");
          expect(body.user_message ?? "").not.toContain("SELF005");
        }
      });
    }
  }

  it("fails closed if the wrapper cannot start: a missing env or cmd is a failed command, not an allow", () => {
    const home = freshHome();
    const command = claudeHookCommand(home, "PreToolUse");
    expectScrubbed(command);
    // Rename the wrapper so the host cannot start it. A missing name is a
    // real test on every platform (Windows Claude uses `env` via Git Bash).
    const broken = command.replace(/^(env)\b/, "$1-agentreel-missing");
    const missing = runHost(broken, home, { input: PRE_TOOL_USE });
    expect(missing.status).not.toBe(0);
    expect(missing.stdout.trim()).toBe("");
    if (process.platform !== "win32") {
      const hidden = runHost(command, home, { path: "/nonexistent", input: PRE_TOOL_USE });
      expect(hidden.status).not.toBe(0);
      expect(hidden.stdout.trim()).toBe("");
    }
    const settings = JSON.parse(readFileSync(join(home, ".claude", "settings.json"), "utf8")) as {
      hooks: Record<string, Array<{ hooks: Array<{ onFailure?: string }> }>>;
    };
    expect(settings.hooks.PreToolUse![0]!.hooks[0]!.onFailure).toBe("block");
    cursorHookCommand(home, "beforeShellExecution");
    const cursor = JSON.parse(readFileSync(join(home, ".cursor", "hooks.json"), "utf8")) as {
      hooks: Record<string, Array<{ failClosed?: boolean }>>;
    };
    expect(cursor.hooks.beforeShellExecution![0]!.failClosed).toBe(true);
    const managedClaude = buildClaudeManagedHooks({ hookCommand: hookPrefix(), platform: process.platform });
    expect(managedClaude.PreToolUse![0]!.hooks[0]!.onFailure).toBe("block");
    const managedCursor = buildCursorManagedHooks({ hookCommand: hookPrefix(), platform: process.platform });
    expect(managedCursor.beforeShellExecution![0]!.failClosed).toBe(true);
  });

  for (const [label, nodeOptions] of deleting) {
    it(`documents the detection-only limit: without the wrapper, ${label} deleting NODE_OPTIONS runs first and the in-process check sees nothing`, () => {
      const home = freshHome();
      const r = runCli(["--version"], { home, nodeOptions });
      expect(existsSync(marker)).toBe(true);
      expect(r.status).toBe(0);
      expect(r.stderr).not.toContain("SELF005");
    });
  }
});

describe("built bundle: npm injects NODE_OPTIONS after env -u unless the command scrubs it", () => {
  function writeMockNpx(dir: string): string {
    mkdirSync(dir, { recursive: true });
    const script = join(dir, "npx-mock.cjs");
    writeFileSync(
      script,
      [
        '"use strict";',
        'const { spawnSync } = require("node:child_process");',
        'const { existsSync, readFileSync } = require("node:fs");',
        'const { join } = require("node:path");',
        "const args = process.argv.slice(2);",
        'const hasEmpty = args.some((a) => a === "--node-options=" || a.startsWith("--node-options="));',
        'const rest = args.filter((a) => a !== "--node-options=" && !a.startsWith("--node-options="));',
        "if (!hasEmpty) {",
        "  if (process.env.npm_config_node_options) {",
        "    process.env.NODE_OPTIONS = process.env.npm_config_node_options;",
        "  } else {",
        '    const home = process.env.HOME || process.env.USERPROFILE || "";',
        '    const npmrc = join(home, ".npmrc");',
        "    if (existsSync(npmrc)) {",
        '      const m = readFileSync(npmrc, "utf8").match(/^node-options=(.*)$/m);',
        "      if (m) process.env.NODE_OPTIONS = m[1].trim();",
        "    }",
        "  }",
        "}",
        'const hookIdx = rest.findIndex((a) => a === "hook" || a === "cursor-hook");',
        "if (hookIdx < 0) process.exit(1);",
        "const node = process.env.AGENTREEL_TEST_NODE || process.execPath;",
        "const cliPath = process.env.AGENTREEL_TEST_CLI;",
        "if (!cliPath) process.exit(1);",
        "const r = spawnSync(node, [cliPath, ...rest.slice(hookIdx)], { stdio: \"inherit\", env: process.env });",
        "process.exit(r.status ?? 1);",
        "",
      ].join("\n"),
    );
    const exe = JSON.stringify(process.execPath);
    const scr = JSON.stringify(script);
    if (process.platform === "win32") {
      writeFileSync(join(dir, "npx.cmd"), `@echo off\r\n${process.execPath} ${script} %*\r\n`);
      const shExe = process.execPath.replace(/\\/g, "/");
      const shScr = script.replace(/\\/g, "/");
      writeFileSync(join(dir, "npx"), `#!/bin/sh\nexec "${shExe}" "${shScr}" "$@"\n`);
    } else {
      writeFileSync(join(dir, "npx"), `#!/bin/sh\nexec ${exe} ${scr} "$@"\n`, { mode: 0o755 });
    }
    return dir;
  }

  function npxPath(mockDir: string): string {
    return process.platform === "win32" ? `${mockDir};${process.env.PATH ?? ""}` : `${mockDir}:${process.env.PATH ?? ""}`;
  }

  function installNpxClaude(home: string): string {
    const settingsPath = join(home, ".claude", "settings.json");
    installClaudeCodeHooks("npx -y @agentreel/agent", { settingsPath });
    const settings = JSON.parse(readFileSync(settingsPath, "utf8")) as {
      hooks: Record<string, Array<{ hooks: Array<{ command: string; shell?: string }> }>>;
    };
    const entry = settings.hooks.PreToolUse![0]!.hooks[0]!;
    if (process.platform === "win32") expect(entry.shell).toBe("bash");
    expectScrubbed(entry.command);
    expect(entry.command).toContain("npx --node-options=");
    return entry.command;
  }

  it("a ~/.npmrc node-options preload never runs under the installed npx command", () => {
    const home = freshHome();
    cachePolicy(home);
    writeFileSync(join(home, ".npmrc"), `node-options=--require=${deleteCjs}\n`);
    const mockDir = writeMockNpx(join(home, "mock-bin"));
    const command = installNpxClaude(home);
    const r = runHost(command, home, { path: npxPath(mockDir), input: PRE_TOOL_USE });
    expect(existsSync(marker), r.detail).toBe(false);
    expect(r.status, r.detail).toBe(0);
    expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision).toBe("deny");
    expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecisionReason).not.toContain("SELF005");
  });

  it("npm_config_node_options never reaches the hook under the installed npx command", () => {
    const home = freshHome();
    cachePolicy(home);
    const mockDir = writeMockNpx(join(home, "mock-bin"));
    const command = installNpxClaude(home);
    const r = runHost(command, home, {
      path: npxPath(mockDir),
      npmConfigNodeOptions: `--require=${deleteCjs}`,
      input: PRE_TOOL_USE,
    });
    expect(existsSync(marker), r.detail).toBe(false);
    expect(r.status, r.detail).toBe(0);
    expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision).toBe("deny");
    expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecisionReason).not.toContain("SELF005");
  });
});

describe("built bundle: installed commands run through the host shell, including a path with spaces", () => {
  function spacedPrefix(): string {
    // Stay under node_modules/.cache so the copied bundle still resolves
    // better-sqlite3 from the package, while the path itself contains spaces.
    const root = join(buildDir, "Program Files", "Agent Reel");
    mkdirSync(root, { recursive: true });
    const cliPath = join(root, "cli.js");
    copyFileSync(cli, cliPath);
    const nodeDir = join(buildDir, "Program Files", "Node");
    mkdirSync(nodeDir, { recursive: true });
    const node = join(nodeDir, process.platform === "win32" ? "node.exe" : "node");
    copyFileSync(process.execPath, node);
    const prefix = hookPrefix(node, cliPath);
    expect(prefix).toContain("Program Files");
    return prefix;
  }

  it("Claude hook with a path with spaces: preload never runs and the hook enforces", () => {
    const home = freshHome();
    cachePolicy(home);
    const prefix = spacedPrefix();
    const settingsPath = join(home, ".claude", "settings.json");
    installClaudeCodeHooks(prefix, { settingsPath });
    const settings = JSON.parse(readFileSync(settingsPath, "utf8")) as {
      hooks: Record<string, Array<{ hooks: Array<{ command: string; shell?: string }> }>>;
    };
    const entry = settings.hooks.PreToolUse![0]!.hooks[0]!;
    if (process.platform === "win32") expect(entry.shell).toBe("bash");
    expectScrubbed(entry.command);
    const r = runHost(entry.command, home, { nodeOptions: `--require=${deleteCjs}`, input: PRE_TOOL_USE });
    expect(existsSync(marker), r.detail).toBe(false);
    expect(r.status, r.detail).toBe(0);
    expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision).toBe("deny");
  });

  it("Cursor hook with a path with spaces: preload never runs and the hook enforces", () => {
    const home = freshHome();
    cachePolicy(home);
    const prefix = spacedPrefix();
    const hooksPath = join(home, ".cursor", "hooks.json");
    installCursorHooks(prefix, hooksPath, { systemHooksPath: join(home, "no-system-hooks.json") });
    const file = JSON.parse(readFileSync(hooksPath, "utf8")) as { hooks: Record<string, Array<{ command: string }>> };
    const command = file.hooks.beforeShellExecution![0]!.command;
    expectScrubbed(command);
    const r = runHost(command, home, { nodeOptions: `--require=${deleteCjs}`, input: CURSOR_SHELL });
    expect(existsSync(marker), r.detail).toBe(false);
    expect(r.status, r.detail).toBe(0);
    expect(JSON.parse(r.stdout).permission).toBe("deny");
  });
});
