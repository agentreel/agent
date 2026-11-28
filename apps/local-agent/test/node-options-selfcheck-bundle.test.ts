/**
 * The NODE_OPTIONS self-check, tested on the BUILT bundle (dist/cli.js built
 * fresh into a private directory), through the same entry a host uses:
 *
 *  - the in-process check is detection only: it denies a preload it can see;
 *  - the INSTALLED hook command (`env -u NODE_OPTIONS ...`) is what stops a
 *    preload that deletes NODE_OPTIONS, because the preload never loads.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Policy } from "../src/policy/types.js";
import { installClaudeCodeHooks, quotePath } from "../src/hooks/install.js";
import { installCursorHooks } from "../src/cursor/hooks-install.js";
import { writeCachedPolicyAtomic } from "../src/policy/cache.js";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
// Inside node_modules so the bundle still resolves better-sqlite3, and ignored by git.
const buildDir = join(packageRoot, "node_modules", ".cache", `agentreel-selfcheck-${process.pid}`);
const cli = join(buildDir, "cli.js");
const work = mkdtempSync(join(tmpdir(), "agentreel-selfcheck-bundle-"));
const posixOnly = process.platform === "win32" ? it.skip : it;

// Preloads. `touch*` leave NODE_OPTIONS alone (a visible violation); `delete*`
// remove it first, which is what blinds an in-process check.
const marker = join(work, "preload-ran");
const touchCjs = join(work, "touch.cjs");
const touchMjs = join(work, "touch.mjs");
const deleteCjs = join(work, "delete.cjs");
const deleteMjs = join(work, "delete.mjs");

beforeAll(() => {
  execFileSync("pnpm", ["exec", "tsup", "--out-dir", buildDir], { cwd: packageRoot, stdio: "pipe" });
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
  };
  return env;
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
    [`--import=${touchMjs}`, touchMjs],
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
    const r = runCli(["hook", "PreToolUse"], { home, execArgv: ["--import", touchMjs], input: PRE_TOOL_USE });
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
    ["--import", `--import=${deleteMjs}`],
  ];

  const claudeHookCommand = (home: string, event: string): string => {
    const settingsPath = join(home, ".claude", "settings.json");
    installClaudeCodeHooks(`${quotePath(process.execPath)} ${quotePath(cli)}`, { settingsPath });
    const settings = JSON.parse(readFileSync(settingsPath, "utf8")) as {
      hooks: Record<string, Array<{ hooks: Array<{ command: string }> }>>;
    };
    return settings.hooks[event]![0]!.hooks[0]!.command;
  };

  const cursorHookCommand = (home: string, event: string): string => {
    const hooksPath = join(home, ".cursor", "hooks.json");
    installCursorHooks(`${quotePath(process.execPath)} ${quotePath(cli)}`, hooksPath, {
      systemHooksPath: join(home, "no-system-hooks.json"),
    });
    const file = JSON.parse(readFileSync(hooksPath, "utf8")) as { hooks: Record<string, Array<{ command: string }>> };
    return file.hooks[event]![0]!.command;
  };

  function sh(command: string, home: string, nodeOptions: string, input: string) {
    const env = baseEnv(home);
    env.NODE_OPTIONS = nodeOptions;
    const r = spawnSync("sh", ["-c", command], { env, input, encoding: "utf8" });
    return { status: r.status, stdout: r.stdout, stderr: r.stderr };
  }

  for (const [label, nodeOptions] of deleting) {
    posixOnly(`installed Claude command (env -u NODE_OPTIONS): ${label} preload never runs and the hook enforces`, () => {
      const home = freshHome();
      cachePolicy(home);
      const command = claudeHookCommand(home, "PreToolUse");
      expect(command.startsWith("env -u NODE_OPTIONS ")).toBe(true);
      const r = sh(command, home, nodeOptions, PRE_TOOL_USE);
      // The preload did not load, so it could not hide anything...
      expect(existsSync(marker)).toBe(false);
      // ...and the hook ran for real: the org policy denies the force push.
      expect(r.status).toBe(0);
      const body = JSON.parse(r.stdout) as { hookSpecificOutput: { permissionDecision: string; permissionDecisionReason: string } };
      expect(body.hookSpecificOutput.permissionDecision).toBe("deny");
      expect(body.hookSpecificOutput.permissionDecisionReason).not.toContain("SELF005");
    });

    posixOnly(`installed Cursor command (env -u NODE_OPTIONS): ${label} preload never runs and the hook enforces`, () => {
      const home = freshHome();
      cachePolicy(home);
      const command = cursorHookCommand(home, "beforeShellExecution");
      expect(command.startsWith("env -u NODE_OPTIONS ")).toBe(true);
      const r = sh(command, home, nodeOptions, CURSOR_SHELL);
      expect(existsSync(marker)).toBe(false);
      expect(r.status).toBe(0);
      const body = JSON.parse(r.stdout) as { permission: string; user_message?: string };
      expect(body.permission).toBe("deny");
      expect(body.user_message ?? "").not.toContain("SELF005");
    });
  }

  posixOnly("fails closed if the wrapper cannot start: a missing `env` is a failed command, not an allow", () => {
    const home = freshHome();
    const command = claudeHookCommand(home, "PreToolUse");
    const env = baseEnv(home);
    env.PATH = "/nonexistent";
    const r = spawnSync("/bin/sh", ["-c", command], { env, input: PRE_TOOL_USE, encoding: "utf8" });
    expect(r.status).not.toBe(0);
    expect(r.stdout).toBe("");
    // Claude PreToolUse entries carry onFailure "block"; Cursor pre-exec entries carry failClosed.
    const settings = JSON.parse(readFileSync(join(home, ".claude", "settings.json"), "utf8")) as {
      hooks: Record<string, Array<{ hooks: Array<{ onFailure?: string }> }>>;
    };
    expect(settings.hooks.PreToolUse![0]!.hooks[0]!.onFailure).toBe("block");
    cursorHookCommand(home, "beforeShellExecution");
    const cursor = JSON.parse(readFileSync(join(home, ".cursor", "hooks.json"), "utf8")) as {
      hooks: Record<string, Array<{ failClosed?: boolean }>>;
    };
    expect(cursor.hooks.beforeShellExecution![0]!.failClosed).toBe(true);
  });

  for (const [label, nodeOptions] of deleting) {
    it(`documents the detection-only limit: without the wrapper, ${label} deleting NODE_OPTIONS runs first and the in-process check sees nothing`, () => {
      const home = freshHome();
      const r = runCli(["--version"], { home, nodeOptions });
      // The preload ran (marker) and the check was blind (the CLI ran).
      expect(existsSync(marker)).toBe(true);
      expect(r.status).toBe(0);
      expect(r.stderr).not.toContain("SELF005");
    });
  }

  mkdirSync(join(work, "keep"), { recursive: true });
});
