import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  MANAGED_CLAUDE_HOOK_EVENTS,
  MANAGED_PATHS,
  buildClaudeManagedHooks,
  buildCursorManagedHooks,
  mergeClaudeManagedSettings,
  mergeCursorManagedHooks,
  serializeJson,
} from "../src/managed/pack.js";
import { applyManagedInstall, planManagedInstall, underRoot } from "../src/managed/install.js";
import { managedInstallCommand } from "../src/commands/managed.js";
import { installClaudeCodeHooks } from "../src/hooks/install.js";
import { installCursorHooks } from "../src/cursor/hooks-install.js";
import { CURSOR_HOOK_EVENTS } from "../src/cursor/hook-normalize.js";
import { shouldSkipTelemetryForArgv } from "../src/telemetry.js";

const HOOK = "/usr/local/bin/agentreel";
const LINUX = MANAGED_PATHS.linux;

let root: string;
let lines: string[];
const quiet = () => ({ log: (l: string) => lines.push(l), error: (l: string) => lines.push(l) });

function filesUnder(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((d) => d.isFile())
    .map((d) => join(d.parentPath ?? (d as unknown as { path: string }).path, d.name))
    .sort();
}

function readJson(path: string): Record<string, any> {
  return JSON.parse(readFileSync(path, "utf8"));
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "agentreel-managed-root-"));
  lines = [];
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
  vi.unstubAllGlobals();
});

describe("managed pack builders", () => {
  it("forces hook lockdown, no bypass mode and the sandbox with no fallback", () => {
    const s = mergeClaudeManagedSettings({}, { hookCommand: HOOK });
    expect(s.$schema).toBe("https://json.schemastore.org/claude-code-settings.json");
    expect(s.allowManagedHooksOnly).toBe(true);
    expect(s.permissions).toEqual({ disableBypassPermissionsMode: "disable" });
    expect(s.sandbox).toEqual({ enabled: true, failIfUnavailable: true, allowUnsandboxedCommands: false });
  });

  it("blocks on failure only on the Claude pre-exec hook, with the approval timeout", () => {
    const hooks = buildClaudeManagedHooks({ hookCommand: HOOK });
    expect(Object.keys(hooks)).toEqual([...MANAGED_CLAUDE_HOOK_EVENTS]);
    expect(hooks.PreToolUse![0]!.hooks[0]).toEqual({
      type: "command",
      command: `${HOOK} hook PreToolUse`,
      timeout: 130,
      onFailure: "block",
    });
    expect(hooks.Stop![0]!.hooks[0]).toEqual({ type: "command", command: `${HOOK} hook Stop`, timeout: 5 });
  });

  it("fails closed only on the Cursor pre-exec hooks", () => {
    const hooks = buildCursorManagedHooks({ hookCommand: HOOK });
    expect(Object.keys(hooks)).toEqual([...CURSOR_HOOK_EVENTS]);
    const closed = Object.entries(hooks).filter(([, d]) => d[0]!.failClosed).map(([e]) => e).sort();
    expect(closed).toEqual(["beforeMCPExecution", "beforeReadFile", "beforeShellExecution", "preToolUse"]);
    expect(hooks.beforeShellExecution![0]).toEqual({
      command: `${HOOK} cursor-hook beforeShellExecution`,
      timeout: 130,
      failClosed: true,
    });
    expect(hooks.afterFileEdit![0]).toEqual({ command: `${HOOK} cursor-hook afterFileEdit`, timeout: 5 });
  });

  it("uses the same events, commands and timeouts as the per-user installers", () => {
    const home = mkdtempSync(join(tmpdir(), "agentreel-managed-user-"));
    try {
      const claudePath = join(home, ".claude", "settings.json");
      const cursorPath = join(home, ".cursor", "hooks.json");
      installClaudeCodeHooks(HOOK, { settingsPath: claudePath });
      installCursorHooks(HOOK, cursorPath);
      const userClaude = readJson(claudePath).hooks;
      const userCursor = readJson(cursorPath).hooks;

      const managedClaude = buildClaudeManagedHooks({ hookCommand: HOOK });
      expect(Object.keys(managedClaude).sort()).toEqual(Object.keys(userClaude).sort());
      for (const [event, groups] of Object.entries(managedClaude)) {
        const { onFailure: _drop, ...entry } = groups[0]!.hooks[0]!;
        expect(entry).toEqual(userClaude[event][0].hooks[0]);
        expect(groups[0]!.matcher).toBe(userClaude[event][0].matcher);
        expect(groups[0]!.__agentreel).toBe(userClaude[event][0].__agentreel);
      }

      const managedCursor = buildCursorManagedHooks({ hookCommand: HOOK });
      expect(Object.keys(managedCursor).sort()).toEqual(Object.keys(userCursor).sort());
      for (const [event, defs] of Object.entries(managedCursor)) {
        const { failClosed: _drop, ...def } = defs[0]!;
        expect(def).toEqual(userCursor[event][0]);
      }
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

  it("merging twice equals merging once", () => {
    const once = mergeClaudeManagedSettings({ model: "x" }, { hookCommand: HOOK });
    expect(mergeClaudeManagedSettings(once, { hookCommand: HOOK })).toEqual(once);
    const c = mergeCursorManagedHooks({}, { hookCommand: HOOK });
    expect(mergeCursorManagedHooks(c, { hookCommand: HOOK })).toEqual(c);
  });

  it("checked-in templates match the generator", () => {
    const docs = join(__dirname, "..", "..", "..", "docs", "managed");
    expect(readFileSync(join(docs, "managed-settings.json"), "utf8")).toBe(
      serializeJson(mergeClaudeManagedSettings({}, { hookCommand: HOOK })),
    );
    expect(readFileSync(join(docs, "cursor-hooks.json"), "utf8")).toBe(
      serializeJson(mergeCursorManagedHooks({}, { hookCommand: HOOK })),
    );
  });
});

describe("agentreel managed install", () => {
  it("dry run prints a diff and writes nothing", () => {
    const code = managedInstallCommand(
      { dryRun: true, root, hookCommand: HOOK, platform: "linux" },
      { ...quiet(), uid: 1000, env: {} },
    );
    expect(code).toBe(0);
    expect(filesUnder(root)).toEqual([]);
    const out = lines.join("\n");
    expect(out).toContain("dry run");
    expect(out).toContain("would create");
    expect(out).toContain('+  "allowManagedHooksOnly": true,');
    expect(out).toContain(`+        "command": "${HOOK} cursor-hook beforeShellExecution",`);
  });

  it("creates both files, then a re-run changes nothing and makes no backup", () => {
    const opts = { root, hookCommand: HOOK, platform: "linux" };
    expect(managedInstallCommand(opts, { ...quiet(), uid: 1000, env: {} })).toBe(0);
    const claude = underRoot(root, LINUX.claudeManagedSettings);
    const cursor = underRoot(root, LINUX.cursorHooks);
    expect(readJson(claude).allowManagedHooksOnly).toBe(true);
    expect(readJson(cursor).version).toBe(1);
    expect(statSync(claude).mode & 0o777).toBe(0o644);
    const before = filesUnder(root);
    const mtimes = before.map((f) => statSync(f).mtimeMs);

    lines = [];
    expect(managedInstallCommand(opts, { ...quiet(), uid: 1000, env: {} })).toBe(0);
    expect(filesUnder(root)).toEqual(before);
    expect(before.map((f) => statSync(f).mtimeMs)).toEqual(mtimes);
    expect(lines.join("\n")).toContain("(unchanged)");
    expect(planManagedInstall({ root, hookCommand: HOOK, platform: "linux" }).map((p) => p.action)).toEqual([
      "unchanged",
      "unchanged",
    ]);
  });

  it("backs up an existing file, keeps the organization's keys and hooks, and replaces only ours", () => {
    const claude = underRoot(root, LINUX.claudeManagedSettings);
    mkdirSync(dirname(claude), { recursive: true });
    const original = serializeJson({
      model: "org-model",
      sandbox: { enabled: false, excludedCommands: ["docker *"] },
      hooks: {
        PreToolUse: [
          { matcher: "Bash", hooks: [{ type: "command", command: "/opt/org/check.sh" }] },
          { matcher: ".*", __agentreel: "agentreel:v1", hooks: [{ type: "command", command: "/old/agentreel hook PreToolUse" }] },
        ],
      },
    });
    writeFileSync(claude, original);

    const plans = planManagedInstall({ root, hookCommand: HOOK, platform: "linux", cursor: false });
    expect(plans[0]!.action).toBe("update");
    const [result] = applyManagedInstall(plans, new Date("2026-11-27T23:00:00Z"));
    expect(result!.backup).toBe(`${claude}.agentreel-backup-2026-11-27T23-00-00-000Z`);
    expect(readFileSync(result!.backup!, "utf8")).toBe(original);

    const merged = readJson(claude);
    expect(merged.model).toBe("org-model");
    expect(merged.sandbox).toEqual({
      enabled: true,
      excludedCommands: ["docker *"],
      failIfUnavailable: true,
      allowUnsandboxedCommands: false,
    });
    expect(merged.hooks.PreToolUse).toHaveLength(2);
    expect(merged.hooks.PreToolUse[0].hooks[0].command).toBe("/opt/org/check.sh");
    expect(merged.hooks.PreToolUse[1].hooks[0].command).toBe(`${HOOK} hook PreToolUse`);
    expect(existsSync(underRoot(root, LINUX.cursorHooks))).toBe(false);

    // A second run is a no-op: no new backup.
    const again = applyManagedInstall(planManagedInstall({ root, hookCommand: HOOK, platform: "linux", cursor: false }));
    expect(again[0]!.action).toBe("unchanged");
    expect(filesUnder(dirname(claude))).toHaveLength(2);
  });

  it("refuses invalid JSON and writes nothing", () => {
    const cursor = underRoot(root, LINUX.cursorHooks);
    mkdirSync(dirname(cursor), { recursive: true });
    writeFileSync(cursor, "{ not json");
    const code = managedInstallCommand({ root, hookCommand: HOOK, platform: "linux" }, { ...quiet(), uid: 0, env: {} });
    expect(code).toBe(1);
    expect(lines.join("\n")).toContain("is not valid JSON");
    expect(filesUnder(root)).toEqual([cursor]);
    expect(readFileSync(cursor, "utf8")).toBe("{ not json");
  });

  it("needs root to write the real system paths", () => {
    // The writer is replaced so a regression here can never touch the real /etc.
    const apply = vi.fn(() => {
      throw new Error("must not write");
    });
    const code = managedInstallCommand({ hookCommand: HOOK, platform: "linux" }, { ...quiet(), uid: 1000, env: {}, apply });
    expect(code).toBe(1);
    expect(lines.join("\n")).toContain("needs root");
    expect(apply).not.toHaveBeenCalled();
  });

  it("refuses to write from inside an agent session but allows a dry run", () => {
    for (const env of [{ CLAUDECODE: "1" }, { CLAUDE_CODE_CHILD_SESSION: "1" }, { CURSOR_AGENT: "1" }]) {
      lines = [];
      expect(managedInstallCommand({ root, hookCommand: HOOK, platform: "linux" }, { ...quiet(), uid: 0, env })).toBe(1);
      expect(lines.join("\n")).toContain("inside an agent session");
      expect(filesUnder(root)).toEqual([]);
      expect(
        managedInstallCommand({ root, hookCommand: HOOK, platform: "linux", dryRun: true }, { ...quiet(), uid: 0, env }),
      ).toBe(0);
    }
  });

  it("writes the macOS paths for --platform darwin", () => {
    expect(managedInstallCommand({ root, hookCommand: HOOK, platform: "darwin" }, { ...quiet(), uid: 0, env: {} })).toBe(0);
    expect(filesUnder(root)).toEqual(
      [
        underRoot(root, "/Library/Application Support/ClaudeCode/managed-settings.json"),
        underRoot(root, "/Library/Application Support/Cursor/hooks.json"),
      ].sort(),
    );
  });

  it("works while per-user AgentReel hooks are installed and leaves them untouched", () => {
    const home = process.env.HOME!;
    const claudeUser = join(home, ".claude", "settings.json");
    const cursorUser = join(home, ".cursor", "hooks.json");
    installClaudeCodeHooks(HOOK, { settingsPath: claudeUser });
    installCursorHooks(HOOK, cursorUser);
    const userBefore = [readFileSync(claudeUser, "utf8"), readFileSync(cursorUser, "utf8")];

    expect(managedInstallCommand({ root, hookCommand: HOOK, platform: "linux" }, { ...quiet(), uid: 0, env: {} })).toBe(0);
    expect([readFileSync(claudeUser, "utf8"), readFileSync(cursorUser, "utf8")]).toEqual(userBefore);
    expect(filesUnder(root)).toHaveLength(2);
  });

  it("makes no network calls and is skipped by CLI telemetry", () => {
    const fetchSpy = vi.fn(() => Promise.reject(new Error("network not allowed")));
    vi.stubGlobal("fetch", fetchSpy);
    expect(managedInstallCommand({ root, hookCommand: HOOK, platform: "linux" }, { ...quiet(), uid: 0, env: {} })).toBe(0);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(shouldSkipTelemetryForArgv(["node", "agentreel", "managed", "install"])).toBe(true);
    expect(shouldSkipTelemetryForArgv(["node", "agentreel", "status"])).toBe(false);
  });
});
