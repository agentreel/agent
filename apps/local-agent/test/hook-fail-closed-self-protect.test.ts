import { existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import * as fs from "node:fs";
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

  describe("never writes through a symlink or a non-regular user hooks file", () => {
    const managedBody = JSON.stringify({
      version: 1,
      hooks: {
        beforeShellExecution: [{ command: "/usr/local/bin/agentreel cursor-hook beforeShellExecution", failClosed: true }],
        preToolUse: [{ command: "/usr/local/bin/agentreel cursor-hook preToolUse", failClosed: true }],
      },
    }, null, 2) + "\n";
    const run = (userPath: string) =>
      cursorInstall.installCursorHooks("agentreel", userPath, { systemHooksPath: systemCursorHooks });
    const noBackups = (dir: string) => readdirSync(dir).filter((f) => f.includes("backup"));

    it("~/.cursor/hooks.json symlinked to the managed file: managed bytes unchanged, warning returned", () => {
      writeFileSync(systemCursorHooks, managedBody);
      const userDir = join(work, "dot-cursor");
      mkdirSync(userDir);
      const userFile = join(userDir, "hooks.json");
      symlinkSync(systemCursorHooks, userFile);
      const res = run(userFile);
      expect(res.skipped).toBe(true);
      expect(res.skipped && res.removed).toBe(0);
      expect(res.skipped && res.backup).toBeNull();
      expect(res.skipped && res.warning).toMatch(/symlink/);
      expect(readFileSync(systemCursorHooks, "utf8")).toBe(managedBody);
      expect(lstatSync(userFile).isSymbolicLink()).toBe(true);
      expect(noBackups(userDir)).toEqual([]);
      expect(noBackups(work)).toEqual([]);
    });

    it("direct removeUserAgentreelCursorHooks on the symlink also refuses", () => {
      writeFileSync(systemCursorHooks, managedBody);
      const userFile = join(work, "link-hooks.json");
      symlinkSync(systemCursorHooks, userFile);
      const res = cursorInstall.removeUserAgentreelCursorHooks(userFile);
      expect(res.removed).toBe(0);
      expect(res.refused).toBeTruthy();
      expect(readFileSync(systemCursorHooks, "utf8")).toBe(managedBody);
    });

    it("~/.cursor itself symlinked to a directory holding the managed file: target bytes unchanged", () => {
      const realDir = join(work, "etc-cursor");
      mkdirSync(realDir);
      const managed = join(realDir, "hooks.json");
      writeFileSync(managed, managedBody);
      const linkDir = join(work, "dot-cursor-link");
      symlinkSync(realDir, linkDir);
      const res = cursorInstall.installCursorHooks("agentreel", join(linkDir, "hooks.json"), { systemHooksPath: managed });
      expect(res.skipped).toBe(true);
      expect(res.skipped && res.removed).toBe(0);
      expect(res.skipped && res.warning).toMatch(/symlink/);
      expect(readFileSync(managed, "utf8")).toBe(managedBody);
      expect(noBackups(realDir)).toEqual([]);
    });

    it("a non-regular file at the hooks path is left alone", () => {
      writeFileSync(systemCursorHooks, managedBody);
      const userFile = join(work, "hooks-is-a-dir");
      mkdirSync(userFile);
      writeFileSync(join(userFile, "keep.txt"), "keep");
      const res = run(userFile);
      expect(res.skipped && res.removed).toBe(0);
      expect(res.skipped && res.warning).toBeTruthy();
      expect(readdirSync(userFile)).toEqual(["keep.txt"]);
      expect(readFileSync(systemCursorHooks, "utf8")).toBe(managedBody);
    });

    it("a dangling symlink is not written through", () => {
      writeFileSync(systemCursorHooks, managedBody);
      const userFile = join(work, "dangling-hooks.json");
      const target = join(work, "does-not-exist.json");
      symlinkSync(target, userFile);
      const res = run(userFile);
      expect(res.skipped && res.removed).toBe(0);
      expect(existsSync(target)).toBe(false);
    });

    it("control: a regular user file is still cleaned", () => {
      writeFileSync(systemCursorHooks, managedBody);
      writeFileSync(cursorHooks, JSON.stringify({ version: 1, hooks: { preToolUse: [{ command: "agentreel cursor-hook preToolUse" }] } }));
      const res = run(cursorHooks);
      expect(res.skipped && res.removed).toBe(1);
      expect(res.skipped && res.warning).toBeUndefined();
    });

    it("cleanup: a missing ~/.cursor directory is nothing to clean", () => {
      writeFileSync(systemCursorHooks, managedBody);
      const userFile = join(work, "missing-cursor", "hooks.json");
      const res = run(userFile);
      expect(res.skipped).toBe(true);
      expect(res.skipped && res.removed).toBe(0);
      expect(res.skipped && res.warning).toBeUndefined();
      expect(existsSync(join(work, "missing-cursor"))).toBe(false);
    });

    it("cleanup: a non-ENOENT lstat error refuses and leaves the file unchanged", () => {
      writeFileSync(systemCursorHooks, managedBody);
      const userDir = join(work, "dot-cursor-eacces-clean");
      mkdirSync(userDir);
      const userFile = join(userDir, "hooks.json");
      const body = JSON.stringify({ version: 1, hooks: { preToolUse: [{ command: "agentreel cursor-hook preToolUse" }] } }) + "\n";
      writeFileSync(userFile, body);
      const real = cursorInstall._userHooksLstatForTests.lstatSync;
      const spy = vi.spyOn(cursorInstall._userHooksLstatForTests, "lstatSync").mockImplementation(((p: fs.PathLike, opts?: unknown) => {
        if (String(p) === userFile) {
          const err = new Error("permission denied") as NodeJS.ErrnoException;
          err.code = "EACCES";
          throw err;
        }
        return real.call(cursorInstall._userHooksLstatForTests, p, opts as never);
      }) as typeof fs.lstatSync);
      try {
        const res = run(userFile);
        expect(res.skipped).toBe(true);
        expect(res.skipped && res.removed).toBe(0);
        expect(res.skipped && res.backup).toBeNull();
        expect(res.skipped && res.warning).toBeTruthy();
        expect(readFileSync(userFile, "utf8")).toBe(body);
        expect(noBackups(userDir)).toEqual([]);
      } finally {
        spy.mockRestore();
      }
    });
  });

  describe("install path never writes through a symlink or when lstat fails", () => {
    const otherBody = "do-not-clobber\n";
    const absentSystem = join(work, "no-system-hooks.json");
    const install = (userPath: string) =>
      cursorInstall.installCursorHooks("agentreel", userPath, { systemHooksPath: absentSystem });
    const noBackups = (dir: string) => readdirSync(dir).filter((f) => f.includes("backup"));

    it("install: hooks.json symlinked to another file: target bytes unchanged", () => {
      const target = join(work, "other-hooks.json");
      writeFileSync(target, otherBody);
      const userDir = join(work, "dot-cursor-install");
      mkdirSync(userDir);
      const userFile = join(userDir, "hooks.json");
      symlinkSync(target, userFile);
      const res = install(userFile);
      expect(res.skipped).toBe(false);
      expect(res.refused).toBe(true);
      expect(res.warning).toMatch(/symlink/);
      expect(res.installedEvents).toEqual([]);
      expect(res.backup).toBeNull();
      expect(readFileSync(target, "utf8")).toBe(otherBody);
      expect(lstatSync(userFile).isSymbolicLink()).toBe(true);
      expect(noBackups(userDir)).toEqual([]);
    });

    it("install: ~/.cursor itself is a symlink: target bytes unchanged", () => {
      const realDir = join(work, "real-cursor");
      mkdirSync(realDir);
      const target = join(realDir, "hooks.json");
      writeFileSync(target, otherBody);
      const linkDir = join(work, "dot-cursor-install-link");
      symlinkSync(realDir, linkDir);
      const res = install(join(linkDir, "hooks.json"));
      expect(res.refused).toBe(true);
      expect(res.warning).toMatch(/symlink/);
      expect(res.installedEvents).toEqual([]);
      expect(readFileSync(target, "utf8")).toBe(otherBody);
      expect(noBackups(realDir)).toEqual([]);
    });

    it("install: a non-ENOENT lstat error refuses and leaves the file unchanged", () => {
      const userDir = join(work, "dot-cursor-eacces-install");
      mkdirSync(userDir);
      const userFile = join(userDir, "hooks.json");
      const body = JSON.stringify({ version: 1, hooks: { afterFileEdit: [{ command: "./fmt" }] } }) + "\n";
      writeFileSync(userFile, body);
      const real = cursorInstall._userHooksLstatForTests.lstatSync;
      const spy = vi.spyOn(cursorInstall._userHooksLstatForTests, "lstatSync").mockImplementation(((p: fs.PathLike, opts?: unknown) => {
        if (String(p) === userFile) {
          const err = new Error("permission denied") as NodeJS.ErrnoException;
          err.code = "EACCES";
          throw err;
        }
        return real.call(cursorInstall._userHooksLstatForTests, p, opts as never);
      }) as typeof fs.lstatSync);
      try {
        const res = install(userFile);
        expect(res.refused).toBe(true);
        expect(res.warning).toBeTruthy();
        expect(res.installedEvents).toEqual([]);
        expect(readFileSync(userFile, "utf8")).toBe(body);
        expect(noBackups(userDir)).toEqual([]);
      } finally {
        spy.mockRestore();
      }
    });

    it("control: a regular file still installs, leaving other hooks in place", () => {
      const userDir = join(work, "dot-cursor-ok");
      mkdirSync(userDir);
      const userFile = join(userDir, "hooks.json");
      writeFileSync(userFile, JSON.stringify({ version: 1, hooks: { afterFileEdit: [{ command: "./fmt" }] } }));
      const res = install(userFile);
      expect(res.skipped).toBe(false);
      expect(res.refused).toBeFalsy();
      expect(res.installedEvents.length).toBeGreaterThan(0);
      const file = JSON.parse(readFileSync(userFile, "utf8")) as { hooks: Record<string, Array<{ command: string }>> };
      expect(file.hooks.afterFileEdit[0]).toEqual({ command: "./fmt" });
      expect(JSON.stringify(file)).toContain("cursor-hook");
    });

    it("control: a missing ~/.cursor directory still installs", () => {
      const userFile = join(work, "brand-new-cursor", "hooks.json");
      expect(existsSync(join(work, "brand-new-cursor"))).toBe(false);
      const res = install(userFile);
      expect(res.skipped).toBe(false);
      expect(res.refused).toBeFalsy();
      expect(res.installedEvents.length).toBeGreaterThan(0);
      expect(existsSync(userFile)).toBe(true);
    });

    it("uninstall: hooks.json symlinked to the managed file leaves managed bytes unchanged and returns the warning", () => {
      const managed = join(work, "managed-for-uninstall.json");
      const full = JSON.stringify({
        version: 1,
        hooks: Object.fromEntries(
          ["preToolUse", "beforeShellExecution", "afterFileEdit"].map((e) => [e, [{ command: `/usr/local/bin/agentreel cursor-hook ${e}` }]]),
        ),
      }, null, 2) + "\n";
      writeFileSync(managed, full);
      const userDir = join(work, "dot-cursor-uninstall");
      mkdirSync(userDir);
      const userFile = join(userDir, "hooks.json");
      symlinkSync(managed, userFile);
      const res = cursorInstall.uninstallCursorHooks(userFile);
      expect(res.removed).toBe(0);
      expect(res.backup).toBeNull();
      expect(res.refused).toMatch(/symlink/);
      expect(readFileSync(managed, "utf8")).toBe(full);
      expect(lstatSync(userFile).isSymbolicLink()).toBe(true);
      expect(noBackups(userDir)).toEqual([]);
    });

    it("uninstall: ~/.cursor symlinked to a directory holding the managed file leaves it unchanged", () => {
      const realDir = join(work, "real-cursor-uninstall");
      mkdirSync(realDir);
      const managed = join(realDir, "hooks.json");
      const full = JSON.stringify({ version: 1, hooks: { preToolUse: [{ command: "agentreel cursor-hook preToolUse" }] } }) + "\n";
      writeFileSync(managed, full);
      const linkDir = join(work, "dot-cursor-uninstall-link");
      symlinkSync(realDir, linkDir);
      const res = cursorInstall.uninstallCursorHooks(join(linkDir, "hooks.json"));
      expect(res.removed).toBe(0);
      expect(res.refused).toMatch(/symlink/);
      expect(readFileSync(managed, "utf8")).toBe(full);
      expect(noBackups(realDir)).toEqual([]);
    });

    it("uninstall: a regular file is still cleaned (control)", () => {
      const userFile = join(work, "uninstall-regular.json");
      writeFileSync(userFile, JSON.stringify({ version: 1, hooks: { preToolUse: [{ command: "agentreel cursor-hook preToolUse" }, { command: "/opt/other" }] } }));
      const res = cursorInstall.uninstallCursorHooks(userFile);
      expect(res.removed).toBe(1);
      expect(res.refused).toBeUndefined();
      expect(res.backup).toBeTruthy();
      expect(JSON.parse(readFileSync(userFile, "utf8")).hooks.preToolUse).toEqual([{ command: "/opt/other" }]);
    });

    it("agentreel uninstall prints the warning instead of reporting a removal", async () => {
      const authMod = await import("../src/commands/auth.js");
      void authMod;
      // uninstallCommand uses the default ~/.cursor path (testHome); stage a symlink there.
      const cursorDir = join(testHome, ".cursor");
      rmSync(cursorDir, { recursive: true, force: true });
      mkdirSync(cursorDir, { recursive: true });
      const target = join(work, "managed-cmd.json");
      const body = JSON.stringify({ version: 1, hooks: { preToolUse: [{ command: "agentreel cursor-hook preToolUse" }] } }) + "\n";
      writeFileSync(target, body);
      symlinkSync(target, join(cursorDir, "hooks.json"));
      const log = vi.spyOn(console, "log").mockImplementation(() => {});
      try {
        await authMod.uninstallCommand();
        const out = log.mock.calls.map((c) => String(c[0])).join("\n");
        expect(out).toMatch(/symlink|untouched/);
        expect(out).not.toContain("Removed AgentReel hooks from ~/.cursor/hooks.json");
      } finally {
        log.mockRestore();
        rmSync(cursorDir, { recursive: true, force: true });
      }
      expect(readFileSync(target, "utf8")).toBe(body);
    });

    describe("TOCTOU: a swap to a symlink between the check and the write", () => {
      const seam = cursorInstall._userHooksWriteForTests;
      const realNoFollow = seam.noFollow;
      afterEach(() => {
        seam.beforeOpen = undefined;
        seam.noFollow = realNoFollow;
      });
      const regularBody = (cmd = "agentreel cursor-hook preToolUse") =>
        JSON.stringify({ version: 1, hooks: { preToolUse: [{ command: cmd }, { command: "/opt/other" }] } }, null, 2) + "\n";
      const victimBody = "victim-managed-bytes\n";

      /** Swap `userFile` for a symlink to `victim` just before the open. */
      function swapFileTo(victim: string) {
        seam.beforeOpen = (p) => {
          rmSync(p, { force: true });
          symlinkSync(victim, p);
        };
      }

      for (const [label, op] of [
        ["install", (f: string) => cursorInstall.installCursorHooks("agentreel", f, { systemHooksPath: join(work, "none.json") })],
        ["cleanup", (f: string) => cursorInstall.installCursorHooks("agentreel", f, { systemHooksPath: systemCursorHooks })],
        ["uninstall", (f: string) => cursorInstall.uninstallCursorHooks(f)],
      ] as const) {
        it(`${label}: file swapped to a symlink after the check, target unchanged (O_NOFOLLOW)`, () => {
          writeFileSync(systemCursorHooks, JSON.stringify({ version: 1, hooks: { preToolUse: [{ command: "agentreel cursor-hook preToolUse" }] } }));
          const victim = join(work, `victim-${label}.json`);
          writeFileSync(victim, victimBody);
          const dir = join(work, `toctou-${label}`);
          mkdirSync(dir);
          const userFile = join(dir, "hooks.json");
          writeFileSync(userFile, regularBody());
          swapFileTo(victim);
          const res = op(userFile) as { refused?: unknown; removed?: number; installedEvents?: unknown[] };
          expect(readFileSync(victim, "utf8")).toBe(victimBody);
          expect(Boolean(res.refused) || res.removed === 0).toBe(true);
          expect(res.installedEvents ?? []).toEqual([]);
        });

        it(`${label}: same swap with no O_NOFOLLOW (Windows) is caught by the lstat right before the write`, () => {
          writeFileSync(systemCursorHooks, JSON.stringify({ version: 1, hooks: { preToolUse: [{ command: "agentreel cursor-hook preToolUse" }] } }));
          const victim = join(work, `victim-nf-${label}.json`);
          writeFileSync(victim, victimBody);
          const dir = join(work, `toctou-nf-${label}`);
          mkdirSync(dir);
          const userFile = join(dir, "hooks.json");
          writeFileSync(userFile, regularBody());
          seam.noFollow = undefined;
          swapFileTo(victim);
          op(userFile);
          expect(readFileSync(victim, "utf8")).toBe(victimBody);
        });

        it(`${label}: parent directory swapped to a symlink after the check is refused`, () => {
          writeFileSync(systemCursorHooks, JSON.stringify({ version: 1, hooks: { preToolUse: [{ command: "agentreel cursor-hook preToolUse" }] } }));
          const realDir = join(work, `real-dir-${label}`);
          mkdirSync(realDir);
          const victim = join(realDir, "hooks.json");
          writeFileSync(victim, regularBody());
          const before = readFileSync(victim, "utf8");
          const dir = join(work, `swap-dir-${label}`);
          mkdirSync(dir);
          const userFile = join(dir, "hooks.json");
          writeFileSync(userFile, regularBody());
          seam.beforeOpen = () => {
            rmSync(dir, { recursive: true, force: true });
            symlinkSync(realDir, dir);
          };
          op(userFile);
          expect(readFileSync(victim, "utf8")).toBe(before);
        });
      }

      it("a fresh install whose missing file is swapped to a symlink is refused, target unchanged", () => {
        const victim = join(work, "victim-fresh.json");
        writeFileSync(victim, victimBody);
        const dir = join(work, "toctou-fresh");
        mkdirSync(dir);
        const userFile = join(dir, "hooks.json");
        seam.beforeOpen = (p) => symlinkSync(victim, p);
        const res = cursorInstall.installCursorHooks("agentreel", userFile, { systemHooksPath: join(work, "none.json") });
        expect(res.refused).toBe(true);
        expect(readFileSync(victim, "utf8")).toBe(victimBody);
      });

      it("an existing file whose backup fails aborts the write", () => {
        const dir = join(work, "backup-null");
        mkdirSync(dir);
        const userFile = join(dir, "hooks.json");
        const original = regularBody();
        writeFileSync(userFile, original);
        // The directory is not writable, so a new backup file cannot be created,
        // but the existing hooks file can still be opened for write. The helper
        // must abort rather than write without a backup.
        fs.chmodSync(dir, 0o500);
        try {
          const res = cursorInstall.installCursorHooks("agentreel", userFile, { systemHooksPath: join(work, "none.json") });
          expect(res.refused).toBe(true);
          expect(res.warning).toMatch(/backed up|untouched/);
          expect(res.installedEvents).toEqual([]);
          expect(readFileSync(userFile, "utf8")).toBe(original);
        } finally {
          fs.chmodSync(dir, 0o755);
        }
      });

      it("install, cleanup and uninstall refuse a hard-linked hooks.json and leave the other name unchanged", () => {
        const victimBody = "victim-hard-link-bytes\n";
        const hooksBody = JSON.stringify({
          version: 1,
          hooks: { preToolUse: [{ command: "agentreel cursor-hook preToolUse" }, { command: "/opt/other" }] },
        }, null, 2) + "\n";
        writeFileSync(systemCursorHooks, JSON.stringify({ version: 1, hooks: { preToolUse: [{ command: "agentreel cursor-hook preToolUse" }] } }));
        const ops: Array<[string, (f: string) => { refused?: unknown; removed?: number; installedEvents?: unknown[] }]> = [
          ["install", (f) => cursorInstall.installCursorHooks("agentreel", f, { systemHooksPath: join(work, "none.json") })],
          ["cleanup", (f) => cursorInstall.installCursorHooks("agentreel", f, { systemHooksPath: systemCursorHooks })],
          ["uninstall", (f) => cursorInstall.uninstallCursorHooks(f)],
        ];
        for (const [label, op] of ops) {
          const dir = join(work, `hardlink-${label}`);
          mkdirSync(dir);
          const victim = join(dir, "other.json");
          const hooks = join(dir, "hooks.json");
          writeFileSync(victim, hooksBody);
          fs.linkSync(victim, hooks);
          expect(lstatSync(hooks).nlink).toBe(2);
          writeFileSync(join(dir, "victim-copy"), victimBody);
          // Keep an independent copy of the shared bytes via the victim path after the link.
          const before = readFileSync(victim, "utf8");
          expect(before).toBe(hooksBody);
          const res = op(hooks);
          expect(res.refused).toBeTruthy();
          expect(res.installedEvents ?? []).toEqual([]);
          expect(readFileSync(victim, "utf8")).toBe(before);
          expect(readFileSync(hooks, "utf8")).toBe(before);
          expect(lstatSync(hooks).nlink).toBe(2);
        }
      });

      it("a first-backup-name EEXIST is retried with a new name and the write succeeds", () => {
        const dir = join(work, "backup-eexist");
        mkdirSync(dir);
        const userFile = join(dir, "hooks.json");
        writeFileSync(userFile, regularBody("/opt/keep"));
        const occupied = join(dir, "occupied-backup");
        writeFileSync(occupied, "occupied");
        const seam = cursorInstall._userHooksWriteForTests;
        const real = seam.nextBackupPath;
        let calls = 0;
        seam.nextBackupPath = (p) => {
          calls += 1;
          if (calls === 1) return occupied;
          seam.nextBackupPath = real;
          // Fall through to the real unique name.
          return `${p}.agentreel-backup-retried-${calls}`;
        };
        try {
          const res = cursorInstall.installCursorHooks("agentreel", userFile, { systemHooksPath: join(work, "none.json") });
          expect(res.refused).toBeFalsy();
          expect(res.backup).toBeTruthy();
          expect(res.backup).not.toBe(occupied);
          expect(readFileSync(occupied, "utf8")).toBe("occupied");
          expect(calls).toBeGreaterThanOrEqual(2);
          expect(readFileSync(userFile, "utf8")).toContain("cursor-hook");
        } finally {
          seam.nextBackupPath = real;
        }
      });

      it("two writes in the same millisecond both succeed and leave two distinct backups", () => {
        const dir = join(work, "same-ms-backup");
        mkdirSync(dir);
        const userFile = join(dir, "hooks.json");
        writeFileSync(
          userFile,
          JSON.stringify({ version: 1, hooks: { preToolUse: [{ command: "agentreel cursor-hook preToolUse" }, { command: "/opt/other" }] } }),
        );
        vi.useFakeTimers({ toFake: ["Date"] });
        try {
          vi.setSystemTime(new Date("2026-11-27T12:00:00.000Z"));
          const installed = cursorInstall.installCursorHooks("agentreel", userFile, { systemHooksPath: join(work, "none.json") });
          expect(installed.skipped).toBe(false);
          expect(installed.refused).toBeFalsy();
          expect(installed.backup).toBeTruthy();
          const uninstalled = cursorInstall.uninstallCursorHooks(userFile);
          expect(uninstalled.refused).toBeUndefined();
          expect(uninstalled.removed).toBeGreaterThan(0);
          expect(uninstalled.backup).toBeTruthy();
          expect(uninstalled.backup).not.toBe(installed.backup);
          const backups = readdirSync(dir).filter((f) => f.includes("agentreel-backup")).sort();
          expect(backups).toHaveLength(2);
          expect(backups[0]).not.toBe(backups[1]);
        } finally {
          vi.useRealTimers();
        }
      });

      it("control: with no swap a regular file is written, keeps its mode and is backed up", () => {
        const dir = join(work, "toctou-control");
        mkdirSync(dir);
        const userFile = join(dir, "hooks.json");
        writeFileSync(userFile, regularBody("/opt/keep"), { mode: 0o640 });
        fs.chmodSync(userFile, 0o640);
        const res = cursorInstall.installCursorHooks("agentreel", userFile, { systemHooksPath: join(work, "none.json") });
        expect(res.refused).toBeFalsy();
        expect(res.backup).toBeTruthy();
        expect(lstatSync(userFile).mode & 0o777).toBe(0o640);
        expect(readFileSync(userFile, "utf8")).toContain("cursor-hook");
      });
    });

    it("agentreel init prints the warning and does not claim a Cursor install", async () => {
      const target = join(work, "other-hooks.json");
      writeFileSync(target, otherBody);
      const userDir = join(work, "dot-cursor-init");
      mkdirSync(userDir);
      const userFile = join(userDir, "hooks.json");
      symlinkSync(target, userFile);
      const log = vi.spyOn(console, "log").mockImplementation(() => {});
      try {
        await initMod.initCommand({
          claude: false,
          cursorHooksPath: userFile,
          systemCursorHooksPath: absentSystem,
          cachePath,
          guardConfigPath,
        });
        const out = log.mock.calls.map((c) => String(c[0])).join("\n");
        expect(out).toMatch(/symlink|untouched/);
        expect(out).not.toContain("Installed");
      } finally {
        log.mockRestore();
      }
      expect(readFileSync(target, "utf8")).toBe(otherBody);
    });
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
  ["SELF003", "node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js managed install --hook-command /tmp/evil"],
  ["SELF003", "sudo node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js managed install --root /"],
  ["SELF003", "sudo node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js uninstall"],
  ["SELF003", "node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js pause"],
  ["SELF001", "node -e \"require('fs').rmSync('/usr/local/lib/node_modules/@agentreel/agent/dist/cli.js')\""],
  ["SELF001", "node -e 'x' /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js"],
  ["SELF001", "node -p 1 /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor"],
  ["SELF001", "node -r /tmp/evil.js /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor"],
  ["SELF001", "node --require=/tmp/evil.js /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor"],
  ["SELF001", "node --import /tmp/evil.mjs /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor"],
  ["SELF001", "node /tmp/evil.js /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js"],
  ["SELF001", "node /tmp/script.js /etc/cursor/hooks.json"],
  ["SELF001", "node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor /etc/cursor/hooks.json"],
  ["SELF001", "node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor > /etc/cursor/hooks.json"],
  ["SELF001", "node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor; rm -rf /usr/local/lib/node_modules/@agentreel/agent"],
  ["SELF001", "node /tmp/x/../node_modules/@agentreel/agent/dist/cli.js doctor"],
  ["SELF001", "node /tmp/node_modules/@agentreel/agent/dist/other.js doctor"],
  ["SELF001", "cat /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js > /tmp/x"],
  ["SELF001", "cp /tmp/evil.js /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js"],
  ["SELF005", "NODE_OPTIONS=--require=/tmp/evil.js node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor"],
  ["SELF005", "NODE_OPTIONS=--import=/tmp/evil.mjs node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor"],
  ["SELF005", "NODE_OPTIONS='--require /tmp/evil.js' node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor"],
  ["SELF005", "env NODE_OPTIONS=--require=/tmp/evil.js node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor"],
  ["SELF005", "env NODE_OPTIONS=--import=/tmp/evil.mjs node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js managed install --dry-run"],
  ["SELF005", "sudo NODE_OPTIONS=--require=/tmp/evil.js node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor"],
  ["SELF005", "export NODE_OPTIONS=--require=/tmp/evil.js"],
  ["SELF005", "unset NODE_OPTIONS"],
  ["SELF005", "NODE_OPTIONS=--require=/tmp/evil.js claude -p hi"],
  ["SELF005", "NODE_OPTIONS=--require=/tmp/evil.js agentreel doctor"],
  ["SELF005", "NODE_OPTIONS=--import=/tmp/evil.mjs agentreel doctor"],
  ["SELF005", "env NODE_OPTIONS=--require=/tmp/evil.js agentreel doctor"],
  ["SELF005", "sudo NODE_OPTIONS=--require=/tmp/evil.js agentreel doctor"],
  ["SELF005", "NODE_OPTIONS=--require=/tmp/evil.js agentreel status"],
  ["SELF005", "NODE_OPTIONS=--import=/tmp/evil.mjs agentreel status"],
  ["SELF005", "env NODE_OPTIONS=--require=/tmp/evil.js agentreel status"],
  ["SELF005", "sudo NODE_OPTIONS=--require=/tmp/evil.js agentreel status"],
  ["SELF005", "NODE_OPTIONS=--require=/tmp/evil.js npx @agentreel/agent doctor"],
  ["SELF005", "NODE_OPTIONS=--import=/tmp/evil.mjs npx @agentreel/agent doctor"],
  ["SELF005", "env NODE_OPTIONS=--require=/tmp/evil.js npx @agentreel/agent doctor"],
  ["SELF005", "sudo NODE_OPTIONS=--require=/tmp/evil.js npx @agentreel/agent doctor"],
  ["SELF005", "NODE_OPTIONS=--require=/tmp/evil.js npm exec @agentreel/agent doctor"],
  ["SELF005", "NODE_OPTIONS=--import=/tmp/evil.mjs npm exec @agentreel/agent doctor"],
  ["SELF005", "env NODE_OPTIONS=--require=/tmp/evil.js npm exec @agentreel/agent doctor"],
  ["SELF005", "sudo NODE_OPTIONS=--require=/tmp/evil.js npm exec @agentreel/agent doctor"],
  ["SELF005", "NODE_OPTIONS=--require=/tmp/evil.js pnpm exec @agentreel/agent doctor"],
  ["SELF005", "NODE_OPTIONS=--import=/tmp/evil.mjs pnpm exec @agentreel/agent doctor"],
  ["SELF005", "env NODE_OPTIONS=--require=/tmp/evil.js pnpm exec @agentreel/agent doctor"],
  ["SELF005", "sudo NODE_OPTIONS=--require=/tmp/evil.js pnpm exec @agentreel/agent doctor"],
  ["SELF005", "NODE_OPTIONS=--require=/tmp/evil.js pnpm dlx @agentreel/agent doctor"],
  ["SELF005", "NODE_OPTIONS=--import=/tmp/evil.mjs pnpm dlx @agentreel/agent doctor"],
  ["SELF005", "env NODE_OPTIONS=--require=/tmp/evil.js pnpm dlx @agentreel/agent doctor"],
  ["SELF005", "sudo NODE_OPTIONS=--require=/tmp/evil.js pnpm dlx @agentreel/agent doctor"],
  ["SELF005", "NODE_OPTIONS=--require=/tmp/evil.js yarn exec @agentreel/agent doctor"],
  ["SELF005", "NODE_OPTIONS=--import=/tmp/evil.mjs yarn exec @agentreel/agent doctor"],
  ["SELF005", "env NODE_OPTIONS=--require=/tmp/evil.js yarn exec @agentreel/agent doctor"],
  ["SELF005", "sudo NODE_OPTIONS=--require=/tmp/evil.js yarn exec @agentreel/agent doctor"],
  ["SELF005", "NODE_OPTIONS=--require=/tmp/evil.js bunx @agentreel/agent doctor"],
  ["SELF005", "NODE_OPTIONS=--import=/tmp/evil.mjs bunx @agentreel/agent doctor"],
  ["SELF005", "env NODE_OPTIONS=--require=/tmp/evil.js bunx @agentreel/agent doctor"],
  ["SELF005", "sudo NODE_OPTIONS=--require=/tmp/evil.js bunx @agentreel/agent doctor"],
  ["SELF005", "NODE_OPTIONS=--require=/tmp/evil.js bun run doctor"],
  ["SELF005", "NODE_OPTIONS=--import=/tmp/evil.mjs bun run doctor"],
  ["SELF005", "env NODE_OPTIONS=--require=/tmp/evil.js bun run doctor"],
  ["SELF005", "sudo NODE_OPTIONS=--require=/tmp/evil.js bun run doctor"],
  ["SELF005", "NODE_OPTIONS=--require=/tmp/evil.js node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor"],
  ["SELF005", "NODE_OPTIONS=--import=/tmp/evil.mjs node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor"],
  ["SELF005", "env NODE_OPTIONS=--require=/tmp/evil.js node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor"],
  ["SELF005", "sudo NODE_OPTIONS=--require=/tmp/evil.js node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor"],
  ["SELF005", "NODE_OPTIONS=--require=/tmp/evil.js nodejs /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor"],
  ["SELF005", "NODE_OPTIONS=--import=/tmp/evil.mjs nodejs /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor"],
  ["SELF005", "env NODE_OPTIONS=--require=/tmp/evil.js nodejs /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor"],
  ["SELF005", "sudo NODE_OPTIONS=--require=/tmp/evil.js nodejs /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor"],
  ["SELF005", "NODE_OPTIONS=--require=/tmp/evil.js /usr/bin/node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor"],
  ["SELF005", "NODE_OPTIONS=--import=/tmp/evil.mjs /usr/bin/node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor"],
  ["SELF005", "env NODE_OPTIONS=--require=/tmp/evil.js /usr/bin/node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor"],
  ["SELF005", "sudo NODE_OPTIONS=--require=/tmp/evil.js /usr/bin/node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor"],
  ["SELF005", "NODE_OPTIONS=--require=/tmp/evil.js tsx src/cli.ts doctor"],
  ["SELF005", "NODE_OPTIONS=--import=/tmp/evil.mjs tsx src/cli.ts doctor"],
  ["SELF005", "env NODE_OPTIONS=--require=/tmp/evil.js tsx src/cli.ts doctor"],
  ["SELF005", "sudo NODE_OPTIONS=--require=/tmp/evil.js tsx src/cli.ts doctor"],
  ["SELF005", "NODE_OPTIONS=--require=/tmp/evil.js ts-node src/cli.ts doctor"],
  ["SELF005", "NODE_OPTIONS=--import=/tmp/evil.mjs ts-node src/cli.ts doctor"],
  ["SELF005", "env NODE_OPTIONS=--require=/tmp/evil.js ts-node src/cli.ts doctor"],
  ["SELF005", "sudo NODE_OPTIONS=--require=/tmp/evil.js ts-node src/cli.ts doctor"],
  ["SELF005", "sudo -E env NODE_OPTIONS=--require=/tmp/evil.js agentreel doctor"],
  ["SELF005", "sudo -E env NODE_OPTIONS=--require=/tmp/evil.js npx @agentreel/agent doctor"],
  ["SELF005", "sudo -E env NODE_OPTIONS=--require=/tmp/evil.js node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor"],
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
  "node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor",
  "node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js managed install --dry-run",
  "sudo node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js managed install --dry-run",
  "nodejs /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js status",
  "/usr/bin/node /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor",
  "node --no-warnings /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js doctor",
  "cat /usr/local/lib/node_modules/@agentreel/agent/dist/cli.js",
  "agentreel doctor",
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
