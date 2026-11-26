import { describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
// Imported first, with HOME still at the suite default, on purpose.
import * as paths from "../src/paths.js";

describe("paths read HOME lazily", () => {
  it("follows HOME set after the module was imported", () => {
    const suiteHome = process.env.HOME!;
    const a = mkdtempSync(join(tmpdir(), "agentreel-paths-a-"));
    const b = mkdtempSync(join(tmpdir(), "agentreel-paths-b-"));
    try {
      expect(paths.agentreelDir()).toBe(join(suiteHome, ".agentreel"));

      process.env.HOME = a;
      expect(paths.homeDir()).toBe(a);
      expect(paths.agentreelDir()).toBe(join(a, ".agentreel"));
      expect(paths.dbPath()).toBe(join(a, ".agentreel", "sessions.db"));
      expect(paths.configPath()).toBe(join(a, ".agentreel", "config.json"));
      expect(paths.policyPath()).toBe(join(a, ".agentreel", "policy.json"));
      expect(paths.guardConfigPath()).toBe(join(a, ".agentreel", "guard-config.json"));
      expect(paths.queueDir()).toBe(join(a, ".agentreel", "queue"));
      expect(paths.logPath()).toBe(join(a, ".agentreel", "agent.log"));
      expect(paths.daemonPidPath()).toBe(join(a, ".agentreel", "daemon.pid"));
      expect(paths.daemonLogPath()).toBe(join(a, ".agentreel", "daemon.log"));
      expect(paths.claudeSettingsPath()).toBe(join(a, ".claude", "settings.json"));
      expect(paths.cursorHooksPath()).toBe(join(a, ".cursor", "hooks.json"));

      process.env.HOME = b;
      expect(paths.logPath()).toBe(join(b, ".agentreel", "agent.log"));
      paths.ensureAgentreelDir();
      expect(existsSync(join(b, ".agentreel", "queue"))).toBe(true);
      expect(existsSync(join(a, ".agentreel"))).toBe(false);
    } finally {
      process.env.HOME = suiteHome;
      rmSync(a, { recursive: true, force: true });
      rmSync(b, { recursive: true, force: true });
    }
  });

  it("the suite runs against a temp HOME, not the real one", () => {
    expect(process.env.HOME).toContain("agentreel-suite-home-");
  });

  it("the guard scan log, the config and the policy cache land under the current HOME", async () => {
    const suiteHome = process.env.HOME!;
    const h = mkdtempSync(join(tmpdir(), "agentreel-paths-c-"));
    try {
      process.env.HOME = h;
      const { scanSession } = await import("../src/guard/scanner.js");
      const spinRule = {
        id: "SLOW", version: 1, severity: "high" as const, category: "safety-bypass" as const,
        name: "s", description: "s", rationale: "s", enabled: true,
        matcher: {
          type: "command" as const,
          customMatcher: () => {
            const end = Date.now() + 3000;
            while (Date.now() < end) { /* busy */ }
            return false;
          },
        },
      };
      scanSession(
        "s1",
        [{ id: "e1", sessionId: "s1", tool: "claude-code", type: "tool_use_pre", ts: 1, payload: { command: "ls" } }],
        undefined,
        { rules: [spinRule], deadlineMs: 20 },
      );
      expect(existsSync(join(h, ".agentreel", "agent.log"))).toBe(true);
    } finally {
      process.env.HOME = suiteHome;
      rmSync(h, { recursive: true, force: true });
    }
  });
});
