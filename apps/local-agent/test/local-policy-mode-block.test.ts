import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import type { AgentConfig } from "../src/config.js";

const testHome = mkdtempSync(join(tmpdir(), "ar-local-block-"));
process.env.HOME = testHome;
process.env.AGENTREEL_HOME = join(testHome, ".agentreel");

const cache = await import("../src/policy/cache.js");
const enforce = await import("../src/policy/enforce.js");
const { RULES } = await import("../src/guard/rules.js");

afterAll(() => rmSync(testHome, { recursive: true, force: true }));

const config: AgentConfig = {
  apiBaseUrl: "http://127.0.0.1:1",
  installedHookTimeouts: { claude: 130, cursor: 130 },
  schemaVersion: 1,
} as AgentConfig;

let n = 0;
function paths(guard: unknown) {
  const dir = mkdtempSync(join(testHome, `case-${n++}-`));
  const guardConfigPath = join(dir, "guard-config.json");
  writeFileSync(guardConfigPath, JSON.stringify(guard), "utf8");
  return { cachePath: join(dir, "policy.json"), guardConfigPath };
}

async function run(guard: unknown, command: string) {
  const p = paths(guard);
  return enforce.enforcePreExec(
    { sessionId: `s-${n}`, tool: "claude-code", toolName: "Bash", command },
    { ...p, config, recordDecision: () => {} },
  );
}

describe("built-in rule count", () => {
  it("ships 31 Guard rules", () => {
    expect(RULES).toHaveLength(31);
    expect(new Set(RULES.map((r) => r.id)).size).toBe(31);
  });
});

describe("guardConfigToPolicy policyMode block", () => {
  it("enforces all 31 built-ins at block when rules is empty", () => {
    const policy = cache.guardConfigToPolicy({ enabled: true, policyMode: "block", rules: {} });
    expect(policy.mode).toBe("enforce");
    expect(Object.keys(policy.builtin)).toHaveLength(31);
    for (const r of RULES) expect(policy.builtin[r.id]).toEqual({ enabled: true, action: "block" });
  });

  it("keeps a disabled rule disabled and applies severity overrides", () => {
    const policy = cache.guardConfigToPolicy({
      policyMode: "block",
      rules: { FS001: { enabled: false }, GIT001: { enabled: true, severity: "critical" } } as never,
    });
    expect(policy.builtin.FS001).toEqual({ enabled: false, action: "block" });
    expect(policy.builtin.GIT001).toEqual({ enabled: true, action: "block", severity: "critical" });
  });

  it("warn stays observe with flag actions", () => {
    const policy = cache.guardConfigToPolicy({ policyMode: "warn", rules: { FS001: { enabled: true } } as never });
    expect(policy.mode).toBe("observe");
    expect(policy.builtin.FS001).toEqual({ enabled: true, action: "flag" });
  });
});

describe("enforcePreExec with local guard-config", () => {
  it("blocks rm -rf ~ when policyMode is block (denied path)", async () => {
    const res = await run({ enabled: true, policyMode: "block", rules: {} }, "rm -rf ~");
    expect(res.permitted).toBe(false);
    expect(res.action).toBe("block");
    expect(res.message ?? "").toContain("your local Guard config");
  });

  it("blocks git push --force to main when policyMode is block", async () => {
    const res = await run({ policyMode: "block" }, "git push --force origin main");
    expect(res.permitted).toBe(false);
  });

  it("allows a benign command when policyMode is block", async () => {
    const res = await run({ policyMode: "block" }, "ls -la");
    expect(res.permitted).toBe(true);
  });

  it("honors the command allowlist in block mode", async () => {
    const res = await run(
      { policyMode: "block", allowlists: { commands: ["git push --force origin main"], paths: [] } },
      "git push --force origin main",
    );
    expect(res.permitted).toBe(true);
  });

  it("does not block a rule the config disables", async () => {
    const res = await run(
      { policyMode: "block", rules: { GIT001: { enabled: false }, GIT002: { enabled: false }, GIT003: { enabled: false } } },
      "git push --force origin main",
    );
    expect(res.permitted).toBe(true);
  });

  it("warn mode never blocks", async () => {
    const res = await run({ policyMode: "warn", rules: { FS001: { enabled: true } } }, "rm -rf ~");
    expect(res.permitted).toBe(true);
  });

  it("off mode never blocks", async () => {
    const res = await run({ policyMode: "off" }, "rm -rf ~");
    expect(res.permitted).toBe(true);
  });
});
