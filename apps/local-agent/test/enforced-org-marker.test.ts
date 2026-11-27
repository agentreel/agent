import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import type { Policy } from "../src/policy/types.js";

const testHome = mkdtempSync(join(tmpdir(), "agentreel-marker-"));
process.env.HOME = testHome;

const cache = await import("../src/policy/cache.js");
const enforce = await import("../src/policy/enforce.js");
const doctor = await import("../src/commands/doctor.js");
const { RULES } = await import("../src/guard/rules.js");

const dir = join(testHome, "ar");
const cachePath = join(dir, "policy.json");
const guardConfigPath = join(dir, "guard-config.json");

function policy(overrides: Partial<Policy> = {}): Policy {
  return {
    version: 1,
    etag: "etag-m",
    workspace_id: "org_acme",
    org_id: "org_acme",
    org_name: "Acme Corp",
    org_slug: "acme",
    updated_at: "2026-11-27T00:00:00Z",
    mode: "enforce",
    offline: "last_known",
    builtin: { FS001: { enabled: true, action: "block", severity: "critical" } },
    custom: [],
    allow: { commands: [], paths: [], repos: [] },
    ...overrides,
  };
}

function cachePolicy(p: Policy): void {
  cache.writeCachedPolicyAtomic({ policy: p, etag: p.etag, fetched_at: Date.now() }, cachePath);
}

async function check(command: string) {
  return enforce.enforcePreExec(
    { sessionId: "s", tool: "claude-code", toolName: "Bash", command },
    {
      cachePath,
      guardConfigPath,
      config: { apiBaseUrl: "http://127.0.0.1:1", schemaVersion: 1 } as never,
      recordDecision: () => {},
      log: () => {},
    },
  );
}

beforeEach(() => {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
});

describe("enforced-org marker", () => {
  it("is written when an enforcing org policy is cached, and removed for an observe one", () => {
    cachePolicy(policy());
    const marker = cache.readEnforcementMarker(cachePath);
    expect(marker?.policy_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(marker?.org_name).toBe("Acme Corp");
    cachePolicy(policy({ mode: "observe" }));
    expect(cache.readEnforcementMarker(cachePath)).toBeNull();
  });

  it("a deleted policy.json loads the lockdown policy and denies rm -rf ~", async () => {
    cachePolicy(policy());
    unlinkSync(cachePath);
    const loaded = cache.loadEffectivePolicy({ cachePath, guardConfigPath });
    expect(loaded.source).toBe("enforced_lockdown");
    expect(loaded.lockdownReason).toBe("policy_missing");
    expect(Object.keys(loaded.policy!.builtin)).toHaveLength(RULES.length);
    const res = await check("rm -rf ~");
    expect(res.permitted).toBe(false);
    expect(res.message).toContain("Acme Corp");
  });

  it("a malformed policy.json loads lockdown (policy_invalid)", async () => {
    cachePolicy(policy());
    writeFileSync(cachePath, "{not json");
    expect(cache.loadEffectivePolicy({ cachePath, guardConfigPath }).lockdownReason).toBe("policy_invalid");
    expect((await check("rm -rf ~")).permitted).toBe(false);
  });

  it("a policy.json edited to mode observe loads lockdown (policy_edited)", async () => {
    cachePolicy(policy());
    const raw = JSON.parse(readFileSync(cachePath, "utf8"));
    raw.policy.mode = "observe";
    writeFileSync(cachePath, JSON.stringify(raw));
    expect(cache.loadEffectivePolicy({ cachePath, guardConfigPath }).lockdownReason).toBe("policy_edited");
    expect((await check("rm -rf ~")).permitted).toBe(false);
  });

  it("an edit that removes a block rule is caught too", async () => {
    cachePolicy(policy({ builtin: { FS001: { enabled: true, action: "block" }, GIT001: { enabled: true, action: "block" } } }));
    const raw = JSON.parse(readFileSync(cachePath, "utf8"));
    delete raw.policy.builtin.GIT001;
    writeFileSync(cachePath, JSON.stringify(raw));
    expect((await check("git push --force origin main")).permitted).toBe(false);
  });

  it("lockdown still allows benign commands", async () => {
    cachePolicy(policy());
    unlinkSync(cachePath);
    expect((await check("ls -la")).permitted).toBe(true);
    expect((await check("git status")).permitted).toBe(true);
  });

  it("an unchanged cache (key order aside) is not treated as edited", async () => {
    cachePolicy(policy());
    const raw = JSON.parse(readFileSync(cachePath, "utf8"));
    const reordered = { fetched_at: raw.fetched_at, etag: raw.etag, policy: Object.fromEntries(Object.entries(raw.policy).reverse()) };
    writeFileSync(cachePath, JSON.stringify(reordered));
    expect(cache.loadEffectivePolicy({ cachePath, guardConfigPath }).source).toBe("server_cache");
  });

  it("an unreadable marker file still means enforcing", async () => {
    cachePolicy(policy());
    writeFileSync(cache.enforcementMarkerPath(cachePath), "garbage");
    expect(cache.loadEffectivePolicy({ cachePath, guardConfigPath }).source).toBe("enforced_lockdown");
  });

  it("without a marker, a missing policy still falls back to observe (no org ever enforced)", async () => {
    expect(cache.loadEffectivePolicy({ cachePath, guardConfigPath }).source).toBe("none");
    expect((await check("rm -rf ~")).permitted).toBe(true);
  });

  it("records the marker on first load of an enforcing cache written before markers existed", () => {
    writeFileSync(cachePath, JSON.stringify({ policy: policy(), etag: "etag-m", fetched_at: Date.now() }));
    expect(existsSync(cache.enforcementMarkerPath(cachePath))).toBe(false);
    expect(cache.loadEffectivePolicy({ cachePath, guardConfigPath }).source).toBe("server_cache");
    expect(existsSync(cache.enforcementMarkerPath(cachePath))).toBe(true);
  });

  it("explicit logout or auth (clearCachedPolicy) removes the marker", () => {
    cachePolicy(policy());
    cache.clearCachedPolicy(cachePath);
    expect(cache.readEnforcementMarker(cachePath)).toBeNull();
    expect(cache.loadEffectivePolicy({ cachePath, guardConfigPath }).source).toBe("none");
  });

  it("doctor reports lockdown as active enforcement with its reason", async () => {
    cachePolicy(policy());
    unlinkSync(cachePath);
    const report = doctor.inspectDoctorState({ cachePath, guardConfigPath, config: { apiBaseUrl: "x", schemaVersion: 1 } as never });
    expect(report.enforcementActive).toBe(true);
    expect(report.lockdownReason).toBe("policy_missing");
    expect(doctor.formatDoctorReport(report)).toContain("lockdown");
  });
});
