import { execFileSync } from "node:child_process";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  getPolicyCacheAgeMs,
  loadEffectivePolicy,
  POLICY_REFRESH_INTERVAL_MS,
  readCachedPolicy,
  readPolicyRejection,
  shouldRefreshPolicy,
  writeCachedPolicyAtomic,
  writePolicyRejectionAtomic,
} from "../src/policy/cache.js";
import { fetchPolicy, repoSlugFromRemoteUrl } from "../src/policy/fetch.js";
import { enforcePreExec } from "../src/policy/enforce.js";
import {
  computeMaxPolicyApprovalExpiresS,
  computePreExecTimeoutS,
  validatePolicy,
  type Policy,
} from "../src/policy/types.js";
import {
  buildPolicySummary,
  formatPolicySummary,
} from "../src/commands/policy.js";
import { formatDoctorReport, inspectDoctorState } from "../src/commands/doctor.js";
import { createPolicyRefresher } from "../src/commands/daemon.js";
import type { AgentConfig } from "../src/config.js";

function makePolicy(overrides: Partial<Policy> = {}): Policy {
  return {
    version: 1,
    etag: "etag-v1",
    workspace_id: "ws_acme",
    updated_at: "2026-11-25T12:00:00Z",
    mode: "observe",
    offline: "last_known",
    builtin: {
      CLOUD001: { enabled: true, action: "block", severity: "critical" },
    },
    custom: [
      {
        id: "cust_1",
        name: "Block sudo",
        enabled: true,
        version: 1,
        message: "Do not use sudo",
        when: [{ field: "command", op: "starts_with", value: "sudo " }],
        action: "block",
        severity: "high",
        scope: { repos: ["acme/*"] },
      },
    ],
    allow: {
      commands: ["rm -rf dist"],
      paths: ["test/fixtures"],
      repos: ["acme/sandbox"],
    },
    ...overrides,
  };
}

function makeConfig(apiBaseUrl: string, apiKey?: string): AgentConfig {
  return {
    apiBaseUrl,
    apiKey,
    schemaVersion: 1,
  };
}

async function startMockServer(
  handler: (req: IncomingMessage, res: ServerResponse) => void,
): Promise<{ url: string; close: () => Promise<void> }> {
  const server = createServer(handler);
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = server.address();
  if (!addr || typeof addr === "string") {
    throw new Error("failed to bind mock server");
  }
  return {
    url: `http://127.0.0.1:${addr.port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

describe("policy validation", () => {
  it("accepts a valid Policy object including optional approval and org metadata", () => {
    const res = validatePolicy(
      makePolicy({
        org_name: "Acme",
        org_slug: "acme",
        builtin: {
          CLOUD001: {
            enabled: true,
            action: "require_approval",
            severity: "critical",
            approval: { expires_s: 180, offline_fallback: "deny" },
          },
        },
        custom: [
          {
            id: "cust_approval",
            name: "Approve deploy",
            enabled: true,
            version: 1,
            message: "Needs approval",
            when: [{ field: "command", op: "starts_with", value: "./deploy" }],
            action: "require_approval",
            severity: "high",
            approval: { expires_s: 60, offline_fallback: "allow" },
          },
        ],
      }),
    );
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.value.org_name).toBe("Acme");
      expect(res.value.org_slug).toBe("acme");
      expect(res.value.builtin.CLOUD001?.approval).toEqual({
        expires_s: 180,
        offline_fallback: "deny",
      });
      expect(res.value.custom[0]?.approval).toEqual({
        expires_s: 60,
        offline_fallback: "allow",
      });
    }
  });

  it("rejects invalid approval config on builtin overrides and custom rules", () => {
    expect(
      validatePolicy({
        ...makePolicy(),
        builtin: {
          CLOUD001: {
            enabled: true,
            action: "require_approval",
            approval: { expires_s: 0 },
          },
        },
      }).ok,
    ).toBe(false);
    expect(
      validatePolicy({
        ...makePolicy(),
        builtin: {
          CLOUD001: {
            enabled: true,
            action: "require_approval",
            approval: { offline_fallback: "flag" },
          },
        },
      }).ok,
    ).toBe(false);
    expect(
      validatePolicy({
        ...makePolicy(),
        custom: [
          {
            id: "c_bad_approval",
            name: "Bad approval",
            enabled: true,
            version: 1,
            message: "m",
            when: [{ field: "command", op: "contains", value: "x" }],
            action: "require_approval",
            severity: "high",
            approval: { expires_s: -5 },
          },
        ],
      }).ok,
    ).toBe(false);
  });

  it("rejects wrong version, invalid mode, invalid offline, or missing allowlists", () => {
    expect(validatePolicy({ ...makePolicy(), version: 2 }).ok).toBe(false);
    expect(validatePolicy({ ...makePolicy(), mode: "block" }).ok).toBe(false);
    expect(validatePolicy({ ...makePolicy(), offline: "deny" }).ok).toBe(false);
    expect(validatePolicy({ ...makePolicy(), allow: { commands: [] } }).ok).toBe(
      false,
    );
    expect(
      validatePolicy({
        ...makePolicy(),
        builtin: { CLOUD001: { enabled: true, action: "drop" } },
      }).ok,
    ).toBe(false);
    expect(
      validatePolicy({
        ...makePolicy(),
        custom: [
          {
            id: "c1",
            name: "empty when",
            enabled: true,
            version: 1,
            message: "m",
            when: [],
            action: "flag",
            severity: "warn",
          },
        ],
      }).ok,
    ).toBe(false);
  });
});

describe("policy fetch and cache", () => {
  let workDir: string;
  let cachePath: string;
  let guardConfigPath: string;

  beforeEach(() => {
    workDir = mkdtempSync(join(tmpdir(), "agentreel-policy-test-"));
    cachePath = join(workDir, "policy.json");
    guardConfigPath = join(workDir, "guard-config.json");
  });

  afterEach(() => {
    rmSync(workDir, { recursive: true, force: true });
  });

  it("fetches 200 from mocked HTTP server, writes atomically with 0600 permissions, and sends Bearer auth", async () => {
    const policy = makePolicy({ etag: "etag-200" });
    let seenAuth: string | undefined;
    let seenPath: string | undefined;
    let seenIfNoneMatch: string | undefined;

    const srv = await startMockServer((req, res) => {
      seenAuth = req.headers.authorization;
      seenPath = req.url;
      seenIfNoneMatch = req.headers["if-none-match"] as string | undefined;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(policy));
    });

    try {
      const now = 1_764_000_000_000;
      const result = await fetchPolicy({
        config: makeConfig(srv.url, "ar_live_testkey123"),
        cachePath,
        cwd: workDir,
        now: () => now,
        log: () => {},
      });

      expect(result.status).toBe("updated");
      expect(seenPath).toBe("/api/v1/policy");
      expect(seenAuth).toBe("Bearer ar_live_testkey123");
      expect(seenIfNoneMatch).toBeUndefined();

      const mode = statSync(cachePath).mode & 0o777;
      expect(mode).toBe(0o600);

      const files = readdirSync(workDir);
      expect(files).toEqual(["policy.json"]);

      const stored = JSON.parse(readFileSync(cachePath, "utf8"));
      expect(stored).toEqual({
        policy,
        etag: "etag-200",
        fetched_at: now,
      });
    } finally {
      await srv.close();
    }
  });

  it("sends If-None-Match on subsequent fetch and keeps policy while bumping fetched_at on 304", async () => {
    const policy = makePolicy({ etag: "etag-304-test" });
    const t0 = 1_764_000_000_000;
    const t1 = t0 + 6 * 60_000;
    writeCachedPolicyAtomic(
      { policy, etag: policy.etag, fetched_at: t0 },
      cachePath,
    );

    let seenIfNoneMatch: string | undefined;
    const srv = await startMockServer((req, res) => {
      seenIfNoneMatch = req.headers["if-none-match"] as string | undefined;
      res.writeHead(304);
      res.end();
    });

    try {
      const res = await fetchPolicy({
        config: makeConfig(srv.url, "ar_live_key"),
        cachePath,
        now: () => t1,
        log: () => {},
      });

      expect(seenIfNoneMatch).toBe("etag-304-test");
      expect(res.status).toBe("not_modified");
      if (res.status === "not_modified") {
        expect(res.fetchedAt).toBe(t1);
        expect(res.etag).toBe("etag-304-test");
        expect(res.policy).toEqual(policy);
      }

      const cached = readCachedPolicy(cachePath);
      expect(cached?.fetched_at).toBe(t1);
      expect(cached?.policy).toEqual(policy);
      expect(statSync(cachePath).mode & 0o777).toBe(0o600);
    } finally {
      await srv.close();
    }
  });

  it.each([404, 401, 403, 500, 503])(
    "keeps last-known cache and logs quietly on HTTP %i",
    async (statusCode) => {
      const policy = makePolicy({ etag: "etag-keep" });
      const t0 = 1_764_000_000_000;
      writeCachedPolicyAtomic(
        { policy, etag: policy.etag, fetched_at: t0 },
        cachePath,
      );

      const logs: string[] = [];
      const srv = await startMockServer((_req, res) => {
        res.writeHead(statusCode, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "unavailable" }));
      });

      try {
        const result = await fetchPolicy({
          config: makeConfig(srv.url, "ar_live_key"),
          cachePath,
          now: () => t0 + 10_000,
          log: (m) => logs.push(m),
        });

        expect(result.status).toBe("kept_cache");
        if (result.status === "kept_cache") {
          expect(result.httpStatus).toBe(statusCode);
          expect(result.keptCache).toBe(true);
        }
        expect(logs.length).toBeGreaterThan(0);

        const cached = readCachedPolicy(cachePath);
        expect(cached).toEqual({
          policy,
          etag: "etag-keep",
          fetched_at: t0,
        });
      } finally {
        await srv.close();
      }
    },
  );

  it("keeps last-known cache on timeout without throwing", async () => {
    const policy = makePolicy({ etag: "etag-timeout" });
    const t0 = 1_764_000_000_000;
    writeCachedPolicyAtomic(
      { policy, etag: policy.etag, fetched_at: t0 },
      cachePath,
    );

    const logs: string[] = [];
    const hangingFetch: typeof fetch = (_input, init) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          const err = new Error("aborted");
          err.name = "AbortError";
          reject(err);
        });
      });

    const result = await fetchPolicy({
      config: makeConfig("http://127.0.0.1:1", "ar_live_key"),
      cachePath,
      timeoutMs: 30,
      fetchImpl: hangingFetch,
      log: (m) => logs.push(m),
    });

    expect(result.status).toBe("kept_cache");
    if (result.status === "kept_cache") {
      expect(result.reason).toContain("timeout");
      expect(result.keptCache).toBe(true);
    }
    expect(logs.length).toBeGreaterThan(0);
    expect(readCachedPolicy(cachePath)?.etag).toBe("etag-timeout");
  });

  it("keeps last-known cache on network error without throwing", async () => {
    const policy = makePolicy({ etag: "etag-neterr" });
    writeCachedPolicyAtomic(
      { policy, etag: policy.etag, fetched_at: 1_764_000_000_000 },
      cachePath,
    );

    const failingFetch: typeof fetch = async () => {
      throw new Error("ECONNREFUSED");
    };

    const result = await fetchPolicy({
      config: makeConfig("http://127.0.0.1:1", "ar_live_key"),
      cachePath,
      fetchImpl: failingFetch,
      log: () => {},
    });

    expect(result.status).toBe("kept_cache");
    expect(readCachedPolicy(cachePath)?.etag).toBe("etag-neterr");
  });

  it("rejects an invalid 200 policy payload and keeps the existing cache", async () => {
    const valid = makePolicy({ etag: "etag-good" });
    writeCachedPolicyAtomic(
      { policy: valid, etag: valid.etag, fetched_at: 1_764_000_000_000 },
      cachePath,
    );

    const logs: string[] = [];
    const badFetch: typeof fetch = async () =>
      new Response(JSON.stringify({ version: 99, mode: "invalid" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });

    const result = await fetchPolicy({
      config: makeConfig("https://api.agentreel.dev", "ar_live_key"),
      cachePath,
      fetchImpl: badFetch,
      log: (m) => logs.push(m),
    });

    expect(result.status).toBe("invalid_policy");
    if (result.status === "invalid_policy") {
      expect(result.keptCache).toBe(true);
    }
    expect(logs.length).toBeGreaterThan(0);
    expect(readCachedPolicy(cachePath)?.etag).toBe("etag-good");
  });

  it("makes no fetch for an unlinked user", async () => {
    const fetchSpy = vi.fn<typeof fetch>();
    const result = await fetchPolicy({
      config: makeConfig("https://api.agentreel.dev", undefined),
      cachePath,
      fetchImpl: fetchSpy,
      log: () => {},
    });

    expect(result).toEqual({ status: "unlinked" });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("treats corrupt or unreadable cache files as no cache without throwing", () => {
    writeFileSync(cachePath, "{not valid json", "utf8");
    expect(readCachedPolicy(cachePath)).toBeNull();
    expect(
      loadEffectivePolicy({ cachePath, guardConfigPath }).source,
    ).toBe("none");

    // Unreadable path: directory in place of cache file
    rmSync(cachePath, { force: true });
    mkdirSync(cachePath);
    expect(readCachedPolicy(cachePath)).toBeNull();
    expect(
      loadEffectivePolicy({ cachePath, guardConfigPath }).source,
    ).toBe("none");
  });

  it("uses last_known cached policy indefinitely regardless of age", () => {
    const policy = makePolicy({ offline: "last_known", etag: "etag-old" });
    const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60_000;
    writeCachedPolicyAtomic(
      { policy, etag: policy.etag, fetched_at: thirtyDaysAgo },
      cachePath,
    );

    const loaded = loadEffectivePolicy({ cachePath, guardConfigPath });
    expect(loaded.source).toBe("server_cache");
    expect(loaded.policy?.etag).toBe("etag-old");
  });

  it("falls back to local guard-config.json in observe mode when no server cache exists", () => {
    writeFileSync(
      guardConfigPath,
      JSON.stringify({
        enabled: true,
        policyMode: "warn",
        rules: {
          CLOUD001: { enabled: false },
          GIT001: { enabled: true, severity: "critical" },
        },
        allowlists: {
          commands: ["rm -rf build"],
          paths: ["tmp/scratch"],
        },
      }),
      "utf8",
    );

    const loaded = loadEffectivePolicy({ cachePath, guardConfigPath });
    expect(loaded.source).toBe("local_fallback");
    expect(loaded.etag).toBeNull();
    expect(loaded.fetchedAt).toBeNull();
    expect(loaded.policy?.mode).toBe("observe");
    expect(loaded.policy?.offline).toBe("last_known");
    expect(loaded.policy?.builtin.CLOUD001).toEqual({
      enabled: false,
      action: "flag",
    });
    expect(loaded.policy?.builtin.GIT001).toEqual({
      enabled: true,
      action: "flag",
      severity: "critical",
    });
    expect(loaded.policy?.allow.commands).toEqual(["rm -rf build"]);
    expect(loaded.policy?.allow.paths).toEqual(["tmp/scratch"]);
  });

  it("handles clock skew when fetched_at is in the future for both age display and refresh logic", () => {
    const now = 1_764_000_000_000;
    const futureFetchedAt = now + 2 * 60 * 60_000;
    const policy = makePolicy({ etag: "etag-skew" });
    const cached = {
      policy,
      etag: policy.etag,
      fetched_at: futureFetchedAt,
    };

    const ageInfo = getPolicyCacheAgeMs(futureFetchedAt, now);
    expect(ageInfo.ageMs).toBe(0);
    expect(ageInfo.clockSkewed).toBe(true);

    expect(shouldRefreshPolicy(cached, now, POLICY_REFRESH_INTERVAL_MS)).toBe(
      true,
    );

    const summary = buildPolicySummary(
      {
        source: "server_cache",
        policy,
        etag: policy.etag,
        fetchedAt: futureFetchedAt,
      },
      now,
    );
    expect(summary.age).toContain("0s ago");
    expect(summary.age).toContain("clock skew");
    expect(summary.age).not.toContain("-");

    const formatted = formatPolicySummary(
      {
        source: "server_cache",
        policy,
        etag: policy.etag,
        fetchedAt: futureFetchedAt,
      },
      now,
    );
    expect(formatted).toContain("server cache");
    expect(formatted).toContain("etag-skew");
    expect(formatted).toContain("observe");
    expect(formatted).toContain("last_known");
    expect(formatted).toContain("builtin overrides: 1");
    expect(formatted).toContain("custom rules:      1");
    expect(formatted).toContain("allow entries:     3");
  });

  it("daemon policy refresher runs immediately, then waits 5 minutes across 30s ticks", async () => {
    let mono = 0;
    const fetchSpy = vi.fn(async () => ({ status: "unlinked" as const }));
    const refresh = createPolicyRefresher(
      POLICY_REFRESH_INTERVAL_MS,
      fetchSpy,
      () => mono,
    );

    // Tick 0: runs immediately
    await refresh();
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    // Ticks at 30s .. 270s: skipped
    for (let sec = 30; sec < 300; sec += 30) {
      mono = sec * 1000;
      const res = await refresh();
      expect(res).toBeNull();
    }
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    // Tick at 300s (5 min): runs again
    mono = 300 * 1000;
    await refresh();
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it("createPolicyRefresher swallows a throwing fetchFn without rejecting", async () => {
    let mono = 0;
    const throwingFetch = vi.fn(async () => {
      throw new Error("unexpected network failure");
    });
    const refresh = createPolicyRefresher(
      POLICY_REFRESH_INTERVAL_MS,
      throwingFetch,
      () => mono,
    );

    await expect(refresh()).resolves.toBeNull();
    expect(throwingFetch).toHaveBeenCalledTimes(1);

    mono = 30_000;
    await expect(refresh()).resolves.toBeNull();
    expect(throwingFetch).toHaveBeenCalledTimes(1);

    mono = POLICY_REFRESH_INTERVAL_MS;
    await expect(refresh()).resolves.toBeNull();
    expect(throwingFetch).toHaveBeenCalledTimes(2);
  });
});

describe("initCommand policy fetch behaviour", () => {
  const initHome = mkdtempSync(join(tmpdir(), "agentreel-init-policy-"));

  afterEach(() => {
    vi.restoreAllMocks();
    rmSync(join(initHome, ".agentreel"), { recursive: true, force: true });
    rmSync(join(initHome, ".claude"), { recursive: true, force: true });
    rmSync(join(initHome, ".cursor"), { recursive: true, force: true });
  });

  it("does not call fetch during agentreel init when unlinked", async () => {
    vi.resetModules();
    const prevHome = process.env.HOME;
    process.env.HOME = initHome;
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const fetchPolicyMock = vi.fn(async () => ({ status: "unlinked" as const }));
    vi.doMock("../src/policy/fetch.js", () => ({
      fetchPolicy: fetchPolicyMock,
    }));
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    try {
      const { initCommand } = await import("../src/commands/init.js");
      const { closeDb } = await import("../src/db.js");
      await initCommand({ claude: false, cursor: false });
      closeDb();
      expect(fetchPolicyMock).not.toHaveBeenCalled();
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      vi.doUnmock("../src/policy/fetch.js");
      logSpy.mockRestore();
      process.env.HOME = prevHome;
    }
  });

  it("fetches policy once during agentreel init when already linked", async () => {
    vi.resetModules();
    const prevHome = process.env.HOME;
    process.env.HOME = initHome;

    const policy = makePolicy({ etag: "etag-init-linked" });
    let policyCalls = 0;
    const srv = await startMockServer((req, res) => {
      const pathname = new URL(req.url ?? "/", "http://127.0.0.1").pathname;
      if (pathname === "/api/v1/policy") {
        policyCalls++;
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(policy));
        return;
      }
      res.writeHead(404);
      res.end();
    });

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      mkdirSync(join(initHome, ".agentreel"), { recursive: true });
      writeFileSync(
        join(initHome, ".agentreel", "config.json"),
        JSON.stringify({
          apiBaseUrl: srv.url,
          apiKey: "ar_live_linkedkey",
          schemaVersion: 1,
        }),
        "utf8",
      );

      const { initCommand } = await import("../src/commands/init.js");
      const { closeDb } = await import("../src/db.js");
      await initCommand({ claude: false, cursor: false });
      closeDb();

      expect(policyCalls).toBe(1);
      const cached = readCachedPolicy(join(initHome, ".agentreel", "policy.json"));
      expect(cached?.etag).toBe("etag-init-linked");
    } finally {
      logSpy.mockRestore();
      await srv.close();
      process.env.HOME = prevHome;
    }
  });

  it("fetches policy once during agentreel link and tolerates 404 from old servers", async () => {
    vi.resetModules();
    const prevHome = process.env.HOME;
    process.env.HOME = initHome;

    let ingestCalls = 0;
    let policyCalls = 0;
    const srv = await startMockServer((req, res) => {
      const pathname = new URL(req.url ?? "/", "http://127.0.0.1").pathname;
      if (pathname === "/api/v1/sessions/ingest") {
        ingestCalls++;
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      if (pathname === "/api/v1/policy") {
        policyCalls++;
        res.writeHead(404);
        res.end();
        return;
      }
      res.writeHead(404);
      res.end();
    });

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      const { linkCommand } = await import("../src/commands/auth.js");
      await linkCommand("ar_live_validkey123", { api: srv.url });
      expect(ingestCalls).toBe(1);
      expect(policyCalls).toBe(1);
    } finally {
      logSpy.mockRestore();
      await srv.close();
      process.env.HOME = prevHome;
    }
  });
});

describe("unsupported regex rejection on policy fetch and doctor output", () => {
  let tmpDir: string;
  let cachePath: string;
  let guardConfigPath: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "agentreel-regex-reject-"));
    cachePath = join(tmpDir, "policy.json");
    guardConfigPath = join(tmpDir, "guard.json");
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("rejects policy with unsupported regex, preserves last-known cache, logs, and surfaces in doctor", async () => {
    const goodPolicy = makePolicy({ etag: "etag-good-v1" });
    const t0 = 1_764_000_000_000;
    writeCachedPolicyAtomic(
      { policy: goodPolicy, etag: goodPolicy.etag, fetched_at: t0 },
      cachePath,
    );

    const badPolicy = makePolicy({
      etag: "etag-bad-v2",
      custom: [
        {
          id: "cust_bad_regex_rule",
          name: "Bad overlapping regex",
          enabled: true,
          version: 1,
          message: "Bad regex",
          when: [
            { field: "command", op: "contains", value: "curl" },
            { field: "command", op: "regex", value: "a.*a.*a.*a.*a.*a.*a.*a.*b" },
          ],
          action: "block",
          severity: "critical",
          scope: {},
        },
      ],
    });

    let serveBad = true;
    const srv = await startMockServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify(
          serveBad ? badPolicy : makePolicy({ etag: "etag-fixed-v3" }),
        ),
      );
    });

    const logs: string[] = [];
    try {
      const rejected = await fetchPolicy({
        config: makeConfig(srv.url, "ar_live_key"),
        cachePath,
        now: () => t0 + 5_000,
        log: (m) => logs.push(m),
      });

      expect(rejected.status).toBe("invalid_policy");
      if (rejected.status === "invalid_policy") {
        expect(rejected.keptCache).toBe(true);
        expect(rejected.error).toContain("cust_bad_regex_rule");
        expect(rejected.error).toContain("when[1]");
      }

      // Last-known cache must not be overwritten.
      const cached = readCachedPolicy(cachePath);
      expect(cached).toEqual({
        policy: goodPolicy,
        etag: "etag-good-v1",
        fetched_at: t0,
      });

      // A log line was written.
      expect(
        logs.some(
          (l) => l.includes("cust_bad_regex_rule") && l.includes("when[1]"),
        ),
      ).toBe(true);

      // Rejection sidecar recorded and doctor shows exact warning string.
      const rejection = readPolicyRejection(cachePath);
      expect(rejection?.reason).toBe("unsupported_regex");
      expect(rejection?.rule_id).toBe("cust_bad_regex_rule");
      expect(rejection?.condition_index).toBe(1);

      const report = inspectDoctorState({
        cachePath,
        guardConfigPath,
        claudeSettingsPath: join(tmpDir, "missing-claude.json"),
        cursorHooksPath: join(tmpDir, "missing-cursor.json"),
        config: makeConfig(srv.url, "ar_live_key"),
        now: () => t0 + 10_000,
      });
      expect(report.lastRejection?.rule_id).toBe("cust_bad_regex_rule");
      const output = formatDoctorReport(report);
      expect(output).toContain(
        "policy rejected by agent: rule cust_bad_regex_rule has an unsupported regex; last known policy still in use",
      );

      // Next valid fetch overwrites cache and clears the rejection warning.
      serveBad = false;
      const recovered = await fetchPolicy({
        config: makeConfig(srv.url, "ar_live_key"),
        cachePath,
        now: () => t0 + 20_000,
        log: (m) => logs.push(m),
      });
      expect(recovered.status).toBe("updated");
      expect(readCachedPolicy(cachePath)?.etag).toBe("etag-fixed-v3");
      expect(readPolicyRejection(cachePath)).toBeNull();

      const recoveredReport = inspectDoctorState({
        cachePath,
        guardConfigPath,
        claudeSettingsPath: join(tmpDir, "missing-claude.json"),
        cursorHooksPath: join(tmpDir, "missing-cursor.json"),
        config: makeConfig(srv.url, "ar_live_key"),
        now: () => t0 + 25_000,
      });
      expect(formatDoctorReport(recoveredReport)).not.toContain(
        "policy rejected by agent:",
      );
    } finally {
      await srv.close();
    }
  });

  it("uses no-cache wording in doctor and fetch log on first fetch rejection with no cached policy", async () => {
    const t0 = 1_764_000_000_000;
    const badPolicy = makePolicy({
      etag: "etag-first-bad",
      custom: [
        {
          id: "cust_first_fetch_bad",
          name: "Bad first-fetch regex",
          enabled: true,
          version: 1,
          message: "Bad regex on first fetch",
          when: [
            { field: "command", op: "regex", value: "\\w+\\s+\\w+" },
          ],
          action: "block",
          severity: "high",
          scope: {},
        },
      ],
    });

    const srv = await startMockServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(badPolicy));
    });

    const logs: string[] = [];
    try {
      const rejected = await fetchPolicy({
        config: makeConfig(srv.url, "ar_live_key"),
        cachePath,
        now: () => t0,
        log: (m) => logs.push(m),
      });

      expect(rejected.status).toBe("invalid_policy");
      if (rejected.status === "invalid_policy") {
        expect(rejected.keptCache).toBe(false);
        expect(rejected.error).toContain("cust_first_fetch_bad");
      }

      expect(readCachedPolicy(cachePath)).toBeNull();
      expect(logs.some((l) => l.includes("keeping last-known cache"))).toBe(
        false,
      );
      expect(
        logs.some((l) =>
          l.includes(
            "the rejected policy was not installed and org enforcement is off until a valid policy is cached",
          ),
        ),
      ).toBe(true);

      const report = inspectDoctorState({
        cachePath,
        guardConfigPath,
        claudeSettingsPath: join(tmpDir, "missing-claude.json"),
        cursorHooksPath: join(tmpDir, "missing-cursor.json"),
        config: makeConfig(srv.url, "ar_live_key"),
        now: () => t0 + 5_000,
      });
      const output = formatDoctorReport(report);
      expect(output).toContain(
        "policy rejected by agent: rule cust_first_fetch_bad has an unsupported regex; the rejected policy was not installed and org enforcement is off until a valid policy is cached",
      );
      expect(output).not.toContain("last known policy still in use");
    } finally {
      await srv.close();
    }
  });
});

describe("govern API v1 (C1) additive fields, repo query, 304, no-org, org_id, expires_s, and severity", () => {
  let tmpDir: string;
  let cachePath: string;
  let guardConfigPath: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "agentreel-c1-fetch-"));
    cachePath = join(tmpDir, "policy.json");
    guardConfigPath = join(tmpDir, "guard-config.json");
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("keeps repoSlugFromRemoteUrl parsing intact while never sending ?repo= on GET /api/v1/policy regardless of cwd", async () => {
    expect(repoSlugFromRemoteUrl("https://github.com/acme/webapp.git")).toBe("acme/webapp");
    expect(repoSlugFromRemoteUrl("https://github.com/acme/webapp")).toBe("acme/webapp");
    expect(repoSlugFromRemoteUrl("https://token@github.com/acme/webapp.git")).toBe("acme/webapp");
    expect(repoSlugFromRemoteUrl("ssh://git@github.com/acme/webapp.git")).toBe("acme/webapp");
    expect(repoSlugFromRemoteUrl("ssh://git@github.com:22/acme/webapp.git")).toBe("acme/webapp");
    expect(repoSlugFromRemoteUrl("git@github.com:acme/webapp.git")).toBe("acme/webapp");
    expect(repoSlugFromRemoteUrl("git@github.com:acme/webapp")).toBe("acme/webapp");
    expect(repoSlugFromRemoteUrl("/local/bare/repo.git")).toBeUndefined();
    expect(repoSlugFromRemoteUrl("file:///local/bare/repo.git")).toBeUndefined();

    const httpsRepo = join(tmpDir, "https-repo");
    const sshRepo = join(tmpDir, "ssh-repo");
    const noRemoteDir = join(tmpDir, "no-remote");
    mkdirSync(httpsRepo, { recursive: true });
    mkdirSync(sshRepo, { recursive: true });
    mkdirSync(noRemoteDir, { recursive: true });

    execFileSync("git", ["init"], { cwd: httpsRepo, stdio: "ignore" });
    execFileSync("git", ["remote", "add", "origin", "https://github.com/acme/api-server.git"], {
      cwd: httpsRepo,
      stdio: "ignore",
    });

    execFileSync("git", ["init"], { cwd: sshRepo, stdio: "ignore" });
    execFileSync("git", ["remote", "add", "origin", "git@github.com:acme/ssh-service.git"], {
      cwd: sshRepo,
      stdio: "ignore",
    });

    const seenUrls: string[] = [];
    const srv = await startMockServer((req, res) => {
      seenUrls.push(req.url ?? "");
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(makePolicy({ etag: `etag-${seenUrls.length}` })));
    });

    try {
      await fetchPolicy({
        config: makeConfig(srv.url, "ar_live_key"),
        cachePath: join(tmpDir, "p1.json"),
        cwd: httpsRepo,
        log: () => {},
      });
      await fetchPolicy({
        config: makeConfig(srv.url, "ar_live_key"),
        cachePath: join(tmpDir, "p2.json"),
        cwd: sshRepo,
        log: () => {},
      });
      await fetchPolicy({
        config: makeConfig(srv.url, "ar_live_key"),
        cachePath: join(tmpDir, "p3.json"),
        cwd: noRemoteDir,
        log: () => {},
      });
      await fetchPolicy({
        config: makeConfig(srv.url, "ar_live_key"),
        cachePath: join(tmpDir, "p4.json"),
        cwd: httpsRepo,
        repo: "acme/explicit-ignored",
        log: () => {},
      });

      expect(seenUrls).toEqual([
        "/api/v1/policy",
        "/api/v1/policy",
        "/api/v1/policy",
        "/api/v1/policy",
      ]);
    } finally {
      await srv.close();
    }
  });

  it("on 304 keeps cached policy, updates fetched_at, clears rejected sidecar, and logs nothing", async () => {
    const t0 = 1_764_500_000_000;
    const t1 = t0 + 10 * 60_000;
    const cachedPolicy = makePolicy({ etag: "etag-304-clean", mode: "enforce" });
    writeCachedPolicyAtomic(
      { policy: cachedPolicy, etag: cachedPolicy.etag, fetched_at: t0 },
      cachePath,
    );
    writePolicyRejectionAtomic(
      { ts: t0 + 1000, error: "prior bad fetch", reason: "invalid_policy" },
      cachePath,
    );
    expect(readPolicyRejection(cachePath)).not.toBeNull();

    let seenIfNoneMatch: string | undefined;
    const srv = await startMockServer((req, res) => {
      seenIfNoneMatch = req.headers["if-none-match"] as string | undefined;
      res.writeHead(304);
      res.end();
    });

    const logs: string[] = [];
    try {
      const res = await fetchPolicy({
        config: makeConfig(srv.url, "ar_live_key"),
        cachePath,
        cwd: tmpDir,
        now: () => t1,
        log: (m) => logs.push(m),
      });

      expect(res.status).toBe("not_modified");
      expect(seenIfNoneMatch).toBe("etag-304-clean");
      expect(logs).toEqual([]);
      expect(readPolicyRejection(cachePath)).toBeNull();
      const updated = readCachedPolicy(cachePath);
      expect(updated?.etag).toBe("etag-304-clean");
      expect(updated?.fetched_at).toBe(t1);
      expect(updated?.policy).toEqual(cachedPolicy);
    } finally {
      await srv.close();
    }
  });

  it("accepts 200 with org_id null, mode observe, and empty builtin/custom/allow as no-org, caches it, and doctor says no org policy", async () => {
    const t0 = 1_764_510_000_000;
    const noOrgPayload = {
      version: 1,
      etag: "etag-no-org",
      org_id: null,
      workspace_id: null,
      updated_at: "2026-11-26T00:00:00Z",
      fetched_at: "2026-11-26T00:00:01Z",
      mode: "observe",
      offline: "last_known",
      builtin: {},
      custom: [],
      allow: { commands: [], paths: [], repos: [] },
      unknown_extra_field: { ignored: true },
    };

    const srv = await startMockServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(noOrgPayload));
    });

    try {
      const fetched = await fetchPolicy({
        config: makeConfig(srv.url, "ar_live_key"),
        cachePath,
        cwd: tmpDir,
        now: () => t0,
        log: () => {},
      });

      expect(fetched.status).toBe("updated");
      const cached = readCachedPolicy(cachePath);
      expect(cached).not.toBeNull();
      expect(cached?.policy.org_id).toBeNull();
      expect(cached?.policy.fetched_at).toBe("2026-11-26T00:00:01Z");
      expect((cached?.policy as unknown as Record<string, unknown>).unknown_extra_field).toBeUndefined();

      const report = inspectDoctorState({
        cachePath,
        guardConfigPath,
        claudeSettingsPath: join(tmpDir, "missing-claude.json"),
        cursorHooksPath: join(tmpDir, "missing-cursor.json"),
        config: makeConfig(srv.url, "ar_live_key"),
        now: t0 + 1000,
      });
      expect(report.noOrgPolicy).toBe(true);
      expect(report.enforcementActive).toBe(false);
      const output = formatDoctorReport(report);
      expect(output).toContain("no org policy");

      const summary = buildPolicySummary(
        loadEffectivePolicy({ cachePath, guardConfigPath }),
        t0 + 1000,
      );
      expect(summary.source).toContain("no org policy");

      // Also accepts org_id: null when workspace_id is omitted
      const omittedWs = validatePolicy({
        version: 1,
        etag: "etag-no-org-2",
        org_id: null,
        updated_at: "2026-11-26T00:00:00Z",
        mode: "observe",
        offline: "last_known",
        builtin: {},
        custom: [],
        allow: { commands: [], paths: [], repos: [] },
      });
      expect(omittedWs.ok).toBe(true);

      // Rejects org_id: null if mode is enforce or rules/allow are non-empty
      expect(
        validatePolicy({ ...noOrgPayload, mode: "enforce" }).ok,
      ).toBe(false);
      expect(
        validatePolicy({
          ...noOrgPayload,
          builtin: { FS001: { enabled: true, action: "flag" } },
        }).ok,
      ).toBe(false);
      expect(
        validatePolicy({
          ...noOrgPayload,
          custom: [
            {
              id: "cust_no_org",
              name: "Custom rule",
              enabled: true,
              version: 1,
              message: "Blocked",
              when: [{ field: "command", op: "contains", value: "sudo" }],
              action: "block",
              severity: "high",
            },
          ],
        }).ok,
      ).toBe(false);
      expect(
        validatePolicy({
          ...noOrgPayload,
          allow: { commands: ["echo ok"], paths: [], repos: [] },
        }).ok,
      ).toBe(false);
      expect(
        validatePolicy({
          ...noOrgPayload,
          allow: { commands: [], paths: ["/tmp/ok"], repos: [] },
        }).ok,
      ).toBe(false);
      expect(
        validatePolicy({
          ...noOrgPayload,
          allow: { commands: [], paths: [], repos: ["acme/sandbox"] },
        }).ok,
      ).toBe(false);
    } finally {
      await srv.close();
    }
  });

  it("accepts matching org_id and workspace_id, rejects mismatch with a clear doctor message, and ignores unknown top-level fields", async () => {
    const t0 = 1_764_520_000_000;
    const validMatching = validatePolicy({
      ...makePolicy({ workspace_id: "org_123" }),
      org_id: "org_123",
      fetched_at: "2026-11-26T00:00:00Z",
      extra_top_level_key: "ignored",
    });
    expect(validMatching.ok).toBe(true);
    if (validMatching.ok) {
      expect(validMatching.value.org_id).toBe("org_123");
      expect(validMatching.value.workspace_id).toBe("org_123");
      expect(validMatching.value.fetched_at).toBe("2026-11-26T00:00:00Z");
    }

    const mismatchPayload = {
      ...makePolicy({ workspace_id: "ws_alpha" }),
      org_id: "org_beta",
    };
    const srv = await startMockServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(mismatchPayload));
    });

    try {
      const res = await fetchPolicy({
        config: makeConfig(srv.url, "ar_live_key"),
        cachePath,
        cwd: tmpDir,
        now: () => t0,
        log: () => {},
      });
      expect(res.status).toBe("invalid_policy");
      if (res.status === "invalid_policy") {
        expect(res.error).toContain("org_beta");
        expect(res.error).toContain("ws_alpha");
      }

      const report = inspectDoctorState({
        cachePath,
        guardConfigPath,
        claudeSettingsPath: join(tmpDir, "missing-claude.json"),
        cursorHooksPath: join(tmpDir, "missing-cursor.json"),
        config: makeConfig(srv.url, "ar_live_key"),
        now: t0 + 1000,
      });
      const output = formatDoctorReport(report);
      expect(output).toContain("org_beta");
      expect(output).toContain("ws_alpha");
      expect(output).toContain("does not match");
    } finally {
      await srv.close();
    }
  });

  it("enforces expires_s integer bounds 10..3600 naming the rule, supports approval_defaults, and enforces severity rules", () => {
    // Boundary accepts: 10 and 3600 on approval_defaults, builtin, and custom
    const okBounds = validatePolicy({
      ...makePolicy(),
      approval_defaults: { expires_s: 120, offline_fallback: "deny" },
      builtin: {
        GIT001: {
          enabled: true,
          action: "require_approval",
          approval: { expires_s: 10 },
        },
        FS001: {
          enabled: true,
          action: "block",
          // severity omitted on builtin is valid
        },
      },
      custom: [
        {
          id: "cust_max_exp",
          name: "Max expiry",
          enabled: true,
          version: 1,
          message: "Max",
          when: [{ field: "command", op: "contains", value: "deploy" }],
          action: "require_approval",
          severity: "info",
          approval: { expires_s: 3600, offline_fallback: "allow" },
        },
      ],
    });
    expect(okBounds.ok).toBe(true);
    if (okBounds.ok) {
      expect(okBounds.value.approval_defaults).toEqual({
        expires_s: 120,
        offline_fallback: "deny",
      });
      expect(computeMaxPolicyApprovalExpiresS(okBounds.value)).toBe(3600);
      expect(computePreExecTimeoutS(okBounds.value)).toBe(3610);
    }

    // approval_defaults flows into computeMaxPolicyApprovalExpiresS / computePreExecTimeoutS
    const defaultsOnly = makePolicy({
      approval_defaults: { expires_s: 240, offline_fallback: "deny" },
      builtin: {
        GIT001: { enabled: true, action: "require_approval" },
      },
      custom: [],
    });
    expect(computeMaxPolicyApprovalExpiresS(defaultsOnly)).toBe(240);
    expect(computePreExecTimeoutS(defaultsOnly)).toBe(250);

    // Out-of-range and non-integer expires_s rejected, naming the rule
    for (const badExp of [9, 3601, 10.5, 0, -1]) {
      const badCustom = validatePolicy({
        ...makePolicy(),
        custom: [
          {
            id: "cust_bad_exp",
            name: "Bad expiry",
            enabled: true,
            version: 1,
            message: "Bad",
            when: [{ field: "command", op: "contains", value: "deploy" }],
            action: "require_approval",
            severity: "high",
            approval: { expires_s: badExp },
          },
        ],
      });
      expect(badCustom.ok, `expected reject custom expires_s=${badExp}`).toBe(false);
      if (!badCustom.ok) {
        expect(badCustom.error).toContain("cust_bad_exp");
      }

      const badBuiltin = validatePolicy({
        ...makePolicy(),
        builtin: {
          GIT001: {
            enabled: true,
            action: "require_approval",
            approval: { expires_s: badExp },
          },
        },
      });
      expect(badBuiltin.ok, `expected reject builtin expires_s=${badExp}`).toBe(false);
      if (!badBuiltin.ok) {
        expect(badBuiltin.error).toContain("GIT001");
      }

      const badDefaults = validatePolicy({
        ...makePolicy(),
        approval_defaults: { expires_s: badExp },
      });
      expect(badDefaults.ok, `expected reject approval_defaults expires_s=${badExp}`).toBe(
        false,
      );
      if (!badDefaults.ok) {
        expect(badDefaults.error).toContain("approval_defaults");
      }
    }

    // Severity stays info|warn|high|critical: required on custom, optional on builtin
    const missingCustomSeverity = validatePolicy({
      ...makePolicy(),
      custom: [
        {
          id: "cust_no_sev",
          name: "Missing severity",
          enabled: true,
          version: 1,
          message: "Missing",
          when: [{ field: "command", op: "contains", value: "foo" }],
          action: "flag",
        },
      ],
    });
    expect(missingCustomSeverity.ok).toBe(false);

    const invalidCustomSeverity = validatePolicy({
      ...makePolicy(),
      custom: [
        {
          id: "cust_bad_sev",
          name: "Bad severity",
          enabled: true,
          version: 1,
          message: "Bad",
          when: [{ field: "command", op: "contains", value: "foo" }],
          action: "flag",
          severity: "medium",
        },
      ],
    });
    expect(invalidCustomSeverity.ok).toBe(false);

    const invalidBuiltinSeverity = validatePolicy({
      ...makePolicy(),
      builtin: {
        FS001: { enabled: true, action: "flag", severity: "medium" },
      },
    });
    expect(invalidBuiltinSeverity.ok).toBe(false);
  });

  it("repro: personal repo cwd fetch returning no-org 200 does not overwrite cached org_acme policy and sudo stays blocked", async () => {
    const t0 = 1_764_530_000_000;
    const orgAcmePolicy: Policy = makePolicy({
      etag: "etag-org-acme-v1",
      org_id: "org_acme",
      workspace_id: "org_acme",
      mode: "enforce",
      custom: [
        {
          id: "cust_block_sudo",
          name: "Block sudo",
          enabled: true,
          version: 1,
          message: "sudo is blocked by org_acme",
          when: [{ field: "command", op: "contains", value: "sudo" }],
          action: "block",
          severity: "critical",
        },
      ],
    });
    writeCachedPolicyAtomic(
      { policy: orgAcmePolicy, etag: orgAcmePolicy.etag, fetched_at: t0 },
      cachePath,
    );

    const personalRepo = join(tmpDir, "hobby");
    mkdirSync(personalRepo, { recursive: true });
    execFileSync("git", ["init"], { cwd: personalRepo, stdio: "ignore" });
    execFileSync("git", ["remote", "add", "origin", "https://github.com/me/hobby.git"], {
      cwd: personalRepo,
      stdio: "ignore",
    });

    const seenUrls: string[] = [];
    const srv = await startMockServer((req, res) => {
      seenUrls.push(req.url ?? "");
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          version: 1,
          etag: "etag-no-org-hobby",
          org_id: null,
          workspace_id: null,
          updated_at: "2026-11-26T00:00:00Z",
          mode: "observe",
          offline: "last_known",
          builtin: {},
          custom: [],
          allow: { commands: [], paths: [], repos: [] },
        }),
      );
    });

    const logs: string[] = [];
    try {
      const res = await fetchPolicy({
        config: makeConfig(srv.url, "ar_live_key"),
        cachePath,
        cwd: personalRepo,
        now: () => t0 + 60_000,
        log: (m) => logs.push(m),
      });

      expect(seenUrls).toEqual(["/api/v1/policy"]);
      expect(res.status).toBe("kept_cache");
      if (res.status === "kept_cache") {
        expect(res.reason).toBe("no_org_ignored");
        expect(res.keptCache).toBe(true);
      }
      expect(logs).toContain(
        "no-org response ignored; keeping cached org policy org_acme",
      );

      const cached = readCachedPolicy(cachePath);
      expect(cached?.policy.org_id).toBe("org_acme");
      expect(cached?.etag).toBe("etag-org-acme-v1");

      const report = inspectDoctorState({
        cachePath,
        guardConfigPath,
        claudeSettingsPath: join(tmpDir, "missing-claude.json"),
        cursorHooksPath: join(tmpDir, "missing-cursor.json"),
        config: makeConfig(srv.url, "ar_live_key"),
        now: t0 + 61_000,
      });
      expect(report.enforcementActive).toBe(true);
      expect(report.noOrgPolicy).toBe(false);
      expect(formatDoctorReport(report)).toContain(
        "no-org response ignored; keeping cached org policy org_acme",
      );

      const outcome = await enforcePreExec(
        {
          sessionId: "sess-acme-backend",
          tool: "claude-code",
          toolName: "Bash",
          command: "sudo rm -rf /",
          repo: "acme/backend",
        },
        {
          cachePath,
          guardConfigPath,
          config: makeConfig(srv.url, "ar_live_key"),
          recordDecision: () => {},
        },
      );
      expect(outcome.permitted).toBe(false);
      expect(outcome.action).toBe("block");
      expect(outcome.enforced).toBe(true);
    } finally {
      await srv.close();
    }
  });

  it("adversarial: neither no-org 200 nor org-B 200 (with new or reused ETag) nor a 304 can replace cached org-A policy", async () => {
    const t0 = 1_764_540_000_000;
    const orgAPolicy: Policy = makePolicy({
      etag: "etag-org-a",
      org_id: "org_a",
      workspace_id: "org_a",
      mode: "enforce",
      custom: [
        {
          id: "cust_org_a_block_sudo",
          name: "Org A block sudo",
          enabled: true,
          version: 1,
          message: "Blocked by org_a",
          when: [{ field: "command", op: "contains", value: "sudo" }],
          action: "block",
          severity: "critical",
        },
      ],
    });
    writeCachedPolicyAtomic(
      { policy: orgAPolicy, etag: orgAPolicy.etag, fetched_at: t0 },
      cachePath,
    );

    const noOrgBase = {
      version: 1,
      org_id: null,
      workspace_id: null,
      updated_at: "2026-11-26T00:00:00Z",
      mode: "observe",
      offline: "last_known",
      builtin: {},
      custom: [],
      allow: { commands: [], paths: [], repos: [] },
    };
    const orgBBase = makePolicy({
      org_id: "org_b",
      workspace_id: "org_b",
      mode: "observe",
      builtin: {},
      custom: [],
      allow: { commands: [], paths: [], repos: [] },
    });

    let step = 0;
    const seenIfNoneMatch: Array<string | undefined> = [];
    const srv = await startMockServer((req, res) => {
      seenIfNoneMatch.push(req.headers["if-none-match"] as string | undefined);
      step++;
      if (step === 1) {
        // Attack 1: no-org 200 with fresh etag
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ...noOrgBase, etag: "etag-no-org" }));
        return;
      }
      if (step === 2) {
        // Attack 2: no-org 200 reusing org_a's exact etag
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ...noOrgBase, etag: "etag-org-a" }));
        return;
      }
      if (step === 3) {
        // Attack 3: org_b 200 with new etag
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ...orgBBase, etag: "etag-org-b" }));
        return;
      }
      if (step === 4) {
        // Attack 4: org_b 200 reusing org_a's exact etag
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ...orgBBase, etag: "etag-org-a" }));
        return;
      }
      // Attack 5: 304 response carrying an adversarial org_b ETag header
      res.writeHead(304, { etag: "etag-org-b" });
      res.end();
    });

    const logs: string[] = [];
    const assertOrgAEnforced = async () => {
      const cached = readCachedPolicy(cachePath);
      expect(cached?.policy.org_id).toBe("org_a");
      expect(cached?.etag).toBe("etag-org-a");

      const outcome = await enforcePreExec(
        {
          sessionId: "sess-adversarial",
          tool: "claude-code",
          toolName: "Bash",
          command: "sudo rm -rf /",
        },
        {
          cachePath,
          guardConfigPath,
          config: makeConfig(srv.url, "ar_live_key"),
          recordDecision: () => {},
        },
      );
      expect(outcome.permitted).toBe(false);
      expect(outcome.action).toBe("block");
      expect(outcome.decision?.rule_id).toBe("cust_org_a_block_sudo");
    };

    try {
      const r1 = await fetchPolicy({
        config: makeConfig(srv.url, "ar_live_key"),
        cachePath,
        now: () => t0 + 10_000,
        log: (m) => logs.push(m),
      });
      expect(r1.status).toBe("kept_cache");
      await assertOrgAEnforced();

      const r2 = await fetchPolicy({
        config: makeConfig(srv.url, "ar_live_key"),
        cachePath,
        now: () => t0 + 20_000,
        log: (m) => logs.push(m),
      });
      expect(r2.status).toBe("kept_cache");
      await assertOrgAEnforced();

      const r3 = await fetchPolicy({
        config: makeConfig(srv.url, "ar_live_key"),
        cachePath,
        now: () => t0 + 30_000,
        log: (m) => logs.push(m),
      });
      expect(r3.status).toBe("kept_cache");
      if (r3.status === "kept_cache") {
        expect(r3.reason).toBe("org_mismatch_ignored");
      }
      expect(logs).toContain(
        "policy for org org_b ignored; keeping cached org org_a",
      );

      const doctorAfterOrgB = inspectDoctorState({
        cachePath,
        guardConfigPath,
        claudeSettingsPath: join(tmpDir, "missing-claude.json"),
        cursorHooksPath: join(tmpDir, "missing-cursor.json"),
        config: makeConfig(srv.url, "ar_live_key"),
        now: t0 + 31_000,
      });
      const doctorOut = formatDoctorReport(doctorAfterOrgB);
      expect(doctorOut).toContain(
        "policy for org org_b ignored; keeping cached org org_a",
      );
      expect(doctorOut).toContain("run `npx @agentreel/agent auth` to switch orgs");
      await assertOrgAEnforced();

      const r4 = await fetchPolicy({
        config: makeConfig(srv.url, "ar_live_key"),
        cachePath,
        now: () => t0 + 40_000,
        log: (m) => logs.push(m),
      });
      expect(r4.status).toBe("kept_cache");
      await assertOrgAEnforced();

      const r5 = await fetchPolicy({
        config: makeConfig(srv.url, "ar_live_key"),
        cachePath,
        now: () => t0 + 50_000,
        log: (m) => logs.push(m),
      });
      expect(r5.status).toBe("not_modified");
      // Every single fetch must have sent org_a's etag, never org_b's
      expect(seenIfNoneMatch).toEqual([
        "etag-org-a",
        "etag-org-a",
        "etag-org-a",
        "etag-org-a",
        "etag-org-a",
      ]);
      expect(readPolicyRejection(cachePath)?.reason).toBe("org_mismatch_ignored");
      const doctorAfter304 = formatDoctorReport(
        inspectDoctorState({
          cachePath,
          guardConfigPath,
          claudeSettingsPath: join(tmpDir, "missing-claude.json"),
          cursorHooksPath: join(tmpDir, "missing-cursor.json"),
          config: makeConfig(srv.url, "ar_live_key"),
          now: t0 + 51_000,
        }),
      );
      expect(doctorAfter304).toContain(
        "policy for org org_b ignored; keeping cached org org_a",
      );
      expect(doctorAfter304).toContain("run `npx @agentreel/agent auth` to switch orgs");
      await assertOrgAEnforced();
    } finally {
      await srv.close();
    }
  });

  it("explicit auth (linkCommand) clears cached policy, etag, and sidecar when switching accounts, and logout clears cache", async () => {
    vi.resetModules();
    const prevHome = process.env.HOME;
    const authHome = mkdtempSync(join(tmpdir(), "agentreel-auth-switch-"));
    process.env.HOME = authHome;

    const orgAPolicy = makePolicy({
      etag: "etag-org-a",
      org_id: "org_a",
      workspace_id: "org_a",
      mode: "enforce",
    });
    const orgBPolicy = makePolicy({
      etag: "etag-org-b",
      org_id: "org_b",
      workspace_id: "org_b",
      mode: "enforce",
    });

    const seenPolicyIfNoneMatch: Array<string | undefined> = [];
    const srv = await startMockServer((req, res) => {
      const pathname = new URL(req.url ?? "/", "http://127.0.0.1").pathname;
      const authHeader = req.headers.authorization;
      if (pathname === "/api/v1/sessions/ingest") {
        if (authHeader === "Bearer ar_live_bad_key") {
          res.writeHead(401, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "unauthorized" }));
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      if (pathname === "/api/v1/policy") {
        seenPolicyIfNoneMatch.push(req.headers["if-none-match"] as string | undefined);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify(
            authHeader === "Bearer ar_live_org_b_key" ? orgBPolicy : orgAPolicy,
          ),
        );
        return;
      }
      res.writeHead(404);
      res.end();
    });

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const exitSpy = vi.spyOn(process, "exit").mockImplementation((() => {
      throw new Error("EXIT_CALLED");
    }) as never);

    try {
      const { linkCommand, logoutCommand } = await import("../src/commands/auth.js");
      const { policyPath } = await import("../src/paths.js");
      const {
        policyRejectionPath,
        readCachedPolicy: readCachedFresh,
        readPolicyRejection: readRejectionFresh,
        writePolicyRejectionAtomic: writeRejectionFresh,
      } = await import("../src/policy/cache.js");

      // 1. Initial link caches org_a
      await linkCommand("ar_live_org_a_key", { api: srv.url });
      expect(readCachedFresh(policyPath())?.policy.org_id).toBe("org_a");
      expect(readCachedFresh(policyPath())?.etag).toBe("etag-org-a");

      // Seed an org_mismatch_ignored sidecar as if a refresh saw org_b
      writeRejectionFresh(
        {
          ts: Date.now(),
          error: "policy for org org_b ignored; keeping cached org org_a",
          reason: "org_mismatch_ignored",
          cached_org_id: "org_a",
          incoming_org_id: "org_b",
        },
        policyPath(),
      );
      expect(readRejectionFresh(policyPath())?.reason).toBe("org_mismatch_ignored");

      // 2. Failed link (401) must NOT wipe org_a cache or sidecar
      await expect(
        linkCommand("ar_live_bad_key", { api: srv.url }),
      ).rejects.toThrow("EXIT_CALLED");
      expect(readCachedFresh(policyPath())?.policy.org_id).toBe("org_a");
      expect(readRejectionFresh(policyPath())?.reason).toBe("org_mismatch_ignored");

      // 3. Successful link to org_b clears org_a cache + etag + sidecar before fetching fresh
      await linkCommand("ar_live_org_b_key", { api: srv.url });
      expect(seenPolicyIfNoneMatch).toEqual([undefined, undefined]);
      expect(readCachedFresh(policyPath())?.policy.org_id).toBe("org_b");
      expect(readCachedFresh(policyPath())?.etag).toBe("etag-org-b");
      expect(readRejectionFresh(policyPath())).toBeNull();

      // 4. Logout clears cached policy and any sidecar
      writeRejectionFresh(
        {
          ts: Date.now(),
          error: "some notice",
          reason: "no_org_ignored",
        },
        policyPath(),
      );
      await logoutCommand();
      expect(existsSync(policyPath())).toBe(false);
      expect(existsSync(policyRejectionPath(policyPath()))).toBe(false);
    } finally {
      logSpy.mockRestore();
      errSpy.mockRestore();
      exitSpy.mockRestore();
      await srv.close();
      process.env.HOME = prevHome;
      rmSync(authHome, { recursive: true, force: true });
    }
  });

  it("explicit auth keeps the old org cache when the post-validation policy fetch fails (5xx, invalid policy, network error)", async () => {
    vi.resetModules();
    const prevHome = process.env.HOME;
    const authHome = mkdtempSync(join(tmpdir(), "agentreel-auth-fetchfail-"));
    process.env.HOME = authHome;

    const orgAPolicy = makePolicy({
      etag: "etag-org-a",
      org_id: "org_a",
      workspace_id: "org_a",
      mode: "enforce",
    });
    const orgBPolicy = makePolicy({
      etag: "etag-org-b",
      org_id: "org_b",
      workspace_id: "org_b",
      mode: "enforce",
    });

    let policyMode: "ok" | "500" | "invalid" | "drop" = "ok";
    const srv = await startMockServer((req, res) => {
      const pathname = new URL(req.url ?? "/", "http://127.0.0.1").pathname;
      const authHeader = req.headers.authorization;
      if (pathname === "/api/v1/sessions/ingest") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      if (pathname === "/api/v1/policy") {
        if (policyMode === "500") {
          res.writeHead(500);
          res.end();
          return;
        }
        if (policyMode === "invalid") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ version: 1, etag: "bad" }));
          return;
        }
        if (policyMode === "drop") {
          req.socket.destroy();
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify(
            authHeader === "Bearer ar_live_org_b_key" ? orgBPolicy : orgAPolicy,
          ),
        );
        return;
      }
      res.writeHead(404);
      res.end();
    });

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    try {
      const { linkCommand } = await import("../src/commands/auth.js");
      const { policyPath } = await import("../src/paths.js");
      const { readCachedPolicy: readCachedFresh } = await import("../src/policy/cache.js");

      await linkCommand("ar_live_org_a_key", { api: srv.url });
      expect(readCachedFresh(policyPath())?.policy.org_id).toBe("org_a");

      for (const mode of ["500", "invalid", "drop"] as const) {
        policyMode = mode;
        await linkCommand("ar_live_org_b_key", { api: srv.url });
        const cached = readCachedFresh(policyPath());
        expect(cached?.policy.org_id, `mode ${mode}`).toBe("org_a");
        expect(cached?.etag, `mode ${mode}`).toBe("etag-org-a");
      }

      // A later successful explicit auth still switches orgs.
      policyMode = "ok";
      await linkCommand("ar_live_org_b_key", { api: srv.url });
      expect(readCachedFresh(policyPath())?.policy.org_id).toBe("org_b");
      expect(readCachedFresh(policyPath())?.etag).toBe("etag-org-b");
    } finally {
      logSpy.mockRestore();
      errSpy.mockRestore();
      await srv.close();
      process.env.HOME = prevHome;
      rmSync(authHome, { recursive: true, force: true });
    }
  });

  it("keeps org_mismatch_ignored sidecar after a later 304 or same-org 200, and doctor still warns until explicit auth succeeds", async () => {
    const t0 = 1_764_550_000_000;
    const orgAPolicy = makePolicy({
      etag: "etag-org-a",
      org_id: "org_a",
      workspace_id: "org_a",
      mode: "enforce",
    });
    const orgAUpdated = makePolicy({
      etag: "etag-org-a-v2",
      org_id: "org_a",
      workspace_id: "org_a",
      mode: "enforce",
    });
    const orgBPolicy = makePolicy({
      etag: "etag-org-b",
      org_id: "org_b",
      workspace_id: "org_b",
      mode: "observe",
    });
    writeCachedPolicyAtomic(
      { policy: orgAPolicy, etag: orgAPolicy.etag, fetched_at: t0 },
      cachePath,
    );

    let step = 0;
    const srv = await startMockServer((_req, res) => {
      step++;
      if (step === 1) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(orgBPolicy));
        return;
      }
      if (step === 2) {
        res.writeHead(304);
        res.end();
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(orgAUpdated));
    });

    const doctorOpts = {
      cachePath,
      guardConfigPath,
      claudeSettingsPath: join(tmpDir, "missing-claude.json"),
      cursorHooksPath: join(tmpDir, "missing-cursor.json"),
      config: makeConfig(srv.url, "ar_live_key"),
    };

    try {
      const ignored = await fetchPolicy({
        config: makeConfig(srv.url, "ar_live_key"),
        cachePath,
        now: () => t0 + 10_000,
      });
      expect(ignored.status).toBe("kept_cache");
      if (ignored.status === "kept_cache") {
        expect(ignored.reason).toBe("org_mismatch_ignored");
      }
      expect(readPolicyRejection(cachePath)?.reason).toBe("org_mismatch_ignored");

      const notModified = await fetchPolicy({
        config: makeConfig(srv.url, "ar_live_key"),
        cachePath,
        now: () => t0 + 20_000,
      });
      expect(notModified.status).toBe("not_modified");
      expect(readCachedPolicy(cachePath)?.fetched_at).toBe(t0 + 20_000);
      expect(readCachedPolicy(cachePath)?.policy.org_id).toBe("org_a");
      expect(readCachedPolicy(cachePath)?.etag).toBe("etag-org-a");
      expect(readPolicyRejection(cachePath)?.reason).toBe("org_mismatch_ignored");
      const after304 = formatDoctorReport(
        inspectDoctorState({ ...doctorOpts, now: t0 + 21_000 }),
      );
      expect(after304).toContain(
        "policy for org org_b ignored; keeping cached org org_a",
      );
      expect(after304).toContain("run `npx @agentreel/agent auth` to switch orgs");

      const sameOrg = await fetchPolicy({
        config: makeConfig(srv.url, "ar_live_key"),
        cachePath,
        now: () => t0 + 30_000,
      });
      expect(sameOrg.status).toBe("updated");
      expect(readCachedPolicy(cachePath)?.etag).toBe("etag-org-a-v2");
      expect(readCachedPolicy(cachePath)?.fetched_at).toBe(t0 + 30_000);
      expect(readPolicyRejection(cachePath)?.reason).toBe("org_mismatch_ignored");
      const afterSameOrg = formatDoctorReport(
        inspectDoctorState({ ...doctorOpts, now: t0 + 31_000 }),
      );
      expect(afterSameOrg).toContain("run `npx @agentreel/agent auth` to switch orgs");
    } finally {
      await srv.close();
    }

    vi.resetModules();
    const prevHome = process.env.HOME;
    const authHome = mkdtempSync(join(tmpdir(), "agentreel-sidecar-auth-"));
    process.env.HOME = authHome;

    const authOrgB = makePolicy({
      etag: "etag-org-b-auth",
      org_id: "org_b",
      workspace_id: "org_b",
      mode: "enforce",
    });
    const authSrv = await startMockServer((req, res) => {
      const pathname = new URL(req.url ?? "/", "http://127.0.0.1").pathname;
      if (pathname === "/api/v1/sessions/ingest") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      if (pathname === "/api/v1/policy") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(authOrgB));
        return;
      }
      res.writeHead(404);
      res.end();
    });
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const { linkCommand } = await import("../src/commands/auth.js");
      const { policyPath } = await import("../src/paths.js");
      const {
        readCachedPolicy: readCachedFresh,
        readPolicyRejection: readRejectionFresh,
        writeCachedPolicyAtomic: writeCachedFresh,
        writePolicyRejectionAtomic: writeRejectionFresh,
      } = await import("../src/policy/cache.js");
      const { formatDoctorReport: formatDoctorFresh, inspectDoctorState: inspectDoctorFresh } =
        await import("../src/commands/doctor.js");

      writeCachedFresh(
        { policy: orgAPolicy, etag: orgAPolicy.etag, fetched_at: t0 },
        policyPath(),
      );
      writeRejectionFresh(
        {
          ts: t0 + 10_000,
          error: "policy for org org_b ignored; keeping cached org org_a",
          reason: "org_mismatch_ignored",
          cached_org_id: "org_a",
          incoming_org_id: "org_b",
        },
        policyPath(),
      );

      await linkCommand("ar_live_org_b_key", { api: authSrv.url });
      expect(readCachedFresh(policyPath())?.policy.org_id).toBe("org_b");
      expect(readRejectionFresh(policyPath())).toBeNull();
      const afterAuth = formatDoctorFresh(
        inspectDoctorFresh({
          cachePath: policyPath(),
          guardConfigPath: join(authHome, "guard.json"),
          claudeSettingsPath: join(authHome, "missing-claude.json"),
          cursorHooksPath: join(authHome, "missing-cursor.json"),
          config: makeConfig(authSrv.url, "ar_live_org_b_key"),
          now: t0 + 40_000,
        }),
      );
      expect(afterAuth).not.toContain("run `npx @agentreel/agent auth` to switch orgs");
      expect(afterAuth).not.toContain("policy for org org_b ignored");
    } finally {
      logSpy.mockRestore();
      errSpy.mockRestore();
      await authSrv.close();
      process.env.HOME = prevHome;
      rmSync(authHome, { recursive: true, force: true });
    }
  });

  it("keeps no_org_ignored sidecar after a later 304 or same-org 200, and doctor still shows the notice", async () => {
    const t0 = 1_764_560_000_000;
    const orgAcmePolicy = makePolicy({
      etag: "etag-org-acme",
      org_id: "org_acme",
      workspace_id: "org_acme",
      mode: "enforce",
    });
    const orgAcmeUpdated = makePolicy({
      etag: "etag-org-acme-v2",
      org_id: "org_acme",
      workspace_id: "org_acme",
      mode: "enforce",
    });
    const noOrgPayload = {
      version: 1,
      etag: "etag-no-org",
      org_id: null,
      workspace_id: null,
      updated_at: "2026-11-26T00:00:00Z",
      mode: "observe",
      offline: "last_known",
      builtin: {},
      custom: [],
      allow: { commands: [], paths: [], repos: [] },
    };
    writeCachedPolicyAtomic(
      { policy: orgAcmePolicy, etag: orgAcmePolicy.etag, fetched_at: t0 },
      cachePath,
    );

    let step = 0;
    const srv = await startMockServer((_req, res) => {
      step++;
      if (step === 1) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(noOrgPayload));
        return;
      }
      if (step === 2) {
        res.writeHead(304);
        res.end();
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(orgAcmeUpdated));
    });

    const doctorOpts = {
      cachePath,
      guardConfigPath,
      claudeSettingsPath: join(tmpDir, "missing-claude.json"),
      cursorHooksPath: join(tmpDir, "missing-cursor.json"),
      config: makeConfig(srv.url, "ar_live_key"),
    };

    try {
      const ignored = await fetchPolicy({
        config: makeConfig(srv.url, "ar_live_key"),
        cachePath,
        now: () => t0 + 10_000,
      });
      expect(ignored.status).toBe("kept_cache");
      if (ignored.status === "kept_cache") {
        expect(ignored.reason).toBe("no_org_ignored");
      }
      expect(readPolicyRejection(cachePath)?.reason).toBe("no_org_ignored");

      const notModified = await fetchPolicy({
        config: makeConfig(srv.url, "ar_live_key"),
        cachePath,
        now: () => t0 + 20_000,
      });
      expect(notModified.status).toBe("not_modified");
      expect(readCachedPolicy(cachePath)?.fetched_at).toBe(t0 + 20_000);
      expect(readCachedPolicy(cachePath)?.policy.org_id).toBe("org_acme");
      expect(readPolicyRejection(cachePath)?.reason).toBe("no_org_ignored");
      const after304 = formatDoctorReport(
        inspectDoctorState({ ...doctorOpts, now: t0 + 21_000 }),
      );
      expect(after304).toContain(
        "no-org response ignored; keeping cached org policy org_acme",
      );

      const sameOrg = await fetchPolicy({
        config: makeConfig(srv.url, "ar_live_key"),
        cachePath,
        now: () => t0 + 30_000,
      });
      expect(sameOrg.status).toBe("updated");
      expect(readCachedPolicy(cachePath)?.etag).toBe("etag-org-acme-v2");
      expect(readPolicyRejection(cachePath)?.reason).toBe("no_org_ignored");
      const afterSameOrg = formatDoctorReport(
        inspectDoctorState({ ...doctorOpts, now: t0 + 31_000 }),
      );
      expect(afterSameOrg).toContain(
        "no-org response ignored; keeping cached org policy org_acme",
      );
    } finally {
      await srv.close();
    }
  });

});
