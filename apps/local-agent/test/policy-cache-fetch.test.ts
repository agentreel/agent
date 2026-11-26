import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import {
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
} from "../src/policy/cache.js";
import { fetchPolicy } from "../src/policy/fetch.js";
import { validatePolicy, type Policy } from "../src/policy/types.js";
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
        policyMode: "block",
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
