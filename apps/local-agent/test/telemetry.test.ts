import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type MockInstance,
} from "vitest";
import { execFileSync, execSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const home = mkdtempSync(join(tmpdir(), "agentreel-telemetry-"));
process.env.HOME = home;

let fetchMock: MockInstance<typeof fetch>;

beforeEach(() => {
  vi.resetModules();
  vi.unstubAllEnvs();
  process.env.HOME = home;
  delete process.env.AGENTREEL_TELEMETRY;
  delete process.env.DO_NOT_TRACK;
  delete process.env.CI;
  delete process.env.NODE_ENV;
  delete process.env.VITEST;
  delete process.env.VITEST_WORKER_ID;
  fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
    new Response("{}", { status: 200 }),
  );
  rmSync(join(home, ".agentreel"), { recursive: true, force: true });
});

afterEach(() => {
  fetchMock.mockRestore();
  vi.unstubAllEnvs();
});

function enabledEnv(): NodeJS.ProcessEnv {
  return {
    AGENTREEL_TELEMETRY: undefined,
    DO_NOT_TRACK: undefined,
    CI: undefined,
    NODE_ENV: "production",
    VITEST: undefined,
    VITEST_WORKER_ID: undefined,
  };
}

async function loadTelemetry() {
  return import("../src/telemetry.js");
}

describe("telemetry opt-out matrix", () => {
  it("default (non-test env) enables telemetry", async () => {
    const { isTelemetryEnabled } = await loadTelemetry();
    expect(isTelemetryEnabled(enabledEnv())).toBe(true);
  });

  it.each([
    ["0"],
    ["false"],
    ["FALSE"],
    ["  Off  "],
    ["NO"],
  ])("AGENTREEL_TELEMETRY=%s opts out", async (value) => {
    const { isTelemetryEnabled } = await loadTelemetry();
    expect(isTelemetryEnabled({ ...enabledEnv(), AGENTREEL_TELEMETRY: value })).toBe(false);
  });

  it.each([["1"], ["true"], ["yes"], ["enabled"], ["  on  "]])(
    "AGENTREEL_TELEMETRY=%s does not opt out",
    async (value) => {
      const { isTelemetryEnabled } = await loadTelemetry();
      expect(isTelemetryEnabled({ ...enabledEnv(), AGENTREEL_TELEMETRY: value })).toBe(true);
    },
  );

  it("DO_NOT_TRACK disables", async () => {
    const { isTelemetryEnabled } = await loadTelemetry();
    expect(isTelemetryEnabled({ ...enabledEnv(), DO_NOT_TRACK: "1" })).toBe(false);
  });

  it("empty DO_NOT_TRACK does not disable", async () => {
    const { isTelemetryEnabled } = await loadTelemetry();
    expect(isTelemetryEnabled({ ...enabledEnv(), DO_NOT_TRACK: "" })).toBe(true);
  });

  it("CI disables", async () => {
    const { isTelemetryEnabled } = await loadTelemetry();
    expect(isTelemetryEnabled({ ...enabledEnv(), CI: "true" })).toBe(false);
  });

  it("NODE_ENV=test disables", async () => {
    const { isTelemetryEnabled } = await loadTelemetry();
    expect(isTelemetryEnabled({ ...enabledEnv(), NODE_ENV: "test" })).toBe(false);
  });

  it("VITEST disables", async () => {
    const { isTelemetryEnabled } = await loadTelemetry();
    expect(isTelemetryEnabled({ ...enabledEnv(), VITEST: "true" })).toBe(false);
  });

  it("when disabled, runCliTelemetry writes no file and does not fetch", async () => {
    vi.stubEnv("NODE_ENV", "test");
    const { runCliTelemetry } = await loadTelemetry();
    runCliTelemetry("1.0.0", ["node", "agentreel", "status"]);
    expect(existsSync(join(home, ".agentreel", "telemetry.json"))).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("telemetry payload schema", () => {
  it("payload has only allowlisted keys and no path-like values", async () => {
    const {
      buildTelemetryPayload,
      ALLOWED_TELEMETRY_PAYLOAD_KEYS,
    } = await loadTelemetry();

    const payload = buildTelemetryPayload(
      "cli_first_run",
      "550e8400-e29b-41d4-a716-446655440000",
      3,
      "0.2.3",
      "linux",
    );

    expect(Object.keys(payload).sort()).toEqual([...ALLOWED_TELEMETRY_PAYLOAD_KEYS].sort());
    const blob = JSON.stringify(payload);
    expect(blob).not.toMatch(/\/Users\//);
    expect(blob).not.toMatch(/\\\\/);
    expect(blob).not.toMatch(/home\//i);
    expect(payload).toEqual({
      event: "cli_first_run",
      anon_id: "550e8400-e29b-41d4-a716-446655440000",
      version: "0.2.3",
      os: "linux",
      session_count: 3,
    });
  });
});

describe("telemetry recorded session count", () => {
  beforeEach(() => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VITEST", "");
    vi.stubEnv("VITEST_WORKER_ID", "");
  });

  afterEach(async () => {
    const db = await import("../src/db.js");
    db.closeDb();
  });

  it("session_count is rows in sessions.db, not CLI invocations", async () => {
    const db = await import("../src/db.js");
    db.upsertSession({ id: "s1", tool: "claude-code", startedAt: 1 } as never);
    db.upsertSession({ id: "s2", tool: "cursor", startedAt: 2 } as never);

    const { runCliTelemetry, countLocalRecordedSessions } = await loadTelemetry();
    expect(countLocalRecordedSessions()).toBe(2);

    await runCliTelemetry("0.2.3", ["node", "agentreel", "status"]);
    const body = JSON.parse(String(fetchMock.mock.calls.at(-1)?.[1]?.body));
    expect(body.session_count).toBe(2);

    db.upsertSession({ id: "s3", tool: "cursor", startedAt: 3 } as never);
    expect(countLocalRecordedSessions()).toBe(3);
  });

  it("returns 0 when sessions.db is missing", async () => {
    const { countLocalRecordedSessions } = await loadTelemetry();
    expect(countLocalRecordedSessions()).toBe(0);
  });

  it("returns 0 quickly when sessions.db is exclusively locked", async () => {
    const Database = (await import("better-sqlite3")).default;
    const { mkdirSync } = await import("node:fs");
    const { join } = await import("node:path");
    const dir = join(home, ".agentreel");
    mkdirSync(dir, { recursive: true });
    const dbPath = join(dir, "sessions.db");
    const locker = new Database(dbPath);
    locker.exec(
      `CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        tool TEXT NOT NULL,
        started_at INTEGER NOT NULL
      )`,
    );
    locker.exec("BEGIN EXCLUSIVE");

    const { countLocalRecordedSessions } = await loadTelemetry();
    const t0 = performance.now();
    expect(countLocalRecordedSessions()).toBe(0);
    expect(performance.now() - t0).toBeLessThan(200);

    locker.exec("ROLLBACK");
    locker.close();
  });
});

describe("telemetry heartbeat cadence", () => {
  beforeEach(() => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VITEST", "");
    vi.stubEnv("VITEST_WORKER_ID", "");
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("sends first_run once, then heartbeat only after 24h", async () => {
    const { runCliTelemetry, pickTelemetryEvent } = await loadTelemetry();
    const day = 24 * 60 * 60 * 1000;
    const t0 = 1_700_000_000_000;

    vi.setSystemTime(t0);
    await runCliTelemetry("0.2.3", ["node", "agentreel", "status"]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const firstBody = JSON.parse(String(fetchMock.mock.calls[0]![1]?.body));
    expect(firstBody.event).toBe("cli_first_run");

    fetchMock.mockClear();
    vi.setSystemTime(t0 + 60_000);
    await runCliTelemetry("0.2.3", ["node", "agentreel", "status"]);
    expect(fetchMock).not.toHaveBeenCalled();

    const state = {
      anon_id: "a",
      first_run_sent: true,
      notice_shown: true,
      last_heartbeat_at: t0,
    };
    expect(pickTelemetryEvent(state, t0 + day - 1)).toBeNull();
    expect(pickTelemetryEvent(state, t0 + day)).toBe("cli_heartbeat");

    fetchMock.mockClear();
    vi.setSystemTime(t0 + day);
    await runCliTelemetry("0.2.3", ["node", "agentreel", "status"]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const hbBody = JSON.parse(String(fetchMock.mock.calls[0]![1]?.body));
    expect(hbBody.event).toBe("cli_heartbeat");
  });
});

describe("telemetry notice", () => {
  beforeEach(() => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VITEST", "");
    vi.stubEnv("VITEST_WORKER_ID", "");
  });

  it("prints the notice only once across runs", async () => {
    const { runCliTelemetry, TELEMETRY_NOTICE } = await loadTelemetry();
    const lines: string[] = [];

    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation((chunk) => {
      lines.push(String(chunk));
      return true;
    });

    await runCliTelemetry("0.2.3", ["node", "agentreel", "status"]);
    await runCliTelemetry("0.2.3", ["node", "agentreel", "status"]);

    stderrSpy.mockRestore();

    const joined = lines.join("");
    expect((joined.match(/Turn off with/g) ?? []).length).toBe(1);
    expect(joined).toContain(TELEMETRY_NOTICE.slice(0, 40));

    const raw = readFileSync(join(home, ".agentreel", "telemetry.json"), "utf8");
    expect(JSON.parse(raw).notice_shown).toBe(true);
  });
});

describe("telemetry network failures", () => {
  beforeEach(() => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VITEST", "");
    vi.stubEnv("VITEST_WORKER_ID", "");
  });

  it("runCliTelemetry never throws on fetch failure or timeout", async () => {
    const { runCliTelemetry, flushCliTelemetry } = await loadTelemetry();
    fetchMock.mockRejectedValueOnce(new Error("network down"));
    await expect(runCliTelemetry("0.2.3", ["node", "agentreel", "status"])).resolves.toBeUndefined();
    await flushCliTelemetry(800);

    fetchMock.mockImplementationOnce(() => new Promise(() => {}));
    void runCliTelemetry("0.2.3", ["node", "agentreel", "status"]);
    const t0 = performance.now();
    await flushCliTelemetry(800);
    expect(performance.now() - t0).toBeLessThan(1000);
  });
});

describe("telemetry first-run delivery", () => {
  beforeEach(() => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VITEST", "");
    vi.stubEnv("VITEST_WORKER_ID", "");
  });

  it("--version as the first command sends cli_first_run and writes marker after 2xx", async () => {
    const { runCliTelemetry, flushCliTelemetry } = await loadTelemetry();
    await runCliTelemetry("0.2.3", ["node", "agentreel", "--version"]);
    await flushCliTelemetry(800);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const body = JSON.parse(String(fetchMock.mock.calls[0]![1]?.body));
    expect(body.event).toBe("cli_first_run");

    const raw = readFileSync(join(home, ".agentreel", "telemetry.json"), "utf8");
    expect(JSON.parse(raw).first_run_sent).toBe(true);
  });

  it("failed POST (non-2xx) does not set first_run_sent; next run sends cli_first_run again", async () => {
    const { runCliTelemetry, flushCliTelemetry } = await loadTelemetry();
    fetchMock.mockResolvedValueOnce(new Response("{}", { status: 500 }));
    await runCliTelemetry("0.2.3", ["node", "agentreel", "status"]);
    await flushCliTelemetry(800);

    const path = join(home, ".agentreel", "telemetry.json");
    expect(existsSync(path)).toBe(true);
    const persisted = JSON.parse(readFileSync(path, "utf8")) as {
      anon_id?: string;
      notice_shown?: boolean;
      first_run_sent?: boolean;
    };
    expect(typeof persisted.anon_id).toBe("string");
    expect(persisted.notice_shown).toBe(true);
    expect(persisted.first_run_sent).not.toBe(true);

    fetchMock.mockClear();
    fetchMock.mockResolvedValueOnce(new Response("{}", { status: 200 }));
    await runCliTelemetry("0.2.3", ["node", "agentreel", "status"]);
    await flushCliTelemetry(800);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const body = JSON.parse(String(fetchMock.mock.calls[0]![1]?.body));
    expect(body.event).toBe("cli_first_run");
  });

  it("network error on POST does not set first_run_sent; next run retries cli_first_run", async () => {
    const { runCliTelemetry, flushCliTelemetry } = await loadTelemetry();
    fetchMock.mockRejectedValueOnce(new Error("network down"));
    await runCliTelemetry("0.2.3", ["node", "agentreel", "status"]);
    await flushCliTelemetry(800);

    const path = join(home, ".agentreel", "telemetry.json");
    expect(existsSync(path)).toBe(true);
    const persisted = JSON.parse(readFileSync(path, "utf8")) as {
      anon_id?: string;
      notice_shown?: boolean;
      first_run_sent?: boolean;
    };
    expect(typeof persisted.anon_id).toBe("string");
    expect(persisted.notice_shown).toBe(true);
    expect(persisted.first_run_sent).not.toBe(true);

    fetchMock.mockClear();
    await runCliTelemetry("0.2.3", ["node", "agentreel", "status"]);
    await flushCliTelemetry(800);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(JSON.parse(String(fetchMock.mock.calls[0]![1]?.body)).event).toBe("cli_first_run");
  });

  it("a hanging POST is capped within about 800ms via flushCliTelemetry", async () => {
    const { runCliTelemetry, flushCliTelemetry } = await loadTelemetry();
    fetchMock.mockImplementation(() => new Promise(() => {}));
    void runCliTelemetry("0.2.3", ["node", "agentreel", "status"]);
    const t0 = performance.now();
    await flushCliTelemetry(800);
    expect(performance.now() - t0).toBeLessThan(1000);
    const path = join(home, ".agentreel", "telemetry.json");
    expect(existsSync(path)).toBe(true);
    const persisted = JSON.parse(readFileSync(path, "utf8")) as {
      anon_id?: string;
      notice_shown?: boolean;
      first_run_sent?: boolean;
    };
    expect(typeof persisted.anon_id).toBe("string");
    expect(persisted.notice_shown).toBe(true);
    expect(persisted.first_run_sent).not.toBe(true);
  });
});

describe("telemetry opt-out never fetches", () => {
  const cliPath = join(dirname(fileURLToPath(import.meta.url)), "../dist/cli.js");
  const fetchSuccessPreload = join(
    dirname(fileURLToPath(import.meta.url)),
    "fixtures/telemetry-fetch-success.mjs",
  );

  function fetchLogPath(): string {
    return join(home, ".agentreel", "fetch-log.txt");
  }

  it("AGENTREEL_TELEMETRY=0 does not call fetch on --version", () => {
    if (!existsSync(cliPath)) {
      return;
    }
    const logPath = fetchLogPath();
    rmSync(join(home, ".agentreel"), { recursive: true, force: true });
    const env = {
      ...process.env,
      HOME: home,
      NODE_ENV: "production",
      VITEST: "",
      VITEST_WORKER_ID: "",
      AGENTREEL_TELEMETRY: "0",
      AGENTREEL_TELEMETRY_FETCH_LOG: logPath,
    };
    // Preload via argv --import. NODE_OPTIONS=--import is denied by the runtime self-check.
    delete env.NODE_OPTIONS;
    const out = execFileSync("node", ["--import", fetchSuccessPreload, cliPath, "--version"], {
      env,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    });
    expect(out.trim().length).toBeGreaterThan(0);
    expect(existsSync(logPath)).toBe(false);
    expect(existsSync(join(home, ".agentreel", "telemetry.json"))).toBe(false);
  });

  it("CI=1 does not call fetch on --version", () => {
    if (!existsSync(cliPath)) {
      return;
    }
    const logPath = fetchLogPath();
    rmSync(join(home, ".agentreel"), { recursive: true, force: true });
    const env = {
      ...process.env,
      HOME: home,
      NODE_ENV: "production",
      VITEST: "",
      VITEST_WORKER_ID: "",
      CI: "true",
      AGENTREEL_TELEMETRY_FETCH_LOG: logPath,
    };
    delete env.NODE_OPTIONS;
    execFileSync("node", ["--import", fetchSuccessPreload, cliPath, "--version"], {
      env,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    });
    expect(existsSync(logPath)).toBe(false);
    expect(existsSync(join(home, ".agentreel", "telemetry.json"))).toBe(false);
  });
});

type IntegrationRunResult = {
  requests: Array<Record<string, unknown>>;
  telemetry: Record<string, unknown> | null;
  exit: { code: number | null; signal: string | null };
};

function runTelemetryCliIntegration(
  fixtureDir: string,
  statusCode: number,
  integrationHome: string,
  keepState: boolean,
  options?: { args?: string[]; stubDelayMs?: number },
): IntegrationRunResult {
  const outPath = join(integrationHome, "integration-result.json");
  const integrationScript = join(fixtureDir, "telemetry-cli-integration.mjs");
  const keepArg = keepState ? "keep" : "reset";
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    NODE_ENV: "production",
    VITEST: "",
    VITEST_WORKER_ID: "",
  };
  if (options?.stubDelayMs != null) {
    env.AGENTREEL_TEST_STUB_DELAY_MS = String(options.stubDelayMs);
  }
  execFileSync(
    "node",
    [
      integrationScript,
      String(statusCode),
      integrationHome,
      outPath,
      keepArg,
      ...(options?.args ?? []),
    ],
    {
      env,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  return JSON.parse(readFileSync(outPath, "utf8")) as IntegrationRunResult;
}

describe("telemetry CLI integration", () => {
  const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
  const fixtureDir = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

  beforeAll(() => {
    execSync("pnpm build", { cwd: packageRoot, stdio: "pipe" });
  });

  it("built CLI --version persists markers via local HTTP stub; second run sends no cli_first_run", () => {
    const integrationHome = mkdtempSync(join(tmpdir(), "agentreel-telemetry-cli-int-"));
    const first = runTelemetryCliIntegration(fixtureDir, 200, integrationHome, false);
    expect(first.requests).toHaveLength(1);
    expect(first.requests[0]?.event).toBe("cli_first_run");
    expect(first.telemetry?.first_run_sent).toBe(true);
    expect(typeof first.telemetry?.anon_id).toBe("string");
    expect(first.telemetry?.notice_shown).toBe(true);

    const second = runTelemetryCliIntegration(fixtureDir, 200, integrationHome, true);
    expect(second.requests).toHaveLength(0);
  });

  it("built CLI keeps local markers when stub returns non-2xx", () => {
    const integrationHome = mkdtempSync(join(tmpdir(), "agentreel-telemetry-cli-int-"));
    const result = runTelemetryCliIntegration(fixtureDir, 503, integrationHome, false);
    expect(result.requests).toHaveLength(1);
    expect(result.requests[0]?.event).toBe("cli_first_run");
    expect(typeof result.telemetry?.anon_id).toBe("string");
    expect(result.telemetry?.notice_shown).toBe(true);
    expect(result.telemetry?.first_run_sent).not.toBe(true);
  });

  it("built CLI unknown command flushes telemetry before process.exit", () => {
    const integrationHome = mkdtempSync(join(tmpdir(), "agentreel-telemetry-cli-int-"));
    const result = runTelemetryCliIntegration(fixtureDir, 200, integrationHome, false, {
      args: ["not-a-command"],
      stubDelayMs: 100,
    });
    expect(result.exit.code).toBe(1);
    expect(result.requests).toHaveLength(1);
    expect(result.requests[0]?.event).toBe("cli_first_run");
    expect(result.telemetry?.first_run_sent).toBe(true);
    expect(typeof result.telemetry?.anon_id).toBe("string");
    expect(result.telemetry?.notice_shown).toBe(true);
  });
});

describe("telemetry CLI exit code", () => {
  const cliPath = join(dirname(fileURLToPath(import.meta.url)), "../dist/cli.js");
  const fetchMockPreload = join(
    dirname(fileURLToPath(import.meta.url)),
    "fixtures/telemetry-fetch-mock.mjs",
  );

  it("does not change exit code when fetch fails", () => {
    if (!existsSync(cliPath)) {
      return;
    }
    expect(() => {
      const env = {
        ...process.env,
        HOME: home,
        NODE_ENV: "production",
        VITEST: "",
        VITEST_WORKER_ID: "",
      };
      delete env.NODE_OPTIONS;
      execFileSync("node", ["--import", fetchMockPreload, cliPath, "--version"], {
        env,
        encoding: "utf8",
        stdio: ["pipe", "pipe", "pipe"],
      });
    }).not.toThrow();
  });
});

describe("telemetry hook commands", () => {
  beforeEach(() => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VITEST", "");
    vi.stubEnv("VITEST_WORKER_ID", "");
  });

  it("skips internal hook subcommands", async () => {
    const { runCliTelemetry } = await loadTelemetry();
    await runCliTelemetry("0.2.3", ["node", "agentreel", "hook", "SessionStart"]);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(existsSync(join(home, ".agentreel", "telemetry.json"))).toBe(false);
  });
});