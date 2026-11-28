import { randomUUID } from "node:crypto";
import Database from "better-sqlite3";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { platform } from "node:os";
import { join } from "node:path";
import { agentreelDir, dbPath } from "./paths.js";

export const CLI_EVENTS_URL = "https://agentreel.dev/api/cli/events";

const telemetryPath = (): string => join(agentreelDir(), "telemetry.json");
const HEARTBEAT_INTERVAL_MS = 24 * 60 * 60 * 1000;
const POST_TIMEOUT_MS = 800;

export const TELEMETRY_EXIT_AWAIT_MS = 800;

export const TELEMETRY_NOTICE =
  "agentreel sends anonymous usage stats (version, OS, session count, no content). " +
  "Turn off with AGENTREEL_TELEMETRY=0. Details: agentreel.dev/docs#telemetry";

export type CliTelemetryEvent = "cli_first_run" | "cli_heartbeat";

export const ALLOWED_TELEMETRY_PAYLOAD_KEYS = [
  "event",
  "anon_id",
  "version",
  "os",
  "session_count",
] as const;

export type CliTelemetryPayload = {
  event: CliTelemetryEvent;
  anon_id: string;
  version: string;
  os: string;
  session_count: number;
};

export interface TelemetryState {
  anon_id: string;
  first_run_sent: boolean;
  notice_shown: boolean;
  last_heartbeat_at?: number;
}

let inFlightTelemetry: Promise<void> | null = null;

/** Distinct replay sessions in the local SQLite buffer (read-only; never throws). */
export function countLocalRecordedSessions(): number {
  try {
    if (!existsSync(dbPath())) return 0;
    const db = new Database(dbPath(), {
      readonly: true,
      fileMustExist: true,
      timeout: 0,
    });
    try {
      const row = db.prepare(`SELECT COUNT(*) AS c FROM sessions`).get() as { c: number } | undefined;
      const n = row?.c;
      return typeof n === "number" && Number.isInteger(n) && n >= 0 ? n : 0;
    } finally {
      db.close();
    }
  } catch {
    return 0;
  }
}

export function isAgentreelTelemetryOptedOut(value: string | undefined): boolean {
  if (value == null) return false;
  const normalized = value.trim().toLowerCase();
  return (
    normalized === "0" ||
    normalized === "false" ||
    normalized === "off" ||
    normalized === "no"
  );
}

export function isTelemetryEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  if (isAgentreelTelemetryOptedOut(env.AGENTREEL_TELEMETRY)) return false;
  if (env.DO_NOT_TRACK != null && env.DO_NOT_TRACK !== "") return false;
  if (env.CI != null && env.CI !== "") return false;
  if (env.NODE_ENV === "test") return false;
  if (env.VITEST === "true") return false;
  const workerId = env.VITEST_WORKER_ID;
  if (workerId != null && String(workerId) !== "") return false;
  return true;
}

export function shouldSkipTelemetryForArgv(argv: string[]): boolean {
  const subcommand = argv[2];
  // `managed` writes system policy as root and must never phone home.
  return subcommand === "hook" || subcommand === "cursor-hook" || subcommand === "managed";
}

function readState(): TelemetryState | null {
  try {
    const raw = readFileSync(telemetryPath(), "utf8");
    const parsed = JSON.parse(raw) as Partial<TelemetryState>;
    if (typeof parsed.anon_id !== "string" || !parsed.anon_id) return null;
    return {
      anon_id: parsed.anon_id,
      first_run_sent: Boolean(parsed.first_run_sent),
      notice_shown: Boolean(parsed.notice_shown),
      last_heartbeat_at:
        typeof parsed.last_heartbeat_at === "number" ? parsed.last_heartbeat_at : undefined,
    };
  } catch {
    return null;
  }
}

function writeState(state: TelemetryState): void {
  mkdirSync(agentreelDir(), { recursive: true });
  writeFileSync(telemetryPath(), JSON.stringify(state, null, 2) + "\n", { mode: 0o600 });
}

/** Persist anon_id and notice_shown without clobbering delivery markers from disk. */
function persistLocalTelemetryMarkers(state: TelemetryState): void {
  const onDisk = readState();
  writeState({
    anon_id: state.anon_id,
    notice_shown: state.notice_shown,
    first_run_sent: onDisk?.first_run_sent ?? false,
    last_heartbeat_at: onDisk?.last_heartbeat_at,
  });
}

export function buildTelemetryPayload(
  event: CliTelemetryEvent,
  anonId: string,
  recordedSessionCount: number,
  version: string,
  osName: string = platform(),
): CliTelemetryPayload {
  return {
    event,
    anon_id: anonId,
    version,
    os: osName,
    session_count: recordedSessionCount,
  };
}

export function pickTelemetryEvent(
  state: TelemetryState,
  now: number,
): CliTelemetryEvent | null {
  if (!state.first_run_sent) return "cli_first_run";
  const last = state.last_heartbeat_at ?? 0;
  if (now - last >= HEARTBEAT_INTERVAL_MS) return "cli_heartbeat";
  return null;
}

async function postTelemetryPayload(payload: CliTelemetryPayload): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), POST_TIMEOUT_MS);
  try {
    const res = await globalThis.fetch(CLI_EVENTS_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    return res.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

export function maybePrintTelemetryNotice(
  state: TelemetryState,
  write: (line: string) => void = (line) => process.stderr.write(line + "\n"),
): TelemetryState {
  if (state.notice_shown) return state;
  write(TELEMETRY_NOTICE);
  return { ...state, notice_shown: true };
}

/**
 * Await any in-flight telemetry work, up to capMs. Never throws.
 */
export async function flushCliTelemetry(capMs: number = TELEMETRY_EXIT_AWAIT_MS): Promise<void> {
  const current = inFlightTelemetry;
  if (!current) return;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      current,
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, capMs);
      }),
    ]);
  } catch {
    // telemetry must never affect the CLI
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/**
 * Anonymous CLI telemetry. Never throws; delivery markers persist only after a 2xx POST.
 */
export function runCliTelemetry(version: string, argv: string[] = process.argv): Promise<void> {
  const run = runCliTelemetryInner(version, argv);
  inFlightTelemetry = run;
  void run.finally(() => {
    if (inFlightTelemetry === run) {
      inFlightTelemetry = null;
    }
  });
  return run;
}

async function runCliTelemetryInner(version: string, argv: string[]): Promise<void> {
  try {
    if (!isTelemetryEnabled()) return;
    if (shouldSkipTelemetryForArgv(argv)) return;

    const now = Date.now();
    let state = readState();
    if (!state) {
      state = {
        anon_id: randomUUID(),
        first_run_sent: false,
        notice_shown: false,
      };
      persistLocalTelemetryMarkers(state);
    }

    const noticeBefore = state.notice_shown;
    state = maybePrintTelemetryNotice(state);
    if (!noticeBefore && state.notice_shown) {
      persistLocalTelemetryMarkers(state);
    }

    const event = pickTelemetryEvent(state, now);
    if (!event) {
      writeState(state);
      return;
    }

    const recordedSessionCount = countLocalRecordedSessions();
    const payload = buildTelemetryPayload(
      event,
      state.anon_id,
      recordedSessionCount,
      version,
    );
    const sent = await postTelemetryPayload(payload);

    if (sent) {
      if (event === "cli_first_run") {
        state = { ...state, first_run_sent: true, last_heartbeat_at: now };
      } else if (event === "cli_heartbeat") {
        state = { ...state, last_heartbeat_at: now };
      }
      writeState(state);
    }
  } catch {
    // telemetry must never affect the CLI
  }
}