import { randomUUID } from "node:crypto";
import Database from "better-sqlite3";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { platform } from "node:os";
import { join } from "node:path";
import { AGENTREEL_DIR, DB_PATH } from "./paths.js";

export const CLI_EVENTS_URL = "https://agentreel.dev/api/cli/events";

const TELEMETRY_PATH = join(AGENTREEL_DIR, "telemetry.json");
const HEARTBEAT_INTERVAL_MS = 24 * 60 * 60 * 1000;
const POST_TIMEOUT_MS = 1500;

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

/** Distinct replay sessions in the local SQLite buffer (read-only; never throws). */
export function countLocalRecordedSessions(): number {
  try {
    if (!existsSync(DB_PATH)) return 0;
    const db = new Database(DB_PATH, {
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
  return subcommand === "hook" || subcommand === "cursor-hook";
}

function readState(): TelemetryState | null {
  try {
    const raw = readFileSync(TELEMETRY_PATH, "utf8");
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
  mkdirSync(AGENTREEL_DIR, { recursive: true });
  writeFileSync(TELEMETRY_PATH, JSON.stringify(state, null, 2) + "\n", { mode: 0o600 });
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

function postTelemetryPayload(payload: CliTelemetryPayload): void {
  void fetch(CLI_EVENTS_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(POST_TIMEOUT_MS),
  }).catch(() => {});
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
 * Anonymous CLI telemetry. Fire-and-forget; never throws.
 */
export function runCliTelemetry(version: string, argv: string[] = process.argv): void {
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
    }

    state = maybePrintTelemetryNotice(state);

    const event = pickTelemetryEvent(state, now);
    if (event === "cli_first_run") {
      // Anchor heartbeat cadence to first run even though the event is not a heartbeat.
      state = { ...state, first_run_sent: true, last_heartbeat_at: now };
    } else if (event === "cli_heartbeat") {
      state = { ...state, last_heartbeat_at: now };
    }

    writeState(state);

    if (event) {
      const recordedSessionCount = countLocalRecordedSessions();
      postTelemetryPayload(
        buildTelemetryPayload(event, state.anon_id, recordedSessionCount, version),
      );
    }
  } catch {
    // telemetry must never affect the CLI
  }
}