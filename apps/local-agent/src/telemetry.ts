import { randomUUID } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { platform } from "node:os";
import { join } from "node:path";
import { AGENTREEL_DIR } from "./paths.js";

export const CLI_EVENTS_URL = "https://agentreel.dev/api/cli/events";

const TELEMETRY_PATH = join(AGENTREEL_DIR, "telemetry.json");
const HEARTBEAT_INTERVAL_MS = 24 * 60 * 60 * 1000;
const POST_TIMEOUT_MS = 1500;

export const TELEMETRY_NOTICE =
  "AgentReel collects anonymous CLI usage metrics (version, OS, invocation count). " +
  "No session content, paths, or credentials are sent. " +
  "Opt out: set AGENTREEL_TELEMETRY=0 or DO_NOT_TRACK=1. " +
  "Details: https://agentreel.dev/docs/cli-telemetry (PLACEHOLDER)";

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
  session_count: number;
  first_run_sent: boolean;
  notice_shown: boolean;
  last_heartbeat_at?: number;
}

export function isTelemetryEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  if (env.AGENTREEL_TELEMETRY === "0") return false;
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
      session_count:
        typeof parsed.session_count === "number" && Number.isInteger(parsed.session_count)
          ? parsed.session_count
          : 0,
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
  state: Pick<TelemetryState, "anon_id" | "session_count">,
  version: string,
  osName: string = platform(),
): CliTelemetryPayload {
  return {
    event,
    anon_id: state.anon_id,
    version,
    os: osName,
    session_count: state.session_count,
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
        session_count: 0,
        first_run_sent: false,
        notice_shown: false,
      };
    }

    state = { ...state, session_count: state.session_count + 1 };
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
      postTelemetryPayload(buildTelemetryPayload(event, state, version));
    }
  } catch {
    // telemetry must never affect the CLI
  }
}